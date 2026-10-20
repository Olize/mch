// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{Cli, hashing::hash_file};
use anyhow::{Context, Result, anyhow, bail};
use rayon::prelude::*;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
enum Kind {
    Regular,
    #[cfg_attr(not(unix), allow(dead_code))]
    Symlink,
}

struct FileTask {
    source: PathBuf,
    destination: PathBuf,
    kind: Kind,
}

struct DirTask {
    source: PathBuf,
    destination: PathBuf,
    preexisting: bool,
}

pub(crate) struct Plan {
    files: Vec<FileTask>,
    directories: Vec<DirTask>,
    sources: Vec<PathBuf>,
}

fn absolute(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !result.pop() {
                    bail!("path escapes root: {}", path.display());
                }
            }
            Component::Normal(part) => result.push(part),
            Component::RootDir | Component::Prefix(_) => result.push(component.as_os_str()),
        }
    }
    Ok(result)
}

fn existing_metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("stat {}", path.display())),
    }
}

// Resolve existing ancestors (including symbolic links), while keeping future path components.
fn intended_path(path: &Path) -> Result<PathBuf> {
    let mut base = absolute(path)?;
    let mut suffix = Vec::<OsString>::new();
    while existing_metadata(&base)?.is_none() {
        let name = base
            .file_name()
            .ok_or_else(|| anyhow!("no existing ancestor: {}", path.display()))?;
        suffix.push(name.to_os_string());
        if !base.pop() {
            bail!("no existing ancestor: {}", path.display());
        }
    }
    let mut resolved =
        fs::canonicalize(&base).with_context(|| format!("resolve {}", base.display()))?;
    for item in suffix.into_iter().rev() {
        resolved.push(item);
    }
    Ok(resolved)
}

fn no_symlink_parents(path: &Path) -> Result<()> {
    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        if let Some(meta) = existing_metadata(ancestor)? {
            if meta.file_type().is_symlink() {
                bail!(
                    "destination parent is a symlink (unsafe): {}",
                    ancestor.display()
                );
            }
            if !meta.is_dir() {
                bail!(
                    "destination parent is not a directory: {}",
                    ancestor.display()
                );
            }
        }
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<()> {
    // Do not follow destination symlinks, including those inserted after preflight.
    let mut missing = Vec::new();
    let mut cursor = path;
    loop {
        if let Some(meta) = existing_metadata(cursor)? {
            if !meta.is_dir() {
                bail!(
                    "destination directory is not a real directory: {}",
                    cursor.display()
                );
            }
            break;
        }
        missing.push(cursor.to_path_buf());
        cursor = cursor
            .parent()
            .ok_or_else(|| anyhow!("no directory ancestor: {}", path.display()))?;
    }
    for directory in missing.iter().rev() {
        match fs::create_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| format!("mkdir {}", directory.display()));
            }
        }
        let meta = fs::symlink_metadata(directory)?;
        if !meta.is_dir() {
            bail!(
                "destination directory changed unexpectedly: {}",
                directory.display()
            );
        }
    }
    Ok(())
}

fn check_destination_file(source: &Path, destination: &Path, overwrite: bool) -> Result<()> {
    no_symlink_parents(destination)?;
    match existing_metadata(destination)? {
        Some(meta) if meta.is_dir() => {
            bail!(
                "cannot replace a directory with a file: {}",
                destination.display()
            )
        }
        Some(_) if !overwrite => {
            bail!(
                "destination already exists (use --overwrite): {}",
                destination.display()
            )
        }
        Some(_)
            if fs::canonicalize(source)
                .is_ok_and(|src| fs::canonicalize(destination).is_ok_and(|dst| src == dst)) =>
        {
            bail!(
                "source and destination resolve to the same file: {}",
                source.display()
            );
        }
        Some(_) =>
        {
            #[cfg(unix)]
            if let (Ok(a), Ok(b)) = (fs::metadata(source), fs::metadata(destination)) {
                use std::os::unix::fs::MetadataExt;
                if a.ino() == b.ino() && a.dev() == b.dev() {
                    bail!("source and destination are hard links to the same file");
                }
            }
        }
        None => {}
    }
    Ok(())
}

fn register_file(plan: &mut Plan, source: &Path, target: &Path, kind: Kind) {
    plan.files.push(FileTask {
        source: source.to_path_buf(),
        destination: target.to_path_buf(),
        kind,
    });
}

fn collect_directory(plan: &mut Plan, source: &Path, destination: &Path) -> Result<()> {
    no_symlink_parents(destination)?;
    let preexisting = match existing_metadata(destination)? {
        Some(meta) if meta.is_dir() => true,
        Some(_) => bail!("destination is not a directory: {}", destination.display()),
        None => false,
    };
    plan.directories.push(DirTask {
        source: source.to_path_buf(),
        destination: destination.to_path_buf(),
        preexisting,
    });

    let mut entries = fs::read_dir(source)
        .with_context(|| format!("read directory {}", source.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let source_path = entry.path();
        let target_path = destination.join(entry.file_name());
        let ty = fs::symlink_metadata(&source_path)
            .with_context(|| format!("stat {}", source_path.display()))?
            .file_type();
        if ty.is_dir() {
            collect_directory(plan, &source_path, &target_path)?;
        } else if ty.is_file() {
            register_file(plan, &source_path, &target_path, Kind::Regular);
        } else if ty.is_symlink() {
            #[cfg(unix)]
            register_file(plan, &source_path, &target_path, Kind::Symlink);
            #[cfg(not(unix))]
            bail!(
                "symlinks are unsupported on this platform: {}",
                source_path.display()
            );
        } else {
            bail!("unsupported special file: {}", source_path.display());
        }
    }
    Ok(())
}

pub(crate) fn build_plan(cli: &Cli, destination: &Path) -> Result<Plan> {
    let dest = absolute(destination)?;
    let explicit_directory = destination
        .as_os_str()
        .to_string_lossy()
        .ends_with(std::path::MAIN_SEPARATOR);
    let destination_is_directory = existing_metadata(&dest)?.is_some_and(|meta| meta.is_dir());

    if cli.sources.len() > 1 && existing_metadata(&dest)?.is_some_and(|meta| !meta.is_dir()) {
        bail!("multiple sources require a destination directory");
    }

    let sources = cli
        .sources
        .iter()
        .map(|p| absolute(p))
        .collect::<Result<Vec<_>>>()?;
    let mut source_paths = HashSet::new();
    for source in &sources {
        if !source_paths.insert(source.clone()) {
            bail!("duplicate source: {}", source.display());
        }
    }
    // Moving a parent and its child in one invocation would delete an already-moved input.
    if cli.move_mode {
        for (i, source) in sources.iter().enumerate() {
            for other in sources.iter().skip(i + 1) {
                if source.starts_with(other) || other.starts_with(source) {
                    bail!("overlapping move sources are not supported");
                }
            }
        }
    }

    let mut plan = Plan {
        files: Vec::new(),
        directories: Vec::new(),
        sources,
    };
    for source in plan.sources.clone() {
        let kind = fs::symlink_metadata(&source)
            .with_context(|| format!("source not accessible: {}", source.display()))?
            .file_type();
        let name = source
            .file_name()
            .ok_or_else(|| anyhow!("source has no basename: {}", source.display()))?;
        if cli.only_src_content && !kind.is_dir() {
            bail!("-O requires a directory source");
        }
        let target = if cli.only_src_content {
            dest.clone()
        } else if kind.is_dir()
            || plan.sources.len() > 1
            || destination_is_directory
            || explicit_directory
        {
            if kind.is_dir()
                && (plan.sources.len() == 1 || destination_is_directory || explicit_directory)
            {
                // Existing CLI semantics: directory always lands inside destination/basename.
                dest.join(name)
            } else {
                dest.join(name)
            }
        } else {
            dest.clone()
        };

        if kind.is_dir() {
            let source_real = fs::canonicalize(&source)?;
            let target_real = intended_path(&target)?;
            if target_real.starts_with(&source_real) {
                bail!(
                    "refusing to copy a directory into itself: {} -> {}",
                    source.display(),
                    target.display()
                );
            }
            collect_directory(&mut plan, &source, &target)?;
        } else if kind.is_file() {
            register_file(&mut plan, &source, &target, Kind::Regular);
        } else if kind.is_symlink() {
            #[cfg(unix)]
            register_file(&mut plan, &source, &target, Kind::Symlink);
            #[cfg(not(unix))]
            bail!(
                "symlinks are unsupported on this platform: {}",
                source.display()
            );
        } else {
            bail!("unsupported source type: {}", source.display());
        }
    }

    let mut targets = HashSet::new();
    let mut directory_targets = HashSet::new();
    for dir in &plan.directories {
        if !directory_targets.insert(dir.destination.clone()) {
            bail!(
                "multiple sources target the same directory: {}",
                dir.destination.display()
            );
        }
    }
    for task in &plan.files {
        if !targets.insert(task.destination.clone()) {
            bail!(
                "multiple sources target the same file: {}",
                task.destination.display()
            );
        }
        if directory_targets.contains(&task.destination) {
            bail!(
                "file/directory destination conflict: {}",
                task.destination.display()
            );
        }
        check_destination_file(&task.source, &task.destination, cli.overwrite)?;
    }
    // Detect file paths that would become parents of any planned target.
    for dir in &plan.directories {
        if targets.contains(&dir.destination) {
            bail!("directory/file conflict: {}", dir.destination.display());
        }
    }
    Ok(plan)
}

struct TempPath(PathBuf);
impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn new_temp_path(destination: &Path) -> Result<TempPath> {
    let parent = destination.parent().context("destination has no parent")?;
    let index = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(TempPath(
        parent.join(format!(".mch-tmp-{}-{index}", std::process::id())),
    ))
}

fn atomic_replace(stage: &Path, destination: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        if fs::symlink_metadata(destination).is_ok() {
            let backup = new_temp_path(destination)?;
            fs::rename(destination, &backup.0)?;
            if let Err(publish_error) = fs::rename(stage, destination) {
                if let Err(restore_error) = fs::rename(&backup.0, destination) {
                    // Never delete the only surviving copy of the old destination.
                    // Leave the backup on disk for manual recovery and report its location.
                    let recovery_path = backup.0.clone();
                    std::mem::forget(backup);
                    bail!(
                        "failed to publish {}: {}; could not restore previous destination: {};                          ORIGINAL DATA RETAINED AT {} (manual recovery required)",
                        destination.display(),
                        publish_error,
                        restore_error,
                        recovery_path.display()
                    );
                }
                return Err(publish_error.into());
            }
            return Ok(());
        }
    }
    fs::rename(stage, destination)
        .with_context(|| format!("publish {} -> {}", stage.display(), destination.display()))
}

fn process_file(cli: &Cli, task: &FileTask) -> Result<()> {
    let parent = task
        .destination
        .parent()
        .context("destination has no parent")?;
    ensure_directory(parent)?;
    check_destination_file(&task.source, &task.destination, cli.overwrite)?;

    let temporary = new_temp_path(&task.destination)?;
    match task.kind {
        Kind::Regular => {
            // Reserving exclusively makes stale temporary files non-destructive.
            let reserved = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary.0)
                .with_context(|| format!("reserve temporary file {}", temporary.0.display()))?;
            drop(reserved); // Release the handle before copying/renaming, especially on Windows.
            fs::copy(&task.source, &temporary.0).with_context(|| {
                format!(
                    "copy {} -> {}",
                    task.source.display(),
                    temporary.0.display()
                )
            })?;

            if !cli.no_hash {
                let original_hash = hash_file(&task.source, cli.hash)?;
                let staged_hash = hash_file(&temporary.0, cli.hash)?;
                if original_hash != staged_hash {
                    bail!(
                        "{} verification FAILED for {} -> {}",
                        cli.hash.label(),
                        task.source.display(),
                        task.destination.display()
                    );
                }
            }
        }
        Kind::Symlink => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                let link = fs::read_link(&task.source)?;
                symlink(&link, &temporary.0)?;
                if !cli.no_hash && fs::read_link(&temporary.0)? != link {
                    bail!("symlink verification FAILED: {}", task.source.display());
                }
            }
            #[cfg(not(unix))]
            bail!("symlink copies are unsupported on this platform");
        }
    }

    // Recheck before committing: the target might have changed during a long copy.
    check_destination_file(&task.source, &task.destination, cli.overwrite)?;
    atomic_replace(&temporary.0, &task.destination)?;

    let label = if matches!(task.kind, Kind::Symlink) {
        "SYMLINK"
    } else if cli.no_hash {
        "COPIED"
    } else {
        cli.hash.label()
    };
    cli.report(
        &format!(
            "{label} OK {} -> {}",
            task.source.display(),
            task.destination.display()
        ),
        true,
    );
    Ok(())
}

pub(crate) fn execute(cli: &Cli, plan: &Plan) -> Result<()> {
    if cli.dry_run {
        for dir in &plan.directories {
            cli.report(&format!("MKDIR {}", dir.destination.display()), true);
        }
        for file in &plan.files {
            cli.report(
                &format!(
                    "COPY {} -> {}",
                    file.source.display(),
                    file.destination.display()
                ),
                true,
            );
        }
        if cli.move_mode {
            for source in &plan.sources {
                cli.report(&format!("AFTER SUCCESS REMOVE {}", source.display()), true);
            }
        }
        if !cli.quiet {
            println!(
                "DRY RUN: {} files/links; {} directories; no changes made",
                plan.files.len(),
                plan.directories.len()
            );
        }
        return Ok(());
    }

    for dir in &plan.directories {
        ensure_directory(&dir.destination)?;
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cli.count)
        .build()
        .context("create worker pool")?;
    pool.install(|| {
        plan.files
            .par_iter()
            .try_for_each(|task| process_file(cli, task))
    })?;

    // Preserve source directory permissions where we actually created a directory.
    // Do it after writing children: source directories can be read-only.
    for directory in plan.directories.iter().rev() {
        if !directory.preexisting {
            fs::set_permissions(
                &directory.destination,
                fs::metadata(&directory.source)?.permissions(),
            )
            .with_context(|| {
                format!(
                    "copy directory permissions {}",
                    directory.destination.display()
                )
            })?;
        }
    }

    if cli.move_mode {
        // IMPORTANT: none of the originals are removed until every planned copy has verified.
        for source in &plan.sources {
            let ty = fs::symlink_metadata(source)?.file_type();
            if ty.is_dir() {
                fs::remove_dir_all(source)?;
            } else {
                fs::remove_file(source)?;
            }
            cli.report(&format!("MOVED {}", source.display()), true);
        }
    }
    if !cli.quiet {
        println!(
            "DONE: {} files/links, {} directories{}",
            plan.files.len(),
            plan.directories.len(),
            if cli.move_mode {
                " (sources removed after verification)"
            } else {
                ""
            }
        );
    }
    Ok(())
}
