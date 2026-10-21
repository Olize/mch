// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{Cli, hashing::hash_file, progress::Progress};
use anyhow::{Context, Result, anyhow, bail};
use filetime::FileTime;
use rayon::prelude::*;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read, Write};
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
    source_times: Option<(FileTime, FileTime)>,
    move_identity: Option<fs::Metadata>,
}

struct DirTask {
    source: PathBuf,
    destination: PathBuf,
    preexisting: bool,
    source_atime: FileTime,
    source_mtime: FileTime,
    move_identity: Option<fs::Metadata>,
}

pub(crate) struct Plan {
    files: Vec<FileTask>,
    directories: Vec<DirTask>,
    sources: Vec<PathBuf>,
    total_bytes: u64,
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
    // macOS exposes /var, /tmp and /etc as system-managed symlinks into /private.
    // Normalize ONLY these verified system roots; other symlink parents stay forbidden.
    #[cfg(target_os = "macos")]
    for (alias, physical) in [
        ("/var", "/private/var"),
        ("/tmp", "/private/tmp"),
        ("/etc", "/private/etc"),
    ] {
        let alias = Path::new(alias);
        let physical = Path::new(physical);
        if result.starts_with(alias)
            && fs::symlink_metadata(alias).is_ok_and(|meta| meta.file_type().is_symlink())
            && fs::canonicalize(alias).ok().as_deref() == Some(physical)
        {
            return Ok(physical.join(result.strip_prefix(alias)?));
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

pub(crate) fn ensure_directory(path: &Path) -> Result<()> {
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

pub(crate) fn check_destination_file(
    source: &Path,
    destination: &Path,
    overwrite: bool,
) -> Result<()> {
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
        source_times: None,
        move_identity: None,
    });
}

fn collect_directory(plan: &mut Plan, source: &Path, destination: &Path) -> Result<()> {
    no_symlink_parents(destination)?;
    let preexisting = match existing_metadata(destination)? {
        Some(meta) if meta.is_dir() => true,
        Some(_) => bail!("destination is not a directory: {}", destination.display()),
        None => false,
    };
    // Snapshot directory times BEFORE read_dir mutates its access time.
    let source_meta = fs::metadata(source)
        .with_context(|| format!("stat source directory {}", source.display()))?;
    plan.directories.push(DirTask {
        source: source.to_path_buf(),
        destination: destination.to_path_buf(),
        preexisting,
        source_atime: FileTime::from_last_access_time(&source_meta),
        source_mtime: FileTime::from_last_modification_time(&source_meta),
        move_identity: None,
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
        total_bytes: 0,
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
        if matches!(task.kind, Kind::Regular) {
            let size = fs::metadata(&task.source)
                .with_context(|| format!("read file size: {}", task.source.display()))?
                .len();
            plan.total_bytes = plan
                .total_bytes
                .checked_add(size)
                .context("total source size exceeds u64 range")?;
        }
    }
    // Detect file paths that would become parents of any planned target.
    for dir in &plan.directories {
        if targets.contains(&dir.destination) {
            bail!("directory/file conflict: {}", dir.destination.display());
        }
    }
    if cli.move_mode {
        // Save source identities before any copying. Files are never deleted
        // merely because the same name happens to exist later.
        for task in &mut plan.files {
            task.move_identity = Some(
                fs::symlink_metadata(&task.source)
                    .with_context(|| format!("snapshot move source {}", task.source.display()))?,
            );
        }
        for directory in &mut plan.directories {
            directory.move_identity =
                Some(fs::symlink_metadata(&directory.source).with_context(|| {
                    format!("snapshot move directory {}", directory.source.display())
                })?);
        }
    }
    if cli.preserve_times {
        // Snapshot EVERY source inode before the first copy/verification read.
        // Hard-linked source names share an atime; a per-worker snapshot would
        // give later workers a newer value after the first source was read.
        for task in &mut plan.files {
            let meta = fs::symlink_metadata(&task.source)
                .with_context(|| format!("snapshot source times {}", task.source.display()))?;
            task.source_times = Some((
                FileTime::from_last_access_time(&meta),
                FileTime::from_last_modification_time(&meta),
            ));
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

fn reserve_private_stage(path: &Path) -> Result<fs::File> {
    // The temporary inode starts as 0600 even when the user's umask is 022.
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("reserve temporary file {}", path.display()))
}

fn new_temp_path(destination: &Path) -> Result<TempPath> {
    let parent = destination.parent().context("destination has no parent")?;
    let index = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(TempPath(
        parent.join(format!(".mch-tmp-{}-{index}", std::process::id())),
    ))
}

pub(crate) fn atomic_replace(stage: &Path, destination: &Path) -> Result<()> {
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

fn process_file(cli: &Cli, task: &FileTask, progress: Option<&Progress>) -> Result<()> {
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
            let mut staged = reserve_private_stage(&temporary.0)?;
            if let Some(progress) = progress {
                // Count bytes only when progress is visible. Streaming is needed
                // so one large file can report progress before completion.
                let mut source = fs::File::open(&task.source)
                    .with_context(|| format!("open source {}", task.source.display()))?;
                let source_permissions = source.metadata()?.permissions();
                let mut buffer = [0_u8; 1024 * 1024];
                loop {
                    let size = source
                        .read(&mut buffer)
                        .with_context(|| format!("read source {}", task.source.display()))?;
                    if size == 0 {
                        break;
                    }
                    staged
                        .write_all(&buffer[..size])
                        .with_context(|| format!("write staged file {}", temporary.0.display()))?;
                    progress.add_bytes(size as u64);
                }
                drop(staged);
                drop(source);
                fs::set_permissions(&temporary.0, source_permissions)
                    .with_context(|| format!("copy file permissions {}", temporary.0.display()))?;
            } else {
                // Keep platform-optimized filesystem copying (e.g. copy_file_range)
                // when progress is off; do not incur a streaming performance cost.
                drop(staged);
                fs::copy(&task.source, &temporary.0).with_context(|| {
                    format!(
                        "copy {} -> {}",
                        task.source.display(),
                        temporary.0.display()
                    )
                })?;
            }

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

    // Apply times to the temporary object before publishing it atomically.
    // Symlink times must never be applied through the link to its target.
    if let Some((atime, mtime)) = task.source_times {
        match task.kind {
            Kind::Regular => filetime::set_file_times(&temporary.0, atime, mtime)
                .with_context(|| format!("preserve file times {}", temporary.0.display()))?,
            Kind::Symlink => {
                #[cfg(unix)]
                filetime::set_symlink_file_times(&temporary.0, atime, mtime)
                    .with_context(|| format!("preserve symlink times {}", temporary.0.display()))?;
                #[cfg(not(unix))]
                bail!("symlink timestamps unsupported on this platform");
            }
        }
    }

    // For a move, flush the complete staged file AND its metadata before
    // publishing. Hashing may have read cached data, not durable storage.
    if cli.move_mode && matches!(task.kind, Kind::Regular) {
        #[cfg(not(windows))]
        fs::File::open(&temporary.0)
            .with_context(|| format!("open staged data for sync {}", temporary.0.display()))?
            .sync_all()
            .with_context(|| format!("sync staged data {}", temporary.0.display()))?;
        #[cfg(windows)]
        {
            // Windows FlushFileBuffers requires a GENERIC_WRITE file handle;
            // sync_all on File::open (read-only) returns AccessDenied.
            // fs::copy may also have marked the staged file read-only.
            let permissions = fs::metadata(&temporary.0)?.permissions();
            if permissions.readonly() {
                let mut writable = permissions.clone();
                // On Windows this toggles FILE_ATTRIBUTE_READONLY only;
                // Unix executable-bit concerns from this Clippy lint do not apply.
                #[allow(clippy::permissions_set_readonly_false)]
                writable.set_readonly(false);
                fs::set_permissions(&temporary.0, writable)?;
            }
            let sync_result = (|| -> Result<()> {
                let staged = fs::OpenOptions::new()
                    .write(true)
                    .open(&temporary.0)
                    .with_context(|| {
                        format!(
                            "open writable staged data for sync {}",
                            temporary.0.display()
                        )
                    })?;
                if permissions.readonly() {
                    // Restore the original source's readonly flag before sync.
                    fs::set_permissions(&temporary.0, permissions.clone())?;
                }
                staged
                    .sync_all()
                    .with_context(|| format!("sync staged data {}", temporary.0.display()))
            })();
            if sync_result.is_err() && permissions.readonly() {
                let _ = fs::set_permissions(&temporary.0, permissions);
            }
            sync_result?;
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
    if let Some(progress) = progress {
        progress.file_finished();
    }
    Ok(())
}

// A move is a two-phase operation: publish verified files, then remove ONLY
// the sources that were explicitly recorded in the plan. Never recursively
// delete the source tree: another application may have written new content.
fn check_move_source_snapshot(plan: &Plan) -> Result<()> {
    let mut planned = HashSet::new();
    for file in &plan.files {
        planned.insert(file.source.clone());
        let original = file
            .move_identity
            .as_ref()
            .context("missing pre-copy move source identity")?;
        let now = fs::symlink_metadata(&file.source)
            .with_context(|| format!("move source disappeared: {}", file.source.display()))?;
        if now.file_type() != original.file_type()
            || now.len() != original.len()
            || now.modified()? != original.modified()?
        {
            bail!(
                "move source was changed or replaced; refusing deletion: {}",
                file.source.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if now.dev() != original.dev() || now.ino() != original.ino() {
                bail!(
                    "move source inode changed; refusing deletion: {}",
                    file.source.display()
                );
            }
        }
    }
    for dir in &plan.directories {
        planned.insert(dir.source.clone());
    }
    for dir in &plan.directories {
        let original = dir
            .move_identity
            .as_ref()
            .context("missing pre-copy move directory identity")?;
        let current = fs::symlink_metadata(&dir.source)?;
        if !current.is_dir() || current.modified()? != original.modified()? {
            bail!("move source directory changed: {}", dir.source.display());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if current.dev() != original.dev() || current.ino() != original.ino() {
                bail!(
                    "move source directory inode changed: {}",
                    dir.source.display()
                );
            }
        }
        #[cfg(windows)]
        {
            // File-index / volume ID from std::MetadataExt are unstable on
            // stable Rust. Creation-time + modification-time are the strongest
            // portable standard-library check we can apply on Windows here.
            use std::os::windows::fs::MetadataExt;
            if current.creation_time() != original.creation_time() {
                bail!(
                    "move source directory was replaced: {}",
                    dir.source.display()
                );
            }
        }
        for entry in fs::read_dir(&dir.source)
            .with_context(|| format!("inspect move source {}", dir.source.display()))?
        {
            let path = entry?.path();
            if !planned.contains(&path) {
                bail!(
                    "move source contains a new/unplanned entry; nothing deleted: {}",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn move_directories_to_sync(plan: &Plan) -> Result<Vec<PathBuf>> {
    use std::collections::BTreeSet;
    // Snapshot which destination ancestors are MISSING *before* creating any.
    // fsync only affected directories and the parent of the highest new
    // directory. Unrelated ancestors (including / on Android) are not ours.
    let mut affected = BTreeSet::new();
    for file in &plan.files {
        let parent = file
            .destination
            .parent()
            .context("destination without parent")?;
        affected.insert(parent.to_path_buf());
        let mut current = parent;
        loop {
            if existing_metadata(current)?.is_some() {
                break;
            }
            let outer = current.parent().context("no existing directory ancestor")?;
            affected.insert(outer.to_path_buf());
            current = outer;
        }
    }
    for dir in &plan.directories {
        affected.insert(dir.destination.clone()); // empty or modified directory
        if !dir.preexisting {
            // An empty tree may contain no FileTask at all: ensure every
            // newly created ancestor and its first existing parent are synced.
            let mut current = dir.destination.as_path();
            loop {
                if existing_metadata(current)?.is_some() {
                    break;
                }
                let parent = current.parent().context("directory without parent")?;
                affected.insert(parent.to_path_buf());
                current = parent;
            }
        }
    }
    // Data and directory entries are synced from deepest to shallowest.
    let mut dirs: Vec<_> = affected.into_iter().collect();
    dirs.sort_by_key(|dir| std::cmp::Reverse(dir.components().count()));
    Ok(dirs)
}

#[cfg(unix)]
fn sync_move_destinations(dirs: &[PathBuf]) -> Result<()> {
    for directory in dirs {
        fs::File::open(directory)
            .with_context(|| {
                format!(
                    "open destination directory for sync {}",
                    directory.display()
                )
            })?
            .sync_all()
            .with_context(|| {
                format!(
                    "sync destination directory before source removal {}",
                    directory.display()
                )
            })?;
    }
    Ok(())
}

pub(crate) fn execute(cli: &Cli, plan: &Plan) -> Result<()> {
    if cli.resume {
        if plan.files.len() != 1
            || !plan.directories.is_empty()
            || !matches!(plan.files[0].kind, Kind::Regular)
        {
            bail!("--resume only supports one regular file, not directories or symlinks");
        }
        if cli.dry_run {
            cli.report(
                &format!(
                    "RESUME DRY RUN {} -> {}",
                    plan.files[0].source.display(),
                    plan.files[0].destination.display()
                ),
                true,
            );
            return Ok(());
        }
        return crate::resume::copy(
            cli,
            &plan.files[0].source,
            &plan.files[0].destination,
            plan.files[0].source_times,
        );
    }
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

    #[cfg(unix)]
    let move_sync_directories = if cli.move_mode {
        move_directories_to_sync(plan)?
    } else {
        Vec::new()
    };
    for dir in &plan.directories {
        ensure_directory(&dir.destination)?;
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cli.count)
        .build()
        .context("create worker pool")?;
    let tracker = Progress::new(plan.total_bytes, plan.files.len() as u64, !cli.no_hash);
    let show_progress = cli.show_progress();
    std::thread::scope(|scope| -> Result<()> {
        let (sender, receiver) = std::sync::mpsc::channel::<bool>();
        let reporter = if show_progress {
            let tracker_ref = &tracker;
            Some(scope.spawn(move || crate::progress::watch(tracker_ref, receiver)))
        } else {
            None
        };
        let progress = show_progress.then_some(&tracker);
        let result = pool.install(|| {
            plan.files
                .par_iter()
                .try_for_each(|task| process_file(cli, task, progress))
        });
        if let Some(reporter) = reporter {
            let _ = sender.send(result.is_ok());
            reporter
                .join()
                .map_err(|_| anyhow!("progress reporter thread panicked"))?;
        }
        result
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
            if cli.preserve_times {
                // Restoring after writing descendants prevents child creation
                // from invalidating the copied directory's modification time.
                filetime::set_file_times(
                    &directory.destination,
                    directory.source_atime,
                    directory.source_mtime,
                )
                .with_context(|| {
                    format!(
                        "preserve directory times {}",
                        directory.destination.display()
                    )
                })?;
            }
        }
    }

    if cli.move_mode {
        // Fail closed if the input tree gained ANY unplanned entry after
        // enumeration. Another process may be actively writing to it.
        check_move_source_snapshot(plan)?;
        #[cfg(unix)]
        sync_move_destinations(&move_sync_directories)?;
        // Remove only planned files and links. Never use remove_dir_all.
        for file in &plan.files {
            fs::remove_file(&file.source)
                .with_context(|| format!("remove planned move source {}", file.source.display()))?;
        }
        // Remove only empty, planned directories, deepest first. If new
        // entries appear during deletion, remove_dir fails and retains them.
        for directory in plan.directories.iter().rev() {
            fs::remove_dir(&directory.source).with_context(|| {
                format!(
                    "remove planned empty source directory {}",
                    directory.source.display()
                )
            })?;
        }
        for source in &plan.sources {
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

#[cfg(test)]
mod move_safety_tests {
    use super::*;
    use clap::Parser;

    #[cfg(unix)]
    #[test]
    fn staged_regular_file_is_private_from_creation() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let stage = t.path().join(".mch-tmp-test");
        let file = reserve_private_stage(&stage).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn move_refuses_new_entries_after_planning_without_deleting_any_sources() {
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("ongoing-download");
        let nested = src.join("nested");
        let dest = t.path().join("backup");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("original.txt"), b"first copied").unwrap();
        let cli = Cli::try_parse_from([
            std::ffi::OsString::from("mch"),
            std::ffi::OsString::from("--move"),
            src.as_os_str().to_os_string(),
            dest.as_os_str().to_os_string(),
        ])
        .unwrap();
        let plan = build_plan(&cli, &dest).unwrap();
        // A separate application adds a new file after the source scan.
        fs::write(
            nested.join("just-created.txt"),
            b"never part of the copy plan",
        )
        .unwrap();
        let error = execute(&cli, &plan).unwrap_err();
        assert!(
            error.to_string().contains("unplanned") || error.to_string().contains("changed"),
            "incorrect failure: {error:#}"
        );
        assert_eq!(
            fs::read(nested.join("original.txt")).unwrap(),
            b"first copied"
        );
        assert_eq!(
            fs::read(nested.join("just-created.txt")).unwrap(),
            b"never part of the copy plan"
        );
        assert_eq!(
            fs::read(dest.join("ongoing-download/nested/original.txt")).unwrap(),
            b"first copied"
        );
        assert!(
            !dest
                .join("ongoing-download/nested/just-created.txt")
                .exists()
        );
    }

    #[test]
    fn move_refuses_replaced_empty_source_directory_after_planning() {
        let t = tempfile::tempdir().unwrap();
        let source = t.path().join("original-dir");
        let backup = t.path().join("saved-original");
        let destination = t.path().join("target");
        fs::create_dir(&source).unwrap();
        let cli = Cli::try_parse_from([
            std::ffi::OsString::from("mch"),
            std::ffi::OsString::from("--move"),
            source.as_os_str().to_os_string(),
            destination.as_os_str().to_os_string(),
        ])
        .unwrap();
        let plan = build_plan(&cli, &destination).unwrap();
        // Another program replaced the empty directory with a different
        // empty directory of the SAME name. Never remove this new inode.
        fs::rename(&source, &backup).unwrap();
        fs::create_dir(&source).unwrap();
        // Make modification timestamps identical so the regression also
        // exercises inode/creation-time identity checks rather than mtime.
        let original_mtime = FileTime::from_last_modification_time(&fs::metadata(&backup).unwrap());
        let replacement_atime = FileTime::from_last_access_time(&fs::metadata(&source).unwrap());
        filetime::set_file_times(&source, replacement_atime, original_mtime).unwrap();
        let result = execute(&cli, &plan);
        assert!(result.is_err(), "must reject replaced source directory");
        assert!(source.is_dir(), "new source directory was destroyed");
        assert!(backup.is_dir(), "original directory was destroyed");
    }

    #[test]
    fn move_refuses_replaced_source_after_planning() {
        let t = tempfile::tempdir().unwrap();
        let source = t.path().join("source.bin");
        let dest = t.path().join("destination.bin");
        fs::write(&source, b"before").unwrap();
        let cli = Cli::try_parse_from([
            std::ffi::OsString::from("mch"),
            std::ffi::OsString::from("--move"),
            source.as_os_str().to_os_string(),
            dest.as_os_str().to_os_string(),
        ])
        .unwrap();
        let plan = build_plan(&cli, &dest).unwrap();
        fs::remove_file(&source).unwrap();
        fs::write(&source, b"replacement-longer").unwrap();
        let err = execute(&cli, &plan).unwrap_err();
        assert!(err.to_string().contains("changed"), "{err:#}");
        assert_eq!(fs::read(source).unwrap(), b"replacement-longer");
    }
}
