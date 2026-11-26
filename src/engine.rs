// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{Cli, hashing::hash_file, progress::Progress};
#[cfg(all(unix, any(target_os = "macos", test)))]
use anyhow::ensure;
use anyhow::{Context, Result, anyhow, bail};
use filetime::FileTime;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read, Write};
#[cfg(all(unix, any(target_os = "macos", test)))]
use std::io::{Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use unicode_normalization::UnicodeNormalization;

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum WindowsFileIdentity {
    Full(u64, [u8; 16]),
    Legacy(u32, u64),
    FatVolumeRoot(u32),
}

#[cfg(windows)]
fn windows_file_identity(path: &Path) -> Result<WindowsFileIdentity> {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, VOLUME_NAME_GUID,
    };

    let file = fs::OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("open Windows file identity {}", path.display()))?;
    let handle = file.as_raw_handle();
    let mut full = FILE_ID_INFO::default();
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut full).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if ok != 0 && full.FileId.Identifier != [0; 16] {
        return Ok(WindowsFileIdentity::Full(
            full.VolumeSerialNumber,
            full.FileId.Identifier,
        ));
    }

    // ReFS requires the full 128-bit identity. Permit legacy indices only on
    // known filesystems where the 64-bit interface applies.
    let mut name = [0u16; 32];
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            handle,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .context("query filesystem for legacy Windows identity");
    }
    let end = name.iter().position(|c| *c == 0).unwrap_or(name.len());
    let name = String::from_utf16_lossy(&name[..end]).to_ascii_uppercase();
    if !matches!(name.as_str(), "NTFS" | "FAT" | "FAT32" | "EXFAT") {
        bail!(
            "filesystem requires an available 128-bit Windows file identity: {}",
            path.display()
        );
    }
    let mut old = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut old) } == 0 {
        return Err(std::io::Error::last_os_error()).context("query legacy Windows file identity");
    }
    let index = (u64::from(old.nFileIndexHigh) << 32) | u64::from(old.nFileIndexLow);
    if index == 0 {
        // FAT roots have no parent directory entry. Only a handle that the
        // kernel resolves to the actual volume root may use this identity.
        if matches!(name.as_str(), "FAT" | "FAT32" | "EXFAT") {
            let mut final_path = [0u16; 64];
            let length = unsafe {
                GetFinalPathNameByHandleW(
                    handle,
                    final_path.as_mut_ptr(),
                    final_path.len() as u32,
                    VOLUME_NAME_GUID,
                )
            } as usize;
            if length > 0 && length < final_path.len() {
                let path = String::from_utf16_lossy(&final_path[..length]);
                if let Some(guid) = path
                    .strip_prefix(r"\\?\Volume{")
                    .and_then(|tail| tail.strip_suffix("}\\"))
                    && guid.len() == 36
                    && guid.bytes().enumerate().all(|(i, b)| match i {
                        8 | 13 | 18 | 23 => b == b'-',
                        _ => b.is_ascii_hexdigit(),
                    })
                {
                    return Ok(WindowsFileIdentity::FatVolumeRoot(old.dwVolumeSerialNumber));
                }
            }
        }
        bail!(
            "Windows filesystem returned an empty file identity: {}",
            path.display()
        );
    }
    Ok(WindowsFileIdentity::Legacy(old.dwVolumeSerialNumber, index))
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
enum Kind {
    Regular,
    #[cfg_attr(not(unix), allow(dead_code))]
    Symlink,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OverwriteTarget {
    len: u64,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    identity: WindowsFileIdentity,
}

impl OverwriteTarget {
    fn capture(_path: &Path, meta: &fs::Metadata) -> Result<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            len: meta.len(),
            modified: meta.modified()?,
            #[cfg(unix)]
            device: meta.dev(),
            #[cfg(unix)]
            inode: meta.ino(),
            #[cfg(windows)]
            identity: windows_file_identity(_path)?,
        })
    }
}

// An absent target always uses the OS no-replace operation. An existing
// target must still match the entry observed when the plan was built.
pub(crate) fn may_replace(planned: Option<&OverwriteTarget>, path: &Path) -> Result<bool> {
    let Some(planned) = planned else {
        return Ok(false);
    };
    let current = fs::symlink_metadata(path)
        .with_context(|| format!("planned overwrite target disappeared: {}", path.display()))?;
    if OverwriteTarget::capture(path, &current)? != *planned {
        bail!("planned overwrite target changed: {}", path.display());
    }
    Ok(true)
}

struct FileTask {
    source: PathBuf,
    destination: PathBuf,
    kind: Kind,
    overwrite_target: Option<OverwriteTarget>,
    source_times: Option<(FileTime, FileTime)>,
    move_identity: Option<fs::Metadata>,
    #[cfg(windows)]
    move_windows_identity: Option<WindowsFileIdentity>,
}

struct DirTask {
    source: PathBuf,
    destination: PathBuf,
    preexisting: bool,
    source_atime: FileTime,
    source_mtime: FileTime,
    move_identity: Option<fs::Metadata>,
    #[cfg(windows)]
    move_windows_identity: Option<WindowsFileIdentity>,
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
    let mut crossed_symlink = false;
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                // Lexical .. is NOT the kernel's .. after traversing a symlink.
                // Refuse ambiguity rather than moving a different source.
                if crossed_symlink {
                    bail!("unsafe .. after symbolic link: {}", path.display());
                }
                if !result.pop() {
                    bail!("path escapes root: {}", path.display());
                }
            }
            Component::Normal(part) => {
                result.push(part);
                if existing_metadata(&result)?.is_some_and(|meta| meta.file_type().is_symlink()) {
                    crossed_symlink = true;
                }
            }
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
pub(crate) fn intended_path(path: &Path) -> Result<PathBuf> {
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
        // Never expose a private 0700 source tree at 0755 during a
        // partially completed copy or after a crash.
        #[cfg(unix)]
        let created = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(directory)
        };
        #[cfg(not(unix))]
        let created = fs::create_dir(directory);
        match created {
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
) -> Result<Option<fs::Metadata>> {
    no_symlink_parents(destination)?;
    let existing = existing_metadata(destination)?;
    match &existing {
        Some(meta) if meta.is_dir() => {
            bail!(
                "cannot replace a directory with a file: {}",
                destination.display()
            )
        }
        Some(meta) if !meta.is_file() && !meta.file_type().is_symlink() => {
            bail!(
                "refusing to replace a special destination: {}",
                destination.display()
            );
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
    Ok(existing)
}

fn register_file(plan: &mut Plan, source: &Path, target: &Path, kind: Kind) {
    plan.files.push(FileTask {
        source: source.to_path_buf(),
        destination: target.to_path_buf(),
        kind,
        overwrite_target: None,
        source_times: None,
        move_identity: None,
        #[cfg(windows)]
        move_windows_identity: None,
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
        #[cfg(windows)]
        move_windows_identity: None,
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

// Preserve opaque OS filename bytes. Only valid Unicode spans participate
// in normalization, including when a different component is not UTF-8.
pub(crate) fn folded_destination_key(path: &Path) -> Vec<u8> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut key = Vec::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        let lowercase = chunk.valid().nfc().collect::<String>().to_lowercase();
        key.extend_from_slice(lowercase.nfc().collect::<String>().as_bytes());
        key.extend_from_slice(chunk.invalid());
    }
    key
}

#[cfg(unix)]
fn directory_identity(_path: &Path, meta: &fs::Metadata) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(windows)]
fn directory_identity(path: &Path, _meta: &fs::Metadata) -> Result<WindowsFileIdentity> {
    windows_file_identity(path)
}

#[cfg(any(unix, windows))]
fn reject_destinations_in_source_trees(plan: &Plan) -> Result<()> {
    if plan.directories.is_empty() {
        return Ok(());
    }
    let mut source_dirs = HashSet::new();
    for dir in &plan.directories {
        source_dirs.insert(directory_identity(
            &dir.source,
            &fs::symlink_metadata(&dir.source)?,
        )?);
    }
    // File targets can have an existing ancestor inside a different source,
    // even when the target itself does not exist yet. Inspect each parent once.
    let directories = plan.directories.iter().map(|d| d.destination.as_path());
    let parents = plan.files.iter().filter_map(|f| f.destination.parent());
    let mut inspected = HashSet::new();
    for dir in directories.chain(parents) {
        for path in dir.ancestors() {
            if !inspected.insert(path) {
                break;
            }
            if let Some(meta) = existing_metadata(path)?
                && meta.is_dir()
                && source_dirs.contains(&directory_identity(path, &meta)?)
            {
                bail!(
                    "a planned destination lies inside a source directory: {}",
                    path.display()
                );
            }
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
            dest.join(name)
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
    let mut folded_targets = HashMap::<Vec<u8>, PathBuf>::new();
    // NFC also catches canonically equivalent Unicode names (e.g. macOS
    // decomposed filenames). This remains conservative and is NOT a proof
    // of every filesystem's case-folding and normalization behavior.
    // Move targets are independently reverified before source deletion.
    let mut check_folded = |target: &Path| -> Result<()> {
        let folded = folded_destination_key(target);
        if let Some(other) = folded_targets.insert(folded, target.to_path_buf())
            && other != target
        {
            bail!(
                "ambiguous case-insensitive destination collision (including Unicode-normalized destination collision): {} and {}",
                other.display(),
                target.display()
            );
        }
        Ok(())
    };
    for dir in &plan.directories {
        check_folded(&dir.destination)?;
        if !directory_targets.insert(dir.destination.clone()) {
            bail!(
                "multiple sources target the same directory: {}",
                dir.destination.display()
            );
        }
    }
    for task in &mut plan.files {
        check_folded(&task.destination)?;
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
        if let Some(meta) = check_destination_file(&task.source, &task.destination, cli.overwrite)?
        {
            task.overwrite_target = Some(OverwriteTarget::capture(&task.destination, &meta)?);
        }
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
    #[cfg(any(unix, windows))]
    reject_destinations_in_source_trees(&plan)?;
    // A different worker can still need an existing destination as its input.
    // Check the whole plan before creating directories or publishing the first file.
    #[cfg(any(unix, windows))]
    if plan
        .files
        .iter()
        .any(|task| task.overwrite_target.is_some())
    {
        let mut inputs = HashSet::new();
        for task in &plan.files {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let meta = fs::symlink_metadata(&task.source)?;
                inputs.insert((meta.dev(), meta.ino()));
            }
            #[cfg(windows)]
            inputs.insert(windows_file_identity(&task.source)?);
        }
        for task in &plan.files {
            if let Some(target) = &task.overwrite_target {
                #[cfg(unix)]
                let id = (target.device, target.inode);
                #[cfg(windows)]
                let id = target.identity;
                if inputs.contains(&id) {
                    bail!(
                        "planned overwrite would replace a source in this transfer: {}",
                        task.destination.display()
                    );
                }
            }
        }
    }
    // Detect file paths that would become parents of any planned target.
    for dir in &plan.directories {
        if targets.contains(&dir.destination) {
            bail!("directory/file conflict: {}", dir.destination.display());
        }
    }
    // Keep the Windows multi-file move/overwrite restriction for this release.
    #[cfg(windows)]
    if cli.move_mode && cli.overwrite && plan.files.len() > 1 {
        bail!("multi-file --move --overwrite is temporarily disabled on Windows for data safety");
    }
    if cli.move_mode {
        // Save source identities before any copying. Files are never deleted
        // merely because the same name happens to exist later.
        for task in &mut plan.files {
            task.move_identity = Some(
                fs::symlink_metadata(&task.source)
                    .with_context(|| format!("snapshot move source {}", task.source.display()))?,
            );
            #[cfg(windows)]
            {
                task.move_windows_identity = Some(windows_file_identity(&task.source)?);
            }
        }
        for directory in &mut plan.directories {
            directory.move_identity =
                Some(fs::symlink_metadata(&directory.source).with_context(|| {
                    format!("snapshot move directory {}", directory.source.display())
                })?);
            #[cfg(windows)]
            {
                directory.move_windows_identity = Some(windows_file_identity(&directory.source)?);
            }
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
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("reserve temporary file {}", path.display()))
}

fn new_temp_path(destination: &Path) -> Result<PathBuf> {
    let parent = destination.parent().context("destination has no parent")?;
    let index = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(".mch-tmp-{}-{index}", std::process::id())))
}

// Enforce no-overwrite *at publication*, not only with a preflight check.
// Prefer the OS-native exclusive rename (Linux/Android renameat2,
// macOS renameatx_np, Windows MoveFileExW without REPLACE_EXISTING).
// For older Linux and other Unix targets, hard-link publication is the
// fail-closed fallback; never use a replacement-capable plain rename.
#[cfg(all(unix, any(target_os = "macos", test)))]
fn exclusive_nonatomic_copy(
    pinned_stage: &fs::File,
    stage_path: &Path,
    destination: &Path,
) -> Result<fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut input = pinned_stage
        .try_clone()
        .context("clone pinned staged inode")?;
    ensure_regular_file(&input)?;
    input.seek(SeekFrom::Start(0))?;
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create_new(true).mode(0o600);
    // O_EXCL ensures a symlink or concurrently created target is NEVER
    // followed or overwritten. The output is *visible while filling*.
    let mut output = options.open(destination).with_context(|| {
        format!(
            "create exclusive non-atomic target {} (existing target is preserved)",
            destination.display()
        )
    })?;
    let copy_result = (|| -> Result<()> {
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        input.seek(SeekFrom::Start(0))?;
        output.seek(SeekFrom::Start(0))?;
        let mut source_buffer = vec![0_u8; 1024 * 1024];
        let mut destination_buffer = vec![0_u8; 1024 * 1024];
        loop {
            let n = input.read(&mut source_buffer)?;
            if n == 0 {
                ensure!(
                    output.read(&mut destination_buffer[..1])? == 0,
                    "non-atomic destination has trailing bytes"
                );
                break;
            }
            output.read_exact(&mut destination_buffer[..n])?;
            ensure!(
                source_buffer[..n] == destination_buffer[..n],
                "non-atomic destination content differs from verified stage"
            );
        }
        Ok(())
    })();
    if let Err(error) = copy_result {
        return Err(error).with_context(|| format!(
            "non-atomic publish FAILED for {}; destination may contain partial data, source is retained",
            destination.display()
        ));
    }
    let expected = pinned_stage.metadata()?;
    let written = output.metadata()?;
    ensure!(
        expected.len() == written.len(),
        "non-atomic output size mismatch; destination may be partial"
    );
    let current = fs::symlink_metadata(destination)?;
    ensure!(
        current.dev() == written.dev() && current.ino() == written.ino(),
        "non-atomic destination was replaced concurrently; refusing success"
    );
    fs::remove_file(stage_path)?;
    Ok(output)
}

#[cfg(all(unix, any(target_os = "macos", test)))]
fn ensure_regular_file(fd: &fs::File) -> Result<()> {
    anyhow::ensure!(
        fd.metadata()?.is_file(),
        "exclusive fallback requires a regular stage"
    );
    Ok(())
}

// Retain the original strict atomic contract for --resume and tests.
#[cfg(any(unix, test))]
pub(crate) fn publish_stage(stage: &Path, destination: &Path, overwrite: bool) -> Result<()> {
    publish_stage_options(stage, destination, overwrite, false, None).map(|_| ())
}

// A successful macOS fallback returns the pinned destination inode. The
// caller must apply permissions/timestamps to THIS descriptor, not the stage.
fn publish_stage_options(
    stage: &Path,
    destination: &Path,
    overwrite: bool,
    _allow_nonatomic: bool,
    _stage_fd: Option<&fs::File>,
) -> Result<Option<fs::File>> {
    if !overwrite {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            let src = CString::new(stage.as_os_str().as_bytes())
                .context("temporary path contains a NUL")?;
            let dst = CString::new(destination.as_os_str().as_bytes())
                .context("destination path contains a NUL")?;
            // Native atomic move with RENAME_NOREPLACE. This also handles
            // Android environments that prohibit owner-created hard links.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    src.as_ptr(),
                    libc::AT_FDCWD,
                    dst.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if rc == 0 {
                return Ok(None);
            }
            let error = std::io::Error::last_os_error();
            // On older kernels or unsupported filesystems, try an equally
            // no-replace link operation. Never fall back to fs::rename.
            if !matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP)
            ) {
                return Err(error)
                    .with_context(|| format!("no-replace publish {}", destination.display()));
            }
        }
        #[cfg(target_os = "macos")]
        {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            let from =
                CString::new(stage.as_os_str().as_bytes()).context("stage name contains a NUL")?;
            let to = CString::new(destination.as_os_str().as_bytes())
                .context("destination name contains a NUL")?;
            // RENAME_EXCL is the Darwin equivalent of RENAME_NOREPLACE.
            // Do not fall back to replacement-capable fs::rename.
            let rc = unsafe {
                libc::renameatx_np(
                    libc::AT_FDCWD,
                    from.as_ptr(),
                    libc::AT_FDCWD,
                    to.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            if rc != 0 {
                let error = std::io::Error::last_os_error();
                // No replacement-capable rename: ExFAT's FSKit implementation
                // rejects RENAME_EXCL, and also has no hard links. The only
                // portable exclusive creation is O_CREAT|O_EXCL. This option
                // is *not atomic* for observers; user must explicitly opt in.
                if _allow_nonatomic
                    && matches!(
                        error.raw_os_error(),
                        Some(libc::ENOTSUP | libc::EOPNOTSUPP | libc::EINVAL)
                    )
                {
                    let fd = _stage_fd
                        .context("non-atomic publish requires a pinned regular-file stage")?;
                    return exclusive_nonatomic_copy(fd, stage, destination).map(Some);
                }
                return Err(error).with_context(|| format!(
                    "exclusive publish {} (filesystem may not support atomic no-replace; --allow-nonatomic-publish opts into a non-atomic, verified copy that can leave a partial target on crash)",
                    destination.display()
                ));
            }
            return Ok(None);
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn MoveFileExW(existing: *const u16, destination: *const u16, flags: u32) -> i32;
            }
            // std::fs canonicalization supplies a verbatim parent for long DOS
            // and UNC paths. The final components must still refer to the named entries.
            let parent = fs::canonicalize(stage.parent().context("stage has no parent")?)?;
            let stage_name = parent.join(stage.file_name().context("stage has no filename")?);
            let dest_parent =
                fs::canonicalize(destination.parent().context("destination has no parent")?)?;
            let dest_name = dest_parent.join(
                destination
                    .file_name()
                    .context("destination has no filename")?,
            );
            let from = stage_name
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let to = dest_name
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            if from[..from.len() - 1].contains(&0) || to[..to.len() - 1].contains(&0) {
                bail!("Windows publish path contains an interior NUL");
            }
            // Zero flags deliberately excludes both MOVEFILE_REPLACE_EXISTING
            // and MOVEFILE_COPY_ALLOWED. Stage and target share a parent,
            // so this is a same-volume no-replace move, not a copy+delete.
            let rc = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) };
            if rc == 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("exclusive publish {}", destination.display()));
            }
            return Ok(None);
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            fs::hard_link(stage, destination).with_context(|| {
                format!(
                    "destination appeared or filesystem does not support safe no-replace publish: {}",
                    destination.display()
                )
            })?;
            fs::remove_file(stage)
                .with_context(|| format!("remove published temporary name {}", stage.display()))?;
            return Ok(None);
        }
    }
    atomic_replace(stage, destination)?;
    Ok(None)
}

pub(crate) fn atomic_replace(stage: &Path, destination: &Path) -> Result<()> {
    // Both names share a directory. Let the OS replace the destination in one rename.
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

    let temporary_path = new_temp_path(&task.destination)?;
    let (temporary, staged_handle, original_permissions) = match task.kind {
        Kind::Regular => {
            // Exclusive creation keeps stale names non-destructive; all writes
            // use the same open file descriptor (never reopen by path).
            let mut staged = reserve_private_stage(&temporary_path)?;
            let temporary = TempPath(temporary_path);
            let mut source = fs::File::open(&task.source)
                .with_context(|| format!("open source {}", task.source.display()))?;
            let original_permissions = source.metadata()?.permissions();
            if cli.sparse {
                crate::sparse::copy(&mut source, &mut staged, progress)?;
            } else if let Some(progress) = progress {
                let mut buffer = vec![0_u8; 1024 * 1024];
                loop {
                    let size = loop {
                        match source.read(&mut buffer) {
                            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                            result => break result,
                        }
                    }
                    .with_context(|| format!("read source {}", task.source.display()))?;
                    if size == 0 {
                        break;
                    }
                    staged
                        .write_all(&buffer[..size])
                        .with_context(|| format!("write staged file {}", temporary.0.display()))?;
                    progress.add_bytes(size as u64);
                }
            } else {
                // std::io::copy specializes file-to-file transfers where the
                // platform permits; crucially it uses our private open handle.
                std::io::copy(&mut source, &mut staged).with_context(|| {
                    format!(
                        "copy {} -> {}",
                        task.source.display(),
                        temporary.0.display()
                    )
                })?;
            }
            drop(source);

            if !cli.no_hash {
                let original_hash =
                    crate::hashing::hash_file_counted(&task.source, cli.hash, progress)?;
                let staged_hash =
                    crate::hashing::hash_file_counted(&temporary.0, cli.hash, progress)?;
                if original_hash != staged_hash {
                    bail!(
                        "{} verification FAILED for {} -> {}",
                        cli.hash.label(),
                        task.source.display(),
                        task.destination.display()
                    );
                }
            }
            (temporary, Some(staged), Some(original_permissions))
        }
        Kind::Symlink => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                let link = fs::read_link(&task.source)?;
                symlink(&link, &temporary_path)?;
                let temporary = TempPath(temporary_path);
                if !cli.no_hash && fs::read_link(&temporary.0)? != link {
                    bail!("symlink verification FAILED: {}", task.source.display());
                }
                (temporary, None, None)
            }
            #[cfg(not(unix))]
            bail!("symlink copies are unsupported on this platform");
        }
    };

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

    // Keep the original private staging handle until after publication.
    // Flush verified bytes before any destructive replacement or move,
    // including on Windows. Ordinary copies retain the faster default.
    if (cli.move_mode || cli.overwrite)
        && let Some(staged) = &staged_handle
    {
        staged
            .sync_all()
            .with_context(|| format!("sync staged data {}", temporary.0.display()))?;
    }

    // Recheck before committing: the target might have changed during a long copy.
    check_destination_file(&task.source, &task.destination, cli.overwrite)?;
    let exclusive_output = publish_stage_options(
        &temporary.0,
        &task.destination,
        may_replace(task.overwrite_target.as_ref(), &task.destination)?,
        cli.allow_nonatomic_publish,
        staged_handle.as_ref(),
    )?;
    // On the non-atomic macOS fallback, the stage and published inode differ.
    // Restore times on the *pinned* output, not the now-removed staged name.
    if let Some(output) = &exclusive_output
        && let Some((atime, mtime)) = task.source_times
    {
        filetime::set_file_handle_times(output, Some(atime), Some(mtime))?;
    }
    let published_handle = exclusive_output.as_ref().or(staged_handle.as_ref());
    // Restore original permissions only through the published inode.
    if let (Some(staged), Some(permissions)) = (published_handle, original_permissions) {
        staged.set_permissions(permissions).with_context(|| {
            format!(
                "apply published file permissions {}",
                task.destination.display()
            )
        })?;
        if cli.move_mode || cli.overwrite || exclusive_output.is_some() {
            staged.sync_all().with_context(|| {
                format!(
                    "sync published file metadata {}",
                    task.destination.display()
                )
            })?;
        }
    }

    // For a destructive overwrite the rename itself must be synchronized on
    // Unix after data and metadata; otherwise power loss can undo the rename.
    #[cfg(unix)]
    if cli.overwrite {
        fs::File::open(parent)
            .with_context(|| format!("open published directory {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("sync published directory {}", parent.display()))?;
    }

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

// A verified copy is not enough for MOVE: a later --overwrite could have
// replaced an earlier planned destination on a case-insensitive filesystem.
// Re-hash *all* final names, even under --no-hash, before deleting any source.
fn verify_move_destinations(plan: &Plan) -> Result<()> {
    #[cfg(unix)]
    let mut file_ids = HashSet::<(u64, u64)>::new();
    #[cfg(windows)]
    let mut windows_file_ids = HashSet::<WindowsFileIdentity>::new();
    for dir in &plan.directories {
        let metadata = fs::symlink_metadata(&dir.destination).with_context(|| {
            format!(
                "move destination directory missing: {}",
                dir.destination.display()
            )
        })?;
        if !metadata.is_dir() {
            bail!(
                "move destination is no longer a directory: {}",
                dir.destination.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !file_ids.insert((metadata.dev(), metadata.ino())) {
                bail!("two planned move directories resolve to one destination; sources retained");
            }
        }
        #[cfg(windows)]
        if !windows_file_ids.insert(windows_file_identity(&dir.destination)?) {
            bail!(
                "two planned Windows move directories resolve to one destination; sources retained"
            );
        }
    }
    for task in &plan.files {
        let target_meta = fs::symlink_metadata(&task.destination)
            .with_context(|| format!("move destination missing: {}", task.destination.display()))?;
        let source_meta = fs::symlink_metadata(&task.source)
            .with_context(|| format!("move source missing: {}", task.source.display()))?;
        ensure_move_kind(
            &task.source,
            &source_meta,
            &task.destination,
            &target_meta,
            task.kind,
        )?;
        match task.kind {
            Kind::Regular => {
                if source_meta.len() != target_meta.len()
                    || hash_file(&task.source, crate::HashAlg::Blake3)?
                        != hash_file(&task.destination, crate::HashAlg::Blake3)?
                {
                    bail!(
                        "move target content mismatch; sources retained: {}",
                        task.destination.display()
                    );
                }
            }
            Kind::Symlink =>
            {
                #[cfg(unix)]
                if fs::read_link(&task.source)? != fs::read_link(&task.destination)? {
                    bail!(
                        "move target symlink mismatch; sources retained: {}",
                        task.destination.display()
                    );
                }
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !file_ids.insert((target_meta.dev(), target_meta.ino())) {
                bail!("two planned move destinations resolve to the same inode; sources retained");
            }
        }
        #[cfg(windows)]
        if !windows_file_ids.insert(windows_file_identity(&task.destination)?) {
            bail!("two planned Windows move destinations resolve to one file ID; sources retained");
        }
    }
    Ok(())
}

fn ensure_move_kind(
    source: &Path,
    source_meta: &fs::Metadata,
    destination: &Path,
    target_meta: &fs::Metadata,
    kind: Kind,
) -> Result<()> {
    let matches = match kind {
        Kind::Regular => source_meta.is_file() && target_meta.is_file(),
        Kind::Symlink => {
            source_meta.file_type().is_symlink() && target_meta.file_type().is_symlink()
        }
    };
    if !matches {
        bail!(
            "move source/destination type changed; sources retained: {} -> {}",
            source.display(),
            destination.display()
        );
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
        #[cfg(windows)]
        if file.move_windows_identity != Some(windows_file_identity(&file.source)?) {
            bail!(
                "move source Windows file ID changed; refusing deletion: {}",
                file.source.display()
            );
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
            use std::os::windows::fs::MetadataExt;
            if current.creation_time() != original.creation_time()
                || dir.move_windows_identity != Some(windows_file_identity(&dir.source)?)
            {
                bail!(
                    "move source directory Windows file ID changed; refusing deletion: {}",
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
        #[cfg(not(windows))]
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
            plan.files[0].overwrite_target.as_ref(),
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
            Some(scope.spawn(move || {
                crate::progress::watch(
                    tracker_ref,
                    receiver,
                    std::time::Duration::from_millis(cli.progress_interval_ms),
                )
            }))
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
        verify_move_destinations(plan)?;
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
    fn new_destination_ancestors_remain_private_even_before_final_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("data/private/inner");
        ensure_directory(&nested).unwrap();
        for dir in [
            tmp.path().join("data"),
            tmp.path().join("data/private"),
            nested,
        ] {
            assert_eq!(
                fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700,
                "new destination ancestor must not expose private source contents: {}",
                dir.display()
            );
        }
    }

    #[test]
    fn move_requires_each_empty_destination_directory_before_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("source");
        let dest = tmp.path().join("dest");
        fs::create_dir(&src).unwrap();
        fs::create_dir(&dest).unwrap();
        let cli = Cli::parse_from([
            "mch",
            "--move",
            src.to_str().unwrap(),
            dest.to_str().unwrap(),
        ]);
        let plan = build_plan(&cli, &dest).unwrap();
        let target = &plan.directories[0].destination;
        assert!(verify_move_destinations(&plan).is_err());
        fs::write(target, b"wrong type").unwrap();
        assert!(verify_move_destinations(&plan).is_err());
        fs::remove_file(target).unwrap();
        fs::create_dir(target).unwrap();
        assert!(verify_move_destinations(&plan).is_ok());
        assert!(src.is_dir());
    }

    #[test]
    fn move_target_recheck_catches_replaced_destination_even_same_size() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("source");
        let dest = tmp.path().join("dest");
        fs::write(&src, b"AAA").unwrap();
        fs::write(&dest, b"AAA").unwrap();
        let cli = Cli::parse_from([
            "mch",
            "--move",
            "--overwrite",
            src.to_str().unwrap(),
            dest.to_str().unwrap(),
        ]);
        let plan = build_plan(&cli, &dest).unwrap();
        fs::write(&dest, b"BBB").unwrap();
        assert!(verify_move_destinations(&plan).is_err());
        assert_eq!(fs::read(&src).unwrap(), b"AAA");
    }

    #[test]
    fn overwrite_only_replaces_the_planned_destination() {
        for resume in [false, true] {
            if resume && !cfg!(unix) {
                continue;
            }
            for existed in [false, true] {
                let tmp = tempfile::tempdir().unwrap();
                let src = tmp.path().join("source");
                let dst = tmp.path().join("destination");
                fs::write(&src, b"copy").unwrap();
                if existed {
                    fs::write(&dst, b"old").unwrap();
                }
                let mut args = vec!["mch", "--move", "--overwrite"];
                if resume {
                    args.push("--resume");
                }
                args.extend([src.to_str().unwrap(), dst.to_str().unwrap()]);
                let cli = Cli::parse_from(args);
                let plan = build_plan(&cli, &dst).unwrap();
                if existed {
                    fs::rename(&dst, tmp.path().join("retired")).unwrap();
                }
                fs::write(&dst, b"new").unwrap();
                assert!(execute(&cli, &plan).is_err());
                assert_eq!(fs::read(&src).unwrap(), b"copy");
                assert_eq!(fs::read(&dst).unwrap(), b"new");
            }
        }
    }

    #[test]
    fn publication_without_overwrite_refuses_a_new_target() {
        let t = tempfile::tempdir().unwrap();
        let stage = t.path().join("staged");
        let destination = t.path().join("new-target");
        fs::write(&stage, b"new copy").unwrap();
        fs::write(&destination, b"precious other data").unwrap();
        assert!(publish_stage(&stage, &destination, false).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"precious other data");
        assert_eq!(fs::read(&stage).unwrap(), b"new copy");
    }

    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn native_exclusive_publish_consumes_stage_without_hardlink_fallback() {
        let t = tempfile::tempdir().unwrap();
        let stage = t.path().join("staged");
        let destination = t.path().join("new-target");
        fs::write(&stage, b"verified copy").unwrap();
        publish_stage(&stage, &destination, false).unwrap();
        assert!(
            !stage.exists(),
            "native rename should consume the staging name"
        );
        assert_eq!(fs::read(&destination).unwrap(), b"verified copy");
        assert!(publish_stage(&stage, &destination, false).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"verified copy");
    }

    #[cfg(unix)]
    #[test]
    fn exclusive_nonatomic_copy_verifies_bytes_and_does_not_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join("stage");
        let target = dir.path().join("target");
        let mut pinned = reserve_private_stage(&stage).unwrap();
        let expected = vec![0xAD_u8; 2 * 1024 * 1024 + 117];
        pinned.write_all(&expected).unwrap();
        pinned.sync_all().unwrap();
        let published = exclusive_nonatomic_copy(&pinned, &stage, &target).unwrap();
        assert_eq!(published.metadata().unwrap().len(), expected.len() as u64);
        assert!(!stage.exists());
        assert_eq!(fs::read(&target).unwrap(), expected);

        let second_stage = dir.path().join("second_stage");
        let mut new = reserve_private_stage(&second_stage).unwrap();
        new.write_all(b"other content").unwrap();
        assert!(exclusive_nonatomic_copy(&new, &second_stage, &target).is_err());
        assert_eq!(fs::read(&target).unwrap(), expected);
        assert_eq!(fs::read(&second_stage).unwrap(), b"other content");
    }

    #[cfg(unix)]
    #[test]
    fn exclusive_nonatomic_copy_refuses_symlink_and_preserves_target() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join("stage");
        let target = dir.path().join("target");
        let victim = dir.path().join("victim");
        fs::write(&victim, b"valuable").unwrap();
        let mut pinned = reserve_private_stage(&stage).unwrap();
        pinned.write_all(b"untrusted").unwrap();
        symlink(&victim, &target).unwrap();
        assert!(exclusive_nonatomic_copy(&pinned, &stage, &target).is_err());
        assert_eq!(fs::read(victim).unwrap(), b"valuable");
        assert!(
            fs::symlink_metadata(target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(stage).unwrap(), b"untrusted");
    }

    #[cfg(unix)]
    #[test]
    fn exclusive_nonatomic_copy_concurrent_writers_have_one_winner() {
        use std::sync::{Arc, Barrier};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let barrier = Arc::new(Barrier::new(6));
        let mut threads = Vec::new();
        for id in 0..6_u8 {
            let stage = dir.path().join(format!("stage-{id}"));
            let mut fd = reserve_private_stage(&stage).unwrap();
            fd.write_all(&vec![id; 16_384]).unwrap();
            let dest = target.clone();
            let shared = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                shared.wait();
                exclusive_nonatomic_copy(&fd, &stage, &dest).is_ok()
            }));
        }
        let results = threads
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|&&succeeded| succeeded).count(), 1);
        let content = fs::read(target).unwrap();
        assert_eq!(content.len(), 16_384);
        assert!(content.iter().all(|byte| *byte == content[0]));
    }

    #[cfg(unix)]
    #[test]
    fn publication_without_overwrite_refuses_dangling_symlink_target() {
        use std::os::unix::fs::symlink;
        let t = tempfile::tempdir().unwrap();
        let stage = t.path().join("staged");
        let destination = t.path().join("new-target");
        fs::write(&stage, b"new copy").unwrap();
        symlink(t.path().join("missing"), &destination).unwrap();
        assert!(publish_stage(&stage, &destination, false).is_err());
        assert!(
            fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&stage).unwrap(), b"new copy");
    }

    #[test]
    fn concurrent_no_overwrite_publications_have_one_winner() {
        use std::sync::{Arc, Barrier};
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("shared-destination");
        let num = 8;
        let barrier = Arc::new(Barrier::new(num));
        let mut workers = Vec::new();
        for id in 0..num {
            let path = t.path().join(format!("stage-{id}"));
            fs::write(&path, format!("payload-{id}")).unwrap();
            let target = target.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                let result = publish_stage(&path, &target, false);
                (id, result.is_ok())
            }));
        }
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        let winners: Vec<_> = results.iter().filter(|(_, ok)| *ok).collect();
        assert_eq!(
            winners.len(),
            1,
            "exactly one simultaneous publisher must win"
        );
        assert_eq!(
            fs::read_to_string(target).unwrap(),
            format!("payload-{}", winners[0].0)
        );
    }

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

    #[cfg(windows)]
    #[test]
    fn windows_file_identity_detects_replaced_directory_with_identical_timestamp() {
        let t = tempfile::tempdir().unwrap();
        let source = t.path().join("source");
        let renamed = t.path().join("renamed");
        fs::create_dir(&source).unwrap();
        let before = windows_file_identity(&source).unwrap();
        fs::rename(&source, &renamed).unwrap();
        assert_eq!(before, windows_file_identity(&renamed).unwrap());
        fs::create_dir(&source).unwrap();
        let after = windows_file_identity(&source).unwrap();
        assert_ne!(
            before, after,
            "replacement must have a different Windows file ID"
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
