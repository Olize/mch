// SPDX-License-Identifier: AGPL-3.0-or-later
//
// PRIVATE experimental Unix planner: pin directories with openat and enumerate
// with fdopendir/readdir. This closes pathname-swap traversal in the planner,
// but does NOT make the separate legacy copy writer race-safe.
use crate::batch_plan::{Entry, EntryKind, entry, validate_relative};
use crate::batch_verify::{component_fd, root_directory};
use anyhow::{Context, Result, bail, ensure};
use std::ffi::{CStr, OsString};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const MAX_ENTRIES: usize = 100_000;

#[cfg(target_os = "android")]
fn errno_ptr() -> *mut libc::c_int {
    // SAFETY: bionic exposes the thread-local errno pointer.
    unsafe { libc::__errno() }
}
#[cfg(target_os = "linux")]
fn errno_ptr() -> *mut libc::c_int {
    // SAFETY: glibc exposes the thread-local errno pointer.
    unsafe { libc::__errno_location() }
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn errno_ptr() -> *mut libc::c_int {
    // SAFETY: Darwin exposes the thread-local errno pointer.
    unsafe { libc::__error() }
}
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
compile_error!("batch fd planner requires a separately audited Unix errno implementation");

struct ReadDirectory(*mut libc::DIR);
impl Drop for ReadDirectory {
    fn drop(&mut self) {
        // SAFETY: fdopendir owns this live DIR pointer; closedir consumes it.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn list_names(dir: &File) -> Result<Vec<Vec<u8>>> {
    // Reopen '.' relative to a pinned directory inode with read permissions.
    // Linux O_PATH descriptors cannot be passed straight to fdopendir.
    // SAFETY: dir is a live directory descriptor and c"." is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("open pinned directory for enumeration");
    }
    // SAFETY: fdopendir takes ownership of the fresh descriptor on success.
    let handle = unsafe { libc::fdopendir(fd) };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(error).context("fdopendir");
    }
    let read_dir = ReadDirectory(handle);
    let mut names = Vec::new();
    loop {
        // SAFETY: errno is a writable thread-local variable. Clearing it
        // disambiguates end-of-stream from a readdir error.
        unsafe {
            *errno_ptr() = 0;
        }
        // SAFETY: read_dir owns a live DIR, never concurrently read here.
        let result = unsafe { libc::readdir(read_dir.0) };
        if result.is_null() {
            let code = unsafe { *errno_ptr() };
            if code != 0 {
                return Err(io::Error::from_raw_os_error(code)).context("readdir");
            }
            break;
        }
        // SAFETY: d_name is NUL-terminated in a successful dirent, valid
        // until the next readdir call; copy it before advancing.
        let name = unsafe { CStr::from_ptr((*result).d_name.as_ptr().cast()).to_bytes() };
        if name == b"." || name == b".." {
            continue;
        }
        ensure!(!name.is_empty(), "empty directory entry");
        names.push(name.to_vec());
        ensure!(names.len() <= MAX_ENTRIES, "too many directory entries");
    }
    names.sort_unstable();
    Ok(names)
}

fn root_if_exists(path: &Path) -> Result<Option<File>> {
    let bytes = path.as_os_str().as_bytes();
    ensure!(
        bytes.starts_with(b"/") && bytes.len() > 1,
        "invalid absolute root"
    );
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(super::batch_verify::directory_flags())
        .open("/")?;
    for component in bytes[1..].split(|b| *b == b'/') {
        match component_fd(&current, component, true) {
            Ok(next) => current = next,
            Err(err)
                if err.chain().any(|cause| {
                    cause
                        .downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == ErrorKind::NotFound)
                }) =>
            {
                return Ok(None);
            }
            Err(err) => return Err(err).context("open existing target root ancestor"),
        }
    }
    Ok(Some(current))
}

fn stat_child(parent: &File, name: &[u8]) -> Result<libc::stat> {
    let c_name = std::ffi::CString::new(name)?;
    let mut out = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent is a live fd; name is NUL-terminated and single-component.
    // fstatat populates out on success and does not follow symlinks.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            c_name.as_ptr(),
            out.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error()).context("lstat child relative to dirfd");
    }
    Ok(unsafe { out.assume_init() })
}

// libc::stat dev_t/ino_t widths differ between Darwin and Linux/Android.
#[allow(clippy::unnecessary_cast)]
fn verify_identity(opened: &File, before: &libc::stat) -> Result<Metadata> {
    let meta = opened.metadata()?;
    ensure!(
        meta.dev() == before.st_dev as u64 && meta.ino() == before.st_ino as u64,
        "directory entry replaced between lstat and pinned open"
    );
    Ok(meta)
}

fn stable_directory(before: &Metadata, after: &Metadata) -> Result<()> {
    ensure!(
        before.is_dir()
            && after.is_dir()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "directory changed during descriptor-anchored plan enumeration"
    );
    Ok(())
}

fn traverse(
    source: &File,
    target: Option<&File>,
    relative: &Path,
    entries: &mut Vec<Entry>,
    require_targets: bool,
) -> Result<()> {
    let before = source.metadata()?;
    ensure!(before.is_dir(), "opened source is not a directory");
    if !relative.as_os_str().is_empty() {
        entries.push(entry(relative, EntryKind::Directory, &before)?);
    }
    for raw_name in list_names(source)? {
        let child = relative.join(OsString::from_vec(raw_name.clone()));
        validate_relative(child.as_os_str().as_bytes())?;
        let source_stat = stat_child(source, &raw_name)?;
        let source_kind = source_stat.st_mode & libc::S_IFMT;
        if source_kind == libc::S_IFDIR {
            let child_src = component_fd(source, &raw_name, true)
                .context("open source subdirectory NOFOLLOW")?;
            verify_identity(&child_src, &source_stat)?;
            let child_dst = if let Some(target_fd) = target {
                match stat_child(target_fd, &raw_name) {
                    Ok(st) => {
                        ensure!(
                            st.st_mode & libc::S_IFMT == libc::S_IFDIR,
                            "target directory conflict / symlink"
                        );
                        let target_fd = component_fd(target_fd, &raw_name, true)?;
                        verify_identity(&target_fd, &st)?;
                        Some(target_fd)
                    }
                    Err(err)
                        if err.chain().any(|cause| {
                            cause
                                .downcast_ref::<io::Error>()
                                .is_some_and(|e| e.kind() == ErrorKind::NotFound)
                        }) =>
                    {
                        ensure!(
                            !require_targets,
                            "planned target directory missing: {}",
                            child.display()
                        );
                        None
                    }
                    Err(err) => return Err(err),
                }
            } else {
                None
            };
            traverse(
                &child_src,
                child_dst.as_ref(),
                &child,
                entries,
                require_targets,
            )?;
        } else if source_kind == libc::S_IFREG {
            let child_src = component_fd(source, &raw_name, false)
                .context("open source regular file NOFOLLOW/NONBLOCK")?;
            let src_meta = verify_identity(&child_src, &source_stat)?;
            ensure!(src_meta.nlink() == 1, "source hardlink unsupported");
            if let Some(target_fd) = target {
                match stat_child(target_fd, &raw_name) {
                    Ok(st) => {
                        ensure!(
                            st.st_mode & libc::S_IFMT == libc::S_IFREG && st.st_nlink == 1,
                            "target file conflict / symlink / hardlink"
                        );
                        let target_file = component_fd(target_fd, &raw_name, false)?;
                        verify_identity(&target_file, &st)?;
                    }
                    Err(err)
                        if err.chain().any(|cause| {
                            cause
                                .downcast_ref::<io::Error>()
                                .is_some_and(|e| e.kind() == ErrorKind::NotFound)
                        }) =>
                    {
                        ensure!(
                            !require_targets,
                            "planned target file missing: {}",
                            child.display()
                        );
                    }
                    Err(err) => return Err(err),
                }
            }
            entries.push(entry(&child, EntryKind::RegularFile, &src_meta)?);
        } else {
            bail!("unsupported or symlink source entry: {}", child.display());
        }
        ensure!(entries.len() <= MAX_ENTRIES, "too many plan entries");
    }
    stable_directory(&before, &source.metadata()?)?;
    Ok(())
}

pub(crate) fn collect(
    source: &Path,
    target: &Path,
    require_targets: bool,
) -> Result<(Metadata, Option<Metadata>, Vec<Entry>)> {
    let src = root_directory(source.as_os_str().as_bytes())
        .context("open source root via pinned NOFOLLOW path components")?;
    let dst = root_if_exists(target)?;
    ensure!(
        !require_targets || dst.is_some(),
        "planned target root missing"
    );
    let src_meta = src.metadata()?;
    let dst_meta = dst.as_ref().map(File::metadata).transpose()?;
    ensure!(src_meta.is_dir(), "source must be directory");
    if let Some(ref target_meta) = dst_meta {
        ensure!(target_meta.is_dir(), "target must be directory");
        ensure!(
            (src_meta.dev(), src_meta.ino()) != (target_meta.dev(), target_meta.ino()),
            "source and destination have the same inode"
        );
    }
    let mut entries = Vec::new();
    traverse(
        &src,
        dst.as_ref(),
        Path::new(""),
        &mut entries,
        require_targets,
    )?;
    stable_directory(&src_meta, &src.metadata()?)?;
    // Re-open both root paths to detect substitutions between original open
    // and end of planning. Runtime writer requires separate dirfd hardening.
    let src_current = root_directory(source.as_os_str().as_bytes())?;
    ensure!(
        src_meta.dev() == src_current.metadata()?.dev()
            && src_meta.ino() == src_current.metadata()?.ino(),
        "source root pathname changed while planning"
    );
    if let Some(ref old) = dst_meta {
        let new = root_directory(target.as_os_str().as_bytes())?;
        ensure!(
            old.dev() == new.metadata()?.dev() && old.ino() == new.metadata()?.ino(),
            "target root pathname changed while planning"
        );
    } else {
        ensure!(
            root_if_exists(target)?.is_none(),
            "new target appeared while planning"
        );
    }
    Ok((src_meta, dst_meta, entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, symlink};
    use std::path::PathBuf;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let src = root.join("src");
        let dst = root.join("dst");
        fs::create_dir(&src).unwrap();
        fs::create_dir(&dst).unwrap();
        (temp, src, dst)
    }

    #[test]
    fn pinned_directory_ignores_a_later_symlink_replacement() {
        let (_tmp, src, dst) = fixture();
        fs::create_dir(src.join("inside")).unwrap();
        fs::write(src.join("inside/safe"), b"protected").unwrap();
        fs::write(dst.join("unsafe"), b"not safe").unwrap();

        let src_fd = root_directory(src.as_os_str().as_bytes()).unwrap();
        let inside_fd = component_fd(&src_fd, b"inside", true).unwrap();
        fs::rename(src.join("inside"), src.join("moved")).unwrap();
        symlink(&dst, src.join("inside")).unwrap();

        assert_eq!(list_names(&inside_fd).unwrap(), vec![b"safe".to_vec()]);
        assert!(component_fd(&src_fd, b"inside", true).is_err());
        let safe = component_fd(&inside_fd, b"safe", false).unwrap();
        assert_eq!(safe.metadata().unwrap().len(), 9);
        assert_eq!(fs::read(dst.join("unsafe")).unwrap(), b"not safe");
    }

    #[test]
    fn rejects_symlinks_in_source_and_destination_ancestors() {
        let (_tmp, src, dst) = fixture();
        fs::create_dir(src.join("nested")).unwrap();
        fs::write(src.join("nested/file"), b"hello").unwrap();
        symlink(&src, src.parent().unwrap().join("src-link")).unwrap();
        assert!(collect(&src.parent().unwrap().join("src-link"), &dst, false).is_err());

        symlink(&src, dst.join("nested")).unwrap();
        assert!(collect(&src, &dst, false).is_err());
        assert!(collect(&src, &dst.join("nested").join("missing"), false).is_err());
        assert_eq!(fs::read(src.join("nested/file")).unwrap(), b"hello");
    }

    #[test]
    fn rejects_named_pipes_without_blocking_or_opening_for_read() {
        let (_tmp, src, dst) = fixture();
        let fifo = src.join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is NUL-terminated and points inside this private fixture.
        let created = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
        assert_eq!(created, 0, "mkfifo: {:?}", io::Error::last_os_error());
        assert!(collect(&src, &dst, false).is_err());
        assert!(fifo.symlink_metadata().unwrap().file_type().is_fifo());
    }
}
