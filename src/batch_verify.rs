// SPDX-License-Identifier: AGPL-3.0-or-later
//
// PRIVATE EXPERIMENTAL: descriptor-relative completed-file revalidation.
// Used by the unmerged --resume-dir CLI pilot; never trust a journal event
// without full independent source and target rehashing.
// Does not copy, overwrite, rename or delete anything. Planning uses pinned
// descriptors; the separate writer is still pathname-based and not audited.
use crate::batch_plan::JobPlan;
use anyhow::{Context, Result, ensure};
use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const CHUNK_SIZE: usize = 128 * 1024;

pub(crate) fn directory_flags() -> i32 {
    let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY;
    // Android SELinux does not permit O_RDONLY on some path ancestors.
    // O_PATH is enough for fstat and openat traversal on Linux and Android.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        flags | libc::O_PATH
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        flags | libc::O_RDONLY
    }
}

pub(crate) fn component_fd(parent: &File, name: &[u8], directory: bool) -> Result<File> {
    ensure!(
        !name.is_empty() && name != b"." && name != b".." && !name.contains(&b'/'),
        "invalid descriptor-relative component"
    );
    let c_name = CString::new(name).context("NUL in path component")?;
    let flags = if directory {
        directory_flags()
    } else {
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
    };
    // SAFETY: parent is a live directory fd, name is a validated single
    // component, and this three-argument openat does not use creation mode.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), c_name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("openat component {:?}", name));
    }
    // SAFETY: successful openat returns a new uniquely owned file descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    if directory {
        ensure!(meta.is_dir(), "opened component is not a directory");
    } else {
        ensure!(
            meta.is_file() && meta.nlink() == 1,
            "not a single-link regular file"
        );
    }
    Ok(file)
}

// Resolve *every* path component from a known directory fd, never via a
// followed symlink. /var -> /private/var aliases are intentionally refused;
// test fixtures use canonicalize() to supply physically normalized roots.
pub(crate) fn root_directory(path: &[u8]) -> Result<File> {
    ensure!(
        path.starts_with(b"/") && path.len() > 1,
        "absolute non-root path required"
    );
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(directory_flags())
        .open("/")?;
    for component in path[1..].split(|byte| *byte == b'/') {
        current = component_fd(&current, component, true)?;
    }
    Ok(current)
}

fn open_planned_file(root: &[u8], relative: &[u8], plan: &JobPlan, source: bool) -> Result<File> {
    let mut parent = root_directory(root)?;
    let mut prefix = Vec::<u8>::new();
    let mut components = relative.split(|b| *b == b'/').peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            return component_fd(&parent, component, false);
        }
        if !prefix.is_empty() {
            prefix.push(b'/');
        }
        prefix.extend_from_slice(component);
        parent = component_fd(&parent, component, true)?;
        if source {
            let (device, inode) = plan.planned_directory_inode(&prefix)?;
            let meta = parent.metadata()?;
            ensure!(
                meta.dev() == device && meta.ino() == inode,
                "source ancestor inode changed since planning"
            );
        }
    }
    anyhow::bail!("missing file component")
}

#[derive(Debug, PartialEq, Eq)]
struct Stable {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

fn stamp(meta: &Metadata) -> Stable {
    Stable {
        dev: meta.dev(),
        ino: meta.ino(),
        size: meta.len(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        ctime: meta.ctime(),
        ctime_nsec: meta.ctime_nsec(),
    }
}

fn hash_open_file(file: &mut File) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; CHUNK_SIZE];
    loop {
        let size = file
            .read(&mut buffer)
            .context("rehash existing completed file")?;
        if size == 0 {
            break;
        }
        hasher.update(&buffer[..size]);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn verify_completed(
    plan: &JobPlan,
    file_index: u64,
    journal_digest: Option<&[u8; 32]>,
) -> Result<[u8; 32]> {
    let planned = plan.regular_entry(file_index)?;
    let (source_root, target_root) = plan.roots();
    let (expected_source_root, expected_target_root) = plan.root_identities();
    let source_root_fd = root_directory(source_root)?;
    let source_meta = source_root_fd.metadata()?;
    ensure!(
        (source_meta.dev(), source_meta.ino()) == expected_source_root,
        "source root inode replaced since job planning"
    );
    if let Some(expected) = expected_target_root {
        let target_root_fd = root_directory(target_root)?;
        let target_meta = target_root_fd.metadata()?;
        ensure!(
            (target_meta.dev(), target_meta.ino()) == expected,
            "target root inode replaced since job planning"
        );
    }

    // Both endpoints are opened with independent paths anchored at '/' and
    // descriptor-relative traversal. Neither a symlink nor a hardlink is accepted.
    let mut source = open_planned_file(source_root, planned.relative, plan, true)?;
    let mut target = open_planned_file(target_root, planned.relative, plan, false)?;
    let before_source = stamp(&source.metadata()?);
    let before_target = stamp(&target.metadata()?);

    ensure!(
        before_source.dev == planned.device
            && before_source.ino == planned.inode
            && before_source.size == planned.size
            && before_source.mtime == planned.mtime_sec
            && before_source.mtime_nsec == planned.mtime_nsec,
        "source identity or metadata differs from immutable job plan"
    );
    ensure!(
        before_target.size == before_source.size,
        "source and target sizes differ"
    );
    ensure!(
        (before_source.dev, before_source.ino) != (before_target.dev, before_target.ino),
        "source and target are the same inode"
    );

    let source_digest = hash_open_file(&mut source)?;
    let target_digest = hash_open_file(&mut target)?;
    ensure!(
        source_digest == target_digest,
        "completed file hash differs from current source"
    );
    if let Some(saved) = journal_digest {
        ensure!(
            &source_digest == saved,
            "current data differs from recorded verified digest"
        );
    }

    ensure!(
        stamp(&source.metadata()?) == before_source,
        "source changed during verification"
    );
    ensure!(
        stamp(&target.metadata()?) == before_target,
        "target changed during verification"
    );
    Ok(source_digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, JobPlan) {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let src = root.join("source");
        let dst = root.join("target");
        fs::create_dir(&src).unwrap();
        fs::create_dir(&dst).unwrap();
        fs::create_dir(src.join("nested")).unwrap();
        fs::create_dir(dst.join("nested")).unwrap();
        fs::write(src.join("nested/file"), b"original contents").unwrap();
        fs::write(dst.join("nested/file"), b"original contents").unwrap();
        let plan = JobPlan::build(&src, &dst).unwrap();
        (temp, src, dst, plan)
    }

    #[test]
    fn full_rehash_with_and_without_recorded_digest() {
        let (_tmp, _src, _dst, plan) = fixture();
        assert_eq!(plan.regular_files(), 1);
        let digest = verify_completed(&plan, 0, None).unwrap();
        assert_eq!(digest, *blake3::hash(b"original contents").as_bytes());
        assert_eq!(verify_completed(&plan, 0, Some(&digest)).unwrap(), digest);
        assert!(verify_completed(&plan, 1, None).is_err());
        assert!(verify_completed(&plan, 0, Some(&[0; 32])).is_err());
    }

    #[test]
    fn destination_corruption_with_equal_size_is_rejected() {
        let (_tmp, _src, dst, plan) = fixture();
        fs::write(dst.join("nested/file"), b"changed_ contents").unwrap();
        assert!(verify_completed(&plan, 0, None).is_err());
        assert_eq!(
            fs::read(dst.join("nested/file")).unwrap(),
            b"changed_ contents"
        );
    }

    #[test]
    fn source_corruption_with_restored_mtime_is_rejected() {
        let (_tmp, src, _dst, plan) = fixture();
        let path = src.join("nested/file");
        let original =
            filetime::FileTime::from_last_modification_time(&fs::metadata(&path).unwrap());
        fs::write(&path, b"tampered contents").unwrap();
        filetime::set_file_mtime(&path, original).unwrap();
        assert!(verify_completed(&plan, 0, None).is_err());
    }

    #[test]
    fn changed_source_inode_even_same_bytes_is_rejected() {
        let (_tmp, src, _dst, plan) = fixture();
        let replacement = src.join("nested/new");
        fs::write(&replacement, b"original contents").unwrap();
        fs::rename(&replacement, src.join("nested/file")).unwrap();
        assert!(verify_completed(&plan, 0, None).is_err());
    }

    #[test]
    fn target_symlink_or_parent_symlink_never_opened() {
        let (_tmp, _src, dst, plan) = fixture();
        let outside = dst.join("unrelated");
        fs::write(&outside, b"preserve outside").unwrap();
        fs::remove_file(dst.join("nested/file")).unwrap();
        symlink(&outside, dst.join("nested/file")).unwrap();
        assert!(verify_completed(&plan, 0, None).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"preserve outside");
        fs::remove_file(dst.join("nested/file")).unwrap();
        fs::remove_dir(dst.join("nested")).unwrap();
        symlink(&outside, dst.join("nested")).unwrap();
        assert!(verify_completed(&plan, 0, None).is_err());
    }

    #[test]
    fn replaced_source_or_target_root_inode_is_rejected() {
        let (_tmp, src, _dst, plan) = fixture();
        let source_old = src.with_extension("old");
        fs::rename(&src, &source_old).unwrap();
        fs::create_dir(&src).unwrap();
        fs::create_dir(src.join("nested")).unwrap();
        fs::write(src.join("nested/file"), b"original contents").unwrap();
        assert!(verify_completed(&plan, 0, None).is_err());

        let (_tmp, _src, dst, plan) = fixture();
        let target_old = dst.with_extension("old");
        fs::rename(&dst, &target_old).unwrap();
        fs::create_dir(&dst).unwrap();
        fs::create_dir(dst.join("nested")).unwrap();
        fs::write(dst.join("nested/file"), b"original contents").unwrap();
        assert!(verify_completed(&plan, 0, None).is_err());
    }

    #[test]
    fn replaced_source_parent_is_rejected_even_for_identical_file() {
        let (_tmp, src, _dst, plan) = fixture();
        let original = src.join("nested");
        fs::rename(&original, src.join("old-nested")).unwrap();
        fs::create_dir(&original).unwrap();
        fs::write(original.join("file"), b"original contents").unwrap();
        assert!(verify_completed(&plan, 0, None).is_err());
    }

    #[test]
    fn opened_directory_fd_does_not_follow_later_path_swap() {
        let (_tmp, _src, dst, _plan) = fixture();
        let root = fs::canonicalize(&dst).unwrap();
        let anchored = root_directory(root.as_os_str().as_encoded_bytes()).unwrap();
        let opened = component_fd(&anchored, b"nested", true).unwrap();
        fs::rename(dst.join("nested"), dst.join("safe-moved")).unwrap();
        let other = dst.join("unrelated");
        fs::write(&other, b"unrelated data").unwrap();
        symlink(&other, dst.join("nested")).unwrap();
        let mut file = component_fd(&opened, b"file", false).unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();
        assert_eq!(data, b"original contents");
        assert_eq!(fs::read(other).unwrap(), b"unrelated data");
    }
}
