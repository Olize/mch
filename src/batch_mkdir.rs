// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Private, experimental Unix directory creation. The target root is an
// existing directory anchored by inode. No filesystem paths are followed
// after initial root resolution; no symlinks or special entries are accepted.
// The private batch runtime now also uses a separate pinned NO-REPLACE writer.
// Public v0.2.1 single-file resume remains untouched.
use crate::batch_plan::{JobPlan, validate_relative};
use crate::batch_verify::{component_fd, root_directory};
use anyhow::{Context, Result, ensure};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

pub(crate) fn sync_pinned_dir(dir: &File) -> Result<()> {
    // SAFETY: dir points to a live pinned directory inode, "." is fixed.
    // O_RDONLY instead of O_PATH is required for fsync.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("open pinned directory for fsync");
    }
    // SAFETY: openat returned a newly owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    file.sync_all().context("fsync pinned directory")
}

fn child_dir(parent: &File, name: &[u8]) -> Result<File> {
    match component_fd(parent, name, true) {
        Ok(fd) => {
            // Recovery may find an existing entry created just before a
            // crash that happened before its parent fsync. Sync both again.
            sync_pinned_dir(&fd)?;
            sync_pinned_dir(parent)?;
            Ok(fd)
        }
        Err(error)
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == ErrorKind::NotFound)
            }) =>
        {
            let child = CString::new(name).context("NUL in directory component")?;
            // SAFETY: parent is pinned; name is NUL-terminated single component;
            // mode is a native mode_t (mkdirat is not variadic).
            let created = unsafe { libc::mkdirat(parent.as_raw_fd(), child.as_ptr(), 0o700) };
            if created != 0 {
                let err = io::Error::last_os_error();
                ensure!(
                    err.kind() == ErrorKind::AlreadyExists,
                    "mkdirat failed: {err}"
                );
            }
            // A concurrent rename/symlink insertion is refused by NOFOLLOW.
            let opened = component_fd(parent, name, true)
                .context("verify newly created target directory")?;
            // Synchronize the child's inode and the parent's new name.
            sync_pinned_dir(&opened)?;
            sync_pinned_dir(parent)?;
            Ok(opened)
        }
        Err(err) => Err(err).context("unsafe or inaccessible target directory component"),
    }
}

pub(crate) fn create_planned_directories(plan: &JobPlan) -> Result<()> {
    let (_, target_path) = plan.roots();
    let (_, planned_target) = plan.root_identities();
    let wanted = planned_target.context("target root must exist for directory resume")?;
    let root = root_directory(target_path)?;
    let meta = root.metadata()?;
    ensure!(
        (meta.dev(), meta.ino()) == wanted,
        "target root replaced since planning"
    );

    // Sorted directory entries ensure ancestors are created first, but walk
    // each one again from the pinned root rather than trusting pathnames.
    for relative in plan.directory_names() {
        validate_relative(relative)?;
        let mut parent = root.try_clone()?;
        for name in relative.split(|x| *x == b'/') {
            parent = child_dir(&parent, name)?;
        }
    }
    // Return success only if the named target root still denotes this inode.
    let again = root_directory(target_path)?;
    let current = again.metadata()?;
    ensure!(
        (current.dev(), current.ino()) == wanted,
        "target root path changed during mkdir"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let source = root.join("src");
        let target = root.join("dst");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        (tmp, source, target)
    }

    #[test]
    fn safely_makes_nested_and_empty_directories_and_is_idempotent() {
        let (_tmp, src, dst) = fixture();
        fs::create_dir_all(src.join("deep/other/empty")).unwrap();
        fs::create_dir(src.join("spare")).unwrap();
        fs::write(src.join("deep/other/file"), b"data").unwrap();
        let plan = JobPlan::build(&src, &dst).unwrap();
        create_planned_directories(&plan).unwrap();
        create_planned_directories(&plan).unwrap();
        assert!(dst.join("deep/other/empty").is_dir());
        assert!(dst.join("spare").is_dir());
        assert!(!dst.join("deep/other/file").exists());
    }

    #[test]
    fn symlinked_target_directory_refused_without_following() {
        let (_tmp, src, dst) = fixture();
        let outside = src.parent().unwrap().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::create_dir(src.join("sub")).unwrap();
        let plan = JobPlan::build(&src, &dst).unwrap();
        symlink(&outside, dst.join("sub")).unwrap();
        assert!(create_planned_directories(&plan).is_err());
        assert!(fs::read_dir(outside).unwrap().next().is_none());
    }

    #[test]
    fn replaced_target_root_inode_is_refused() {
        let (_tmp, src, dst) = fixture();
        fs::create_dir(src.join("sub")).unwrap();
        let plan = JobPlan::build(&src, &dst).unwrap();
        fs::rename(&dst, dst.with_extension("previous")).unwrap();
        fs::create_dir(&dst).unwrap();
        assert!(create_planned_directories(&plan).is_err());
        assert!(!dst.join("sub").exists());
    }

    #[test]
    fn existing_file_at_directory_name_fails_closed() {
        let (_tmp, src, dst) = fixture();
        fs::create_dir(src.join("sub")).unwrap();
        let plan = JobPlan::build(&src, &dst).unwrap();
        fs::write(dst.join("sub"), b"not a directory").unwrap();
        assert!(create_planned_directories(&plan).is_err());
        assert_eq!(fs::read(dst.join("sub")).unwrap(), b"not a directory");
    }
}
