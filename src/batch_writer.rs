// SPDX-License-Identifier: AGPL-3.0-or-later
//
// PRIVATE Unix-only directory-resume writer. All source/stage/manifest/lock/
// destination operations are relative to PINNED dirfds; only no-replace
// renameat2 / renameatx_np publishes a fully verified stage. This does not
// modify the publicly reviewed v0.2.1 single-file resume implementation.
// Power-cut and hostile same-UID concurrent-write guarantees remain unaudited.
use crate::batch_mkdir::sync_pinned_dir;
use crate::batch_plan::{JobPlan, PlannedFile, validate_relative};
use crate::batch_verify::{component_fd, root_directory};
use anyhow::{Context, Result, bail, ensure};
use std::ffi::{CStr, CString};
use std::fs::{File, Metadata};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const BLOCK: usize = 128 * 1024;
const MANIFEST_LIMIT: u64 = 256;

fn relative_parent(root: &File, relative: &[u8]) -> Result<(File, CString)> {
    validate_relative(relative)?;
    let mut parent = root.try_clone()?;
    let mut parts = relative.split(|byte| *byte == b'/').peekable();
    while let Some(component) = parts.next() {
        if parts.peek().is_none() {
            return Ok((parent, CString::new(component)?));
        }
        parent = component_fd(&parent, component, true)
            .context("open nested file parent from pinned root (NOFOLLOW)")?;
    }
    bail!("missing file leaf")
}

fn verified_root(path: &[u8], expected: (u64, u64)) -> Result<File> {
    let root = root_directory(path)?;
    let meta = root.metadata()?;
    ensure!(
        (meta.dev(), meta.ino()) == expected,
        "root directory identity changed"
    );
    Ok(root)
}

fn verify_parent_again(root: &File, relative: &[u8], expected: &File) -> Result<()> {
    let (parent, _) = relative_parent(root, relative)?;
    let opened = expected.metadata()?;
    let again = parent.metadata()?;
    ensure!(
        (opened.dev(), opened.ino()) == (again.dev(), again.ino()),
        "directory parent was replaced while writing"
    );
    Ok(())
}

fn planned_source_identity(meta: &Metadata, planned: &PlannedFile<'_>) -> Result<()> {
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.dev() == planned.device
            && meta.ino() == planned.inode
            && meta.len() == planned.size
            && meta.mtime() == planned.mtime_sec
            && meta.mtime_nsec() == planned.mtime_nsec,
        "source file identity or contents metadata differ from immutable plan"
    );
    Ok(())
}

fn stat_leaf(dir: &File, leaf: &CStr) -> Result<Option<libc::stat>> {
    let mut raw = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: dir fd and leaf CStr are valid; fstatat writes on success.
    let status = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            leaf.as_ptr(),
            raw.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status == 0 {
        Ok(Some(unsafe { raw.assume_init() }))
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error).context("fstatat leaf")
        }
    }
}

fn assert_inode_named(dir: &File, name: &CStr, file: &File) -> Result<()> {
    let current = stat_leaf(dir, name)?.context("expected file name vanished")?;
    let fd = file.metadata()?;
    ensure!(
        current.st_mode & libc::S_IFMT == libc::S_IFREG
            && current.st_nlink == 1
            && fd.nlink() == 1
            && current.st_dev as u64 == fd.dev()
            && current.st_ino as u64 == fd.ino(),
        "file name replaced or unexpectedly linked during batch resume"
    );
    Ok(())
}

fn private_open(dir: &File, name: &CStr, create_new: bool) -> Result<File> {
    let mut flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    if create_new {
        flags |= libc::O_CREAT | libc::O_EXCL;
    }
    // SAFETY: dir is pinned, name a single NUL-terminated component, and
    // mode is promoted to c_uint for openat's variadic mode argument.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, 0o600 as libc::c_uint) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("open private staged batch inode");
    }
    // SAFETY: openat returned a fresh uniquely owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o777 == 0o600,
        "unsafe private batch inode permissions, owner, link count or type"
    );
    assert_inode_named(dir, name, &file)?;
    Ok(file)
}

fn open_or_create(dir: &File, name: &CStr) -> Result<File> {
    match private_open(dir, name, true) {
        Ok(file) => {
            sync_pinned_dir(dir)?;
            Ok(file)
        }
        Err(error)
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == ErrorKind::AlreadyExists)
            }) =>
        {
            private_open(dir, name, false)
        }
        Err(error) => Err(error),
    }
}

fn lock_exclusive(lock: &File) -> Result<()> {
    // SAFETY: flock owns this fd until the end of copy().
    let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        return Err(io::Error::last_os_error()).context("concurrent batch file resume lock");
    }
    Ok(())
}

fn source_manifest(meta: &Metadata) -> String {
    // Identical to private v0.2.1 Unix --resume manifest format.
    format!(
        "MCH-RESUME-1\n{}:{}:{}:{}:{}\n",
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec()
    )
}

fn validate_manifest(manifest: &mut File, expected: &str, existed: bool) -> Result<()> {
    if existed {
        ensure!(
            manifest.metadata()?.len() <= MANIFEST_LIMIT,
            "oversized batch manifest"
        );
        let mut bytes = Vec::new();
        (&mut *manifest)
            .take(MANIFEST_LIMIT + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes == expected.as_bytes(),
            "persistent batch source identity changed"
        );
    } else {
        manifest.write_all(expected.as_bytes())?;
        manifest.sync_all()?;
    }
    Ok(())
}

fn stage_names(plan: &JobPlan, planned: &PlannedFile<'_>) -> Result<(CString, CString, CString)> {
    let (src_root, dst_root) = plan.roots();
    let mut full_src = src_root.to_vec();
    full_src.push(b'/');
    full_src.extend_from_slice(planned.relative);
    let mut full_dst = dst_root.to_vec();
    full_dst.push(b'/');
    full_dst.extend_from_slice(planned.relative);
    let mut h = blake3::Hasher::new();
    // Match the *existing* v1 single-file resume staged-state naming exactly.
    h.update(b"MCH-resume-v1\0");
    for part in [&full_src, &full_dst] {
        h.update(&(part.len() as u64).to_le_bytes());
        h.update(part);
    }
    let key = h.finalize().to_hex();
    let base = format!(".mch-resume-v1-{key}");
    Ok((
        CString::new(format!("{base}.part"))?,
        CString::new(format!("{base}.lock"))?,
        CString::new(format!("{base}.meta"))?,
    ))
}

fn verify_prefix(source: &mut File, stage: &mut File, len: u64) -> Result<()> {
    source.seek(SeekFrom::Start(0))?;
    stage.seek(SeekFrom::Start(0))?;
    let mut left = len;
    let mut from_source = [0u8; BLOCK];
    let mut from_stage = [0u8; BLOCK];
    while left > 0 {
        let count = left.min(BLOCK as u64) as usize;
        source.read_exact(&mut from_source[..count])?;
        stage.read_exact(&mut from_stage[..count])?;
        ensure!(
            from_source[..count] == from_stage[..count],
            "resume prefix differs from source; refusing damaged partial"
        );
        left -= count as u64;
    }
    Ok(())
}

fn transfer(source: &mut File, stage: &mut File, from: u64, size: u64) -> Result<()> {
    source.seek(SeekFrom::Start(from))?;
    stage.seek(SeekFrom::Start(from))?;
    let mut buffer = [0u8; BLOCK];
    let mut remaining = size - from;
    while remaining > 0 {
        let count = remaining.min(BLOCK as u64) as usize;
        source
            .read_exact(&mut buffer[..count])
            .context("read pinned planned source")?;
        stage
            .write_all(&buffer[..count])
            .context("write pinned staging inode")?;
        remaining -= count as u64;
    }
    stage.flush()?;
    stage.sync_all()?;
    Ok(())
}

fn hash_handle(file: &mut File) -> Result<[u8; 32]> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = blake3::Hasher::new();
    let mut buffer = [0u8; BLOCK];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(*digest.finalize().as_bytes())
}

fn verified_content_stamp(before: &Metadata, after: &Metadata) -> Result<()> {
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.nlink() == 1
            && after.nlink() == 1
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "source metadata changed during independent hash verification"
    );
    Ok(())
}

fn publish_no_replace(parent: &File, stage: &CStr, target: &CStr) -> Result<()> {
    // Do not fall back to unchecked rename; that could replace an existing
    // target created concurrently. Filesystems lacking no-replace fail closed.
    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    let result = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            stage.as_ptr(),
            parent.as_raw_fd(),
            target.as_ptr(),
            libc::RENAME_NOREPLACE as _,
        )
    };
    #[cfg(any(target_os = "android", all(target_os = "linux", target_env = "musl")))]
    let result = unsafe {
        // Android API 24 Bionic and Linux musl may lack libc renameat2.
        // Invoke the kernel syscall directly, with
        // identical atomic NOREPLACE flags. ENOSYS fails closed.
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            stage.as_ptr(),
            parent.as_raw_fd(),
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            stage.as_ptr(),
            parent.as_raw_fd(),
            target.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        let _ = (parent, stage, target);
        bail!("secure no-replace batch publication unsupported on this Unix");
    }
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    {
        if result != 0 {
            return Err(io::Error::last_os_error())
                .context("atomic NO-REPLACE batch stage publication");
        }
        Ok(())
    }
}

fn unlink_exact(dir: &File, name: &CStr, fd: &File) -> Result<()> {
    assert_inode_named(dir, name, fd)?;
    // SAFETY: name is an exact single component relative to an owned parent.
    let status = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
    if status != 0 {
        return Err(io::Error::last_os_error()).context("unlink verified manifest");
    }
    sync_pinned_dir(dir)
}

pub(crate) fn sync_target_parent(plan: &JobPlan, index: u64) -> Result<()> {
    let planned = plan.regular_entry(index)?;
    let (_, target_root_path) = plan.roots();
    let (_, root_identity) = plan.root_identities();
    let root = verified_root(
        target_root_path,
        root_identity.context("no planned target root identity")?,
    )?;
    let (parent, _) = relative_parent(&root, planned.relative)?;
    sync_pinned_dir(&parent)?;
    verify_parent_again(&root, planned.relative, &parent)?;
    Ok(())
}

// Finish an interrupted publication only after the caller has independently
// verified its current source and destination bytes. The leftover manifest
// proves this is a stage we created, not an arbitrary preexisting target.
// Never change metadata of an unrelated complete target.
pub(crate) fn finalize_recovered(plan: &JobPlan, index: u64) -> Result<bool> {
    let planned = plan.regular_entry(index)?;
    let (src_path, dst_path) = plan.roots();
    let (src_identity, dst_identity) = plan.root_identities();
    let src_root = verified_root(src_path, src_identity)?;
    let dst_root = verified_root(
        dst_path,
        dst_identity.context("missing target root identity")?,
    )?;
    let (src_parent, src_name) = relative_parent(&src_root, planned.relative)?;
    let (dst_parent, dst_name) = relative_parent(&dst_root, planned.relative)?;
    let (stage_name, lock_name, manifest_name) = stage_names(plan, &planned)?;
    if stat_leaf(&dst_parent, &manifest_name)?.is_none() {
        ensure!(
            stat_leaf(&dst_parent, &stage_name)?.is_none(),
            "both published target and orphan stage exist without manifest"
        );
        return Ok(false);
    }
    ensure!(
        stat_leaf(&dst_parent, &stage_name)?.is_none(),
        "both published target and staged inode exist: refusing ambiguous recovery"
    );
    ensure!(
        stat_leaf(&dst_parent, &lock_name)?.is_some(),
        "orphan manifest without persistent lock: refusing"
    );
    let lock = private_open(&dst_parent, &lock_name, false)?;
    lock_exclusive(&lock)?;
    let source = component_fd(&src_parent, src_name.to_bytes(), false)?;
    let src_meta = source.metadata()?;
    planned_source_identity(&src_meta, &planned)?;
    let mut manifest = private_open(&dst_parent, &manifest_name, false)?;
    validate_manifest(&mut manifest, &source_manifest(&src_meta), true)?;
    let target = component_fd(&dst_parent, dst_name.to_bytes(), false)?;
    let target_meta = target.metadata()?;
    ensure!(
        target_meta.uid() == unsafe { libc::geteuid() } && target_meta.nlink() == 1,
        "cannot recover metadata of unowned or linked target"
    );
    // The caller must rehash both files before this call and again after it.
    assert_inode_named(&dst_parent, &dst_name, &target)?;
    target.set_permissions(std::fs::Permissions::from_mode(src_meta.mode() & 0o7777))?;
    target.sync_all()?;
    sync_pinned_dir(&dst_parent)?;
    assert_inode_named(&dst_parent, &dst_name, &target)?;
    unlink_exact(&dst_parent, &manifest_name, &manifest)?;
    verify_parent_again(&dst_root, planned.relative, &dst_parent)?;
    verify_parent_again(&src_root, planned.relative, &src_parent)?;
    Ok(true)
}

pub(crate) fn destination_exists(plan: &JobPlan, index: u64) -> Result<bool> {
    let planned = plan.regular_entry(index)?;
    let (_, target_root_path) = plan.roots();
    let (_, target_inode) = plan.root_identities();
    let target = verified_root(
        target_root_path,
        target_inode.context("target root has no planned inode")?,
    )?;
    let (parent, name) = relative_parent(&target, planned.relative)?;
    Ok(stat_leaf(&parent, &name)?.is_some())
}

pub(crate) fn copy(plan: &JobPlan, index: u64) -> Result<[u8; 32]> {
    let planned = plan.regular_entry(index)?;
    let (source_root_path, target_root_path) = plan.roots();
    let (source_identity, target_identity) = plan.root_identities();
    let source_root = verified_root(source_root_path, source_identity)?;
    let target_root = verified_root(
        target_root_path,
        target_identity.context("target root has no planned inode")?,
    )?;
    let (source_parent, source_name) = relative_parent(&source_root, planned.relative)?;
    let (destination_parent, destination_name) = relative_parent(&target_root, planned.relative)?;

    // Check every nested SOURCE ancestor against the immutable plan.
    let mut prefix = Vec::<u8>::new();
    let mut src_dir = source_root.try_clone()?;
    let mut components = planned.relative.split(|byte| *byte == b'/').peekable();
    while let Some(name) = components.next() {
        if components.peek().is_none() {
            break;
        }
        if !prefix.is_empty() {
            prefix.push(b'/');
        }
        prefix.extend_from_slice(name);
        src_dir = component_fd(&src_dir, name, true)?;
        let (dev, ino) = plan.planned_directory_inode(&prefix)?;
        let meta = src_dir.metadata()?;
        ensure!(
            (meta.dev(), meta.ino()) == (dev, ino),
            "planned source ancestor replaced"
        );
    }

    // Detect existing target without following any symlink. A concurrent
    // creation is also blocked atomically at renameat2/renameatx_np.
    ensure!(
        stat_leaf(&destination_parent, &destination_name)?.is_none(),
        "target already exists; use full independent resume verification"
    );

    let mut source = component_fd(&source_parent, source_name.to_bytes(), false)?;
    let initial = source.metadata()?;
    planned_source_identity(&initial, &planned)?;
    let (stage_name, lock_name, manifest_name) = stage_names(plan, &planned)?;
    let lock = open_or_create(&destination_parent, &lock_name)?;
    lock_exclusive(&lock)?;
    assert_inode_named(&destination_parent, &lock_name, &lock)?;

    let partial_exists = stat_leaf(&destination_parent, &stage_name)?.is_some();
    let manifest_exists = stat_leaf(&destination_parent, &manifest_name)?.is_some();
    ensure!(
        partial_exists == manifest_exists,
        "incomplete stage/manifest pair; refusing automatic repair"
    );

    let mut stage = if partial_exists {
        private_open(&destination_parent, &stage_name, false)?
    } else {
        private_open(&destination_parent, &stage_name, true)?
    };
    if !partial_exists {
        sync_pinned_dir(&destination_parent)?;
    }
    crate::batch_fault::kill_if("stage_initialized");
    let mut manifest = if manifest_exists {
        private_open(&destination_parent, &manifest_name, false)?
    } else {
        private_open(&destination_parent, &manifest_name, true)?
    };
    if !manifest_exists {
        sync_pinned_dir(&destination_parent)?;
    }
    crate::batch_fault::kill_if("manifest_initialized");
    validate_manifest(&mut manifest, &source_manifest(&initial), manifest_exists)?;
    crate::batch_fault::kill_if("manifest_synced");
    assert_inode_named(&destination_parent, &manifest_name, &manifest)?;
    let reused = stage.metadata()?.len();
    ensure!(
        reused <= planned.size,
        "stage is larger than planned source"
    );
    verify_prefix(&mut source, &mut stage, reused)?;
    transfer(&mut source, &mut stage, reused, planned.size)?;
    crate::batch_fault::kill_if("stage_data_synced");
    ensure!(
        stage.metadata()?.len() == planned.size,
        "staged size changed during copy"
    );
    assert_inode_named(&destination_parent, &stage_name, &stage)?;
    let after_transfer = source.metadata()?;
    verified_content_stamp(&initial, &after_transfer)?;

    let source_hash = hash_handle(&mut source)?;
    let stage_hash = hash_handle(&mut stage)?;
    ensure!(
        source_hash == stage_hash,
        "source/stage full BLAKE3 hashes differ"
    );
    verified_content_stamp(&initial, &source.metadata()?)?;
    planned_source_identity(&source.metadata()?, &planned)?;
    // The source pathname must STILL name the same planned inode.
    let now_source = component_fd(&source_parent, source_name.to_bytes(), false)?;
    let now_meta = now_source.metadata()?;
    ensure!(
        now_meta.dev() == initial.dev() && now_meta.ino() == initial.ino(),
        "planned source pathname was replaced during copy"
    );
    verify_parent_again(&source_root, planned.relative, &source_parent)?;
    verify_parent_again(&target_root, planned.relative, &destination_parent)?;
    let named_source = verified_root(source_root_path, source_identity)?;
    ensure!(
        (
            named_source.metadata()?.dev(),
            named_source.metadata()?.ino()
        ) == (source_root.metadata()?.dev(), source_root.metadata()?.ino()),
        "source root path replaced before publication"
    );
    let current_root = verified_root(target_root_path, target_identity.unwrap())?;
    ensure!(
        current_root.metadata()?.ino() == target_root.metadata()?.ino(),
        "target root changed before publication"
    );

    assert_inode_named(&destination_parent, &lock_name, &lock)?;
    assert_inode_named(&destination_parent, &manifest_name, &manifest)?;
    assert_inode_named(&destination_parent, &stage_name, &stage)?;
    ensure!(
        stat_leaf(&destination_parent, &destination_name)?.is_none(),
        "destination appeared before no-replace publication"
    );
    stage.sync_all()?;
    sync_pinned_dir(&destination_parent)?;
    crate::batch_fault::kill_if("before_publish");

    publish_no_replace(&destination_parent, &stage_name, &destination_name)?;
    crate::batch_fault::kill_if("after_publish");
    // The stage inode is now the destination; no alias remains on rename.
    let published = component_fd(&destination_parent, destination_name.to_bytes(), false)?;
    let published_meta = published.metadata()?;
    ensure!(
        published_meta.dev() == stage.metadata()?.dev()
            && published_meta.ino() == stage.metadata()?.ino(),
        "published target inode differs from verified stage"
    );
    stage.set_permissions(std::fs::Permissions::from_mode(initial.mode() & 0o7777))?;
    stage.sync_all()?;
    sync_pinned_dir(&destination_parent)?;
    crate::batch_fault::kill_if("published_metadata_synced");
    unlink_exact(&destination_parent, &manifest_name, &manifest)?;
    crate::batch_fault::kill_if("manifest_removed");
    verify_parent_again(&target_root, planned.relative, &destination_parent)?;
    let final_root = verified_root(target_root_path, target_identity.unwrap())?;
    ensure!(
        final_root.metadata()?.ino() == target_root.metadata()?.ino(),
        "target root changed after publication"
    );
    Ok(source_hash)
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
        let source = root.join("source");
        let target = root.join("target");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        fs::create_dir(source.join("inner")).unwrap();
        fs::write(source.join("inner/file"), b"checked bytes").unwrap();
        let plan = JobPlan::build(&source, &target).unwrap();
        crate::batch_mkdir::create_planned_directories(&plan).unwrap();
        (temp, source, target, plan)
    }

    #[test]
    fn writes_then_verifies_new_target_without_any_legacy_path_writer() {
        let (_tmp, src, dst, plan) = fixture();
        let bytes = copy(&plan, 0).unwrap();
        assert_eq!(bytes, *blake3::hash(b"checked bytes").as_bytes());
        assert_eq!(fs::read(dst.join("inner/file")).unwrap(), b"checked bytes");
        assert!(destination_exists(&plan, 0).unwrap());
        assert_eq!(
            crate::batch_verify::verify_completed(&plan, 0, Some(&bytes)).unwrap(),
            bytes
        );
        assert!(copy(&plan, 0).is_err());
        assert_eq!(fs::read(src.join("inner/file")).unwrap(), b"checked bytes");
    }

    #[test]
    fn atomic_no_replace_does_not_modify_an_existing_target() {
        let (_tmp, _src, dst, _plan) = fixture();
        let parent = root_directory(dst.join("inner").as_os_str().as_encoded_bytes()).unwrap();
        let mut partial = private_open(&parent, c"source.part", true).unwrap();
        partial.write_all(b"new").unwrap();
        partial.sync_all().unwrap();
        fs::write(dst.join("inner/file"), b"valuable existing data").unwrap();
        assert!(publish_no_replace(&parent, c"source.part", c"file").is_err());
        assert_eq!(
            fs::read(dst.join("inner/file")).unwrap(),
            b"valuable existing data"
        );
        assert_eq!(fs::read(dst.join("inner/source.part")).unwrap(), b"new");
    }

    #[test]
    fn symlinked_target_parent_is_never_followed_by_writer() {
        let (_tmp, _src, dst, plan) = fixture();
        let outside = dst.parent().unwrap().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("file"), b"untouchable").unwrap();
        fs::remove_dir(dst.join("inner")).unwrap();
        symlink(&outside, dst.join("inner")).unwrap();
        assert!(copy(&plan, 0).is_err());
        assert_eq!(fs::read(outside.join("file")).unwrap(), b"untouchable");
    }

    #[test]
    fn replaced_source_inode_fails_before_creating_stage_files() {
        let (_tmp, src, dst, plan) = fixture();
        fs::rename(src.join("inner/file"), src.join("inner/old")).unwrap();
        fs::write(src.join("inner/file"), b"checked bytes").unwrap();
        assert!(copy(&plan, 0).is_err());
        let count = fs::read_dir(dst.join("inner")).unwrap().count();
        assert_eq!(
            count, 0,
            "source replacement must not create lock/part/manifest"
        );
    }

    #[test]
    fn corrupt_stage_prefix_refused_and_both_inputs_preserved() {
        let (_tmp, src, dst, plan) = fixture();
        let planned = plan.regular_entry(0).unwrap();
        let (part_name, _lock, meta_name) = stage_names(&plan, &planned).unwrap();
        let parent = root_directory(dst.join("inner").as_os_str().as_encoded_bytes()).unwrap();
        let mut partial = private_open(&parent, &part_name, true).unwrap();
        partial.write_all(b"CORRUPT").unwrap();
        partial.sync_all().unwrap();
        let manifest = private_open(&parent, &meta_name, true).unwrap();
        let source_meta = fs::metadata(src.join("inner/file")).unwrap();
        fs::write(
            dst.join("inner").join(meta_name.to_str().unwrap()),
            source_manifest(&source_meta),
        )
        .unwrap();
        manifest.sync_all().unwrap();
        assert!(copy(&plan, 0).is_err());
        assert_eq!(
            fs::read(dst.join("inner").join(part_name.to_str().unwrap())).unwrap(),
            b"CORRUPT"
        );
        assert_eq!(fs::read(src.join("inner/file")).unwrap(), b"checked bytes");
        assert!(!dst.join("inner/file").exists());
    }
}
