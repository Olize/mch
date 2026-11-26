// SPDX-License-Identifier: AGPL-3.0-or-later
// Local Linux filesystems. A single exclusive rename commits the whole tree.
use anyhow::{Context, Result, ensure};
use std::{
    collections::{HashMap, HashSet},
    ffi::{CString, OsStr},
    fs::{self, File, Metadata, OpenOptions},
    io::ErrorKind,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
    process::Command,
};

fn meta(path: &Path) -> Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn dir(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?)
}
fn identity(m: &Metadata) -> (u64, u64) {
    (m.dev(), m.ino())
}

fn rename_tree(from: &File, name: &OsStr, to: &File, target: &OsStr, exchange: bool) -> Result<()> {
    let name = CString::new(name.as_bytes())?;
    let target = CString::new(target.as_bytes())?;
    // Both names are single components below pinned directories. Exchange is used only for an explicit replacement with a retained previous tree.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            from.as_raw_fd(),
            name.as_ptr(),
            to.as_raw_fd(),
            target.as_ptr(),
            if exchange {
                libc::RENAME_EXCHANGE
            } else {
                libc::RENAME_NOREPLACE
            },
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("atomic transaction rename");
    }
    if exchange {
        crate::batch_fault::kill_if("transaction_exchanged_unsynced");
    }
    to.sync_all()?;
    from.sync_all()?;
    Ok(())
}

fn read_record(path: &Path) -> Result<Vec<u8>> {
    // The entire short record is the payload of one atomic symlink creation.
    // Never follow journal links. A crash cannot leave a partially written ID.
    Ok(fs::read_link(path)?.as_os_str().as_bytes().to_vec())
}

fn record(folder: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let path = folder.join(name);
    match std::os::unix::fs::symlink(OsStr::from_bytes(bytes), &path) {
        Ok(()) => (),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            ensure!(
                read_record(&path)? == bytes,
                "transaction record conflicts: {name}"
            );
        }
        Err(e) => return Err(e.into()),
    }
    dir(folder)?.sync_all()?;
    Ok(())
}

fn paths(root: &Path, excluded: &[(u64, u64)]) -> Result<HashSet<PathBuf>> {
    let mut result = HashSet::new();
    let mut directory_ids = HashSet::new();
    let mut keys = HashSet::new();
    let mut todo = vec![PathBuf::new()];
    let device = fs::metadata(root)?.dev();
    let mount = crate::linux_tree::mount_id(root)?;
    while let Some(relative) = todo.pop() {
        let path = root.join(&relative);
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.dev() == device && crate::linux_tree::mount_id(&path)? == mount,
            "nested filesystem at {}",
            path.display()
        );
        ensure!(
            keys.insert(crate::engine::folded_destination_key(&relative)),
            "ambiguous filename: {}",
            relative.display()
        );
        if m.is_dir() {
            ensure!(
                !excluded.contains(&identity(&m)) && directory_ids.insert(identity(&m)),
                "overlapping directory identity at {}",
                path.display()
            );
            for item in fs::read_dir(path)? {
                todo.push(relative.join(item?.file_name()));
            }
        } else {
            ensure!(
                m.is_file() || m.is_symlink(),
                "unsupported file type: {}",
                path.display()
            );
        }
        result.insert(relative);
    }
    Ok(result)
}

fn rsync(src: &Path, dst: &Path, check: bool) -> Result<()> {
    let mut cmd = Command::new("rsync");
    cmd.args([
        "-aHAXS",
        "--numeric-ids",
        "--modify-window=-1",
        "--checksum",
        "--no-devices",
        "--no-specials",
    ]);
    if check {
        cmd.args(["--dry-run", "--itemize-changes", "--delete"]);
    } else {
        cmd.args(["--fsync", "--partial", "--no-whole-file"]);
    }
    let output = cmd
        .arg("--")
        .arg(src.join(""))
        .arg(dst.join(""))
        .output()
        .context("start rsync with ACL/xattr support")?;
    ensure!(
        output.status.success(),
        "rsync: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if check {
        ensure!(
            output.stdout.is_empty(),
            "metadata or tree differs: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    Ok(())
}

fn verified_read(
    root: &File,
    relative: &Path,
    expected: &Metadata,
    sync: bool,
) -> Result<blake3::Hash> {
    let name = CString::new(relative.as_os_str().as_bytes())?;
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW) as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_XDEV;
    // openat2 resolves the entire name under the pinned root on Linux 5.6+.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of_val(&how),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open file beneath verified tree");
    }
    let mut f = unsafe { File::from_raw_fd(fd as i32) };
    let stamp = |m: &Metadata| (identity(m), m.mode(), m.len(), m.ctime(), m.ctime_nsec());
    ensure!(
        expected.is_file() && stamp(&f.metadata()?) == stamp(expected),
        "file changed before hashing"
    );
    let mut h = blake3::Hasher::new();
    h.update_reader(&mut f)?;
    ensure!(
        stamp(&f.metadata()?) == stamp(expected),
        "file changed during hashing"
    );
    if sync {
        f.sync_all()?;
    }
    Ok(h.finalize())
}

fn verify(src: &Path, dst: &Path, sync: bool) -> Result<()> {
    let source_fd = dir(src)?;
    let target_fd = dir(dst)?;
    let names = paths(src, &[])?;
    ensure!(
        names == paths(dst, &[])?,
        "source and target entries differ"
    );
    let mut forward = HashMap::new();
    let mut reverse = HashMap::new();
    let mut directories = vec![];
    for name in names {
        let (a, b) = (src.join(&name), dst.join(&name));
        let (s, t) = (fs::symlink_metadata(&a)?, fs::symlink_metadata(&b)?);
        ensure!(
            s.mode() == t.mode() && s.uid() == t.uid() && s.gid() == t.gid(),
            "type, mode or ownership differs: {}",
            name.display()
        );
        if s.is_file() {
            let (id, other) = (identity(&s), identity(&t));
            ensure!(
                *forward.entry(id).or_insert(other) == other
                    && *reverse.entry(other).or_insert(id) == id,
                "hardlink topology differs: {}",
                name.display()
            );
            ensure!(
                s.len() == t.len()
                    && verified_read(&source_fd, &name, &s, false)?
                        == verified_read(&target_fd, &name, &t, sync)?,
                "content differs: {}",
                name.display()
            );
        } else if s.is_symlink() {
            ensure!(
                fs::read_link(&a)? == fs::read_link(&b)?,
                "link differs: {}",
                name.display()
            );
        } else if sync {
            directories.push(b);
        }
    }
    rsync(src, dst, true)?;
    directories.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for path in directories {
        dir(&path)?.sync_all()?;
    }
    Ok(())
}

fn inode_marker(m: &Metadata) -> String {
    format!("{} {}", m.dev(), m.ino())
}

fn durable_marker(m: &Metadata) -> Result<String> {
    ensure!(m.is_dir(), "expected a directory");
    let born = m
        .created()
        .context("filesystem does not provide directory birth times")?
        .duration_since(std::time::UNIX_EPOCH)?;
    Ok(format!(
        "{} {} {}",
        inode_marker(m),
        born.as_secs(),
        born.subsec_nanos()
    ))
}

fn matches_marker(path: &Path, marker: &[u8]) -> Result<bool> {
    match meta(path)? {
        Some(m) if m.is_dir() => Ok(durable_marker(&m)?.as_bytes() == marker),
        _ => Ok(false),
    }
}

fn require_prior(path: &Path, prior: Option<&[u8]>) -> Result<()> {
    let matches = match prior {
        Some(marker) => matches_marker(path, marker)?,
        None => meta(path)?.is_none(),
    };
    ensure!(
        matches,
        "destination differs from its initial transaction state: {}",
        path.display()
    );
    Ok(())
}

fn withdraw(state: &Path, lock: &File) -> Result<()> {
    if meta(&state.join("tree"))?.is_some() {
        rename_tree(
            lock,
            OsStr::new("tree"),
            lock,
            OsStr::new("withdrawn"),
            false,
        )?;
    } else {
        record(state, "withdrawn", b"empty")?;
    }
    Ok(())
}

pub(crate) fn run(
    input: &Path,
    output: &Path,
    state: &Path,
    rollback: bool,
    exchange: bool,
) -> Result<()> {
    ensure!(
        fs::symlink_metadata(state)?.is_dir(),
        "state must be a real directory"
    );
    let src = if rollback {
        crate::engine::intended_path(input)?
    } else {
        ensure!(
            fs::symlink_metadata(input)?.is_dir(),
            "source must be a real directory"
        );
        fs::canonicalize(input)?
    };
    let state = fs::canonicalize(state)?;
    let output = std::path::absolute(output)?;
    let name = output
        .file_name()
        .context("invalid transaction destination")?;
    let parent = fs::canonicalize(output.parent().context("missing destination parent")?)?;
    let dst = parent.join(name);
    let parent_fd = dir(&parent)?;
    let lock = dir(&state)?;
    let sm = lock.metadata()?;
    ensure!(
        sm.uid() == unsafe { libc::geteuid() } && sm.mode() & 0o7777 == 0o700,
        "state must be owned and mode 0700"
    );
    ensure!(
        sm.dev() == parent_fd.metadata()?.dev(),
        "state and destination must be on the same filesystem"
    );
    for (a, b) in [(&src, &dst), (&src, &state), (&state, &dst)] {
        ensure!(
            !a.starts_with(b) && !b.starts_with(a),
            "overlapping transaction trees"
        );
    }
    lock.try_lock().context("transaction already running")?;
    // A different job can use a separate state directory for the same destination.
    // Hold its parent while deciding which tree to restore and doing the rename.
    if rollback {
        parent_fd
            .try_lock()
            .context("another transaction is updating the destination parent; retry")?;
    }
    let stage = state.join("tree");
    let prepared = state.join("prepared");
    let prior_path = state.join("previous.v1");
    let mut binding = blake3::Hasher::new();
    for path in [&src, &dst, &state] {
        binding.update(path.as_os_str().as_bytes());
        binding.update(&[0]);
    }
    if exchange {
        binding.update(b"exchange-v1\0");
    }
    let mut path_binding = binding.clone();
    for m in [parent_fd.metadata()?, lock.metadata()?] {
        path_binding.update(&m.dev().to_le_bytes());
        path_binding.update(&m.ino().to_le_bytes());
    }
    let recovery_key = path_binding.finalize().to_hex();
    let journal = state.join("job.v1");
    let recovery = state.join("recovery.v1");
    if rollback && meta(&recovery)?.is_some() {
        ensure!(
            read_record(&recovery)? == recovery_key.as_bytes() && meta(&journal)?.is_some(),
            "rollback belongs to another job"
        );
    } else {
        if meta(&journal)?.is_none() {
            ensure!(
                !rollback && fs::read_dir(&state)?.next().is_none(),
                "new transaction requires empty state"
            );
            if exchange {
                ensure!(
                    meta(&dst)?.is_some_and(|m| m.is_dir()),
                    "tree exchange requires an existing directory"
                );
                paths(&dst, &[identity(&fs::metadata(&src)?), identity(&sm)])?;
            } else {
                require_prior(&dst, None)?;
            }
        }
        for m in [fs::metadata(&src)?, parent_fd.metadata()?, sm] {
            binding.update(&m.dev().to_le_bytes());
            binding.update(&m.ino().to_le_bytes());
        }
        record(&state, "job.v1", binding.finalize().to_hex().as_bytes())?;
        record(&state, "recovery.v1", recovery_key.as_bytes())?;
    }
    let previous = if exchange {
        if meta(&prior_path)?.is_none() {
            ensure!(
                meta(&stage)?.is_none() && meta(&prepared)?.is_none(),
                "missing previous-tree journal"
            );
            let old = fs::symlink_metadata(&dst)?;
            record(&state, "previous.v1", durable_marker(&old)?.as_bytes())?;
        }
        Some(read_record(&prior_path)?)
    } else {
        None
    };
    let prior = previous.as_deref();
    if meta(&state.join("withdrawn"))?.is_some() {
        ensure!(rollback, "transaction already withdrawn");
        require_prior(&dst, prior)?;
        lock.sync_all()?;
        parent_fd.sync_all()?;
        return Ok(());
    }

    let prepared_id = meta(&prepared)?
        .map(|_| read_record(&prepared))
        .transpose()?;
    let published = match (meta(&dst)?, prepared_id.as_deref()) {
        (Some(m), Some(id)) => m.is_dir() && inode_marker(&m).as_bytes() == id,
        _ => false,
    };
    let restore = state.join("rollback.v1");
    if meta(&restore)?.is_some() {
        ensure!(
            rollback && read_record(&restore)? == recovery_key.as_bytes(),
            "continue this job with --rollback"
        );
    }
    if published {
        require_prior(&stage, prior)?;
        if meta(&state.join("prepared.birth"))?.is_some() {
            ensure!(
                matches_marker(&dst, &read_record(&state.join("prepared.birth"))?)?,
                "published directory identity changed"
            );
        } else {
            // A dev.3 job predates birth-time receipts. Keep its original validation contract.
            verify(&src, &dst, false)?;
        }
        if rollback {
            record(&state, "rollback.v1", recovery_key.as_bytes())?;
            if exchange {
                rename_tree(&lock, OsStr::new("tree"), &parent_fd, name, true)?;
                crate::batch_fault::kill_if("transaction_restored");
                require_prior(&dst, prior)?;
                withdraw(&state, &lock)?;
            } else {
                rename_tree(&parent_fd, name, &lock, OsStr::new("withdrawn"), false)?;
            }
        } else {
            verify(&src, &dst, false)?;
        }
        parent_fd.sync_all()?;
        lock.sync_all()?;
        return Ok(());
    }
    require_prior(&dst, prior)?;
    if rollback {
        record(&state, "rollback.v1", recovery_key.as_bytes())?;
        return withdraw(&state, &lock);
    }
    let mut excluded = vec![
        identity(&parent_fd.metadata()?),
        identity(&lock.metadata()?),
    ];
    if exchange {
        excluded.push(identity(&fs::symlink_metadata(&dst)?));
    }
    paths(&src, &excluded)?;
    if meta(&stage)?.is_none() {
        ensure!(prepared_id.is_none(), "prepared tree is missing");
        fs::create_dir(&stage)?;
        lock.sync_all()?;
    }
    let stage_fd = dir(&stage)?;
    let entry = stage_fd.metadata()?;
    let marker = inode_marker(&entry);
    if let Some(id) = prepared_id {
        ensure!(id == marker.as_bytes(), "prepared tree identity changed");
    } else {
        rsync(&src, &stage, false)?;
    }
    crate::batch_fault::kill_if("transaction_staged");
    verify(&src, &stage, true)?;
    ensure!(
        identity(&fs::symlink_metadata(&stage)?) == identity(&entry)
            && identity(&fs::metadata(&parent)?) == identity(&parent_fd.metadata()?)
            && identity(&fs::metadata(&state)?) == identity(&lock.metadata()?),
        "tree or roots changed before publication"
    );
    record(&state, "prepared.birth", durable_marker(&entry)?.as_bytes())?;
    record(&state, "prepared", marker.as_bytes())?;
    crate::batch_fault::kill_if("transaction_prepared");
    // Staging and hashing can overlap for sibling jobs. Serialize the final
    // prior-identity check and rename with other MCH publications and rollbacks.
    parent_fd
        .try_lock()
        .context("another transaction is updating the destination parent; retry")?;
    require_prior(&dst, prior)?;
    rename_tree(&lock, OsStr::new("tree"), &parent_fd, name, exchange)?;
    crate::batch_fault::kill_if("transaction_committed");
    require_prior(&stage, prior)?;
    ensure!(
        matches_marker(&dst, &read_record(&state.join("prepared.birth"))?)?,
        "published directory identity changed"
    );
    Ok(())
}
