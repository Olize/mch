// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fail-closed, opt-in, single-file Unix resume protocol v1.
// Windows is deliberately unsupported until secure staging/locking is reviewed.
use crate::Cli;
use anyhow::{Result, bail};
use filetime::FileTime;
use std::path::Path;

#[cfg(not(unix))]
pub(crate) fn copy(
    _cli: &Cli,
    _source: &Path,
    _destination: &Path,
    _source_times: Option<(FileTime, FileTime)>,
) -> Result<()> {
    bail!("--resume is not supported on this platform")
}

#[cfg(unix)]
pub(crate) use unix::copy;

#[cfg(unix)]
mod unix {
    use super::*;
    use anyhow::{Context, anyhow};
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::{Duration, Instant};

    const BLOCK: usize = 1024 * 1024;

    // Path bytes are length-delimited. Do not use lossily converted Unicode.
    fn staging_paths(source: &Path, destination: &Path) -> Result<(PathBuf, PathBuf, PathBuf)> {
        let canonical_source = fs::canonicalize(source)
            .with_context(|| format!("resolve source path {}", source.display()))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"MCH-resume-v1\0");
        for part in [canonical_source.as_os_str(), destination.as_os_str()] {
            let bytes = part.as_bytes();
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        let key = hasher.finalize().to_hex();
        let parent = destination.parent().context("destination has no parent")?;
        let base = format!(".mch-resume-v1-{key}");
        Ok((
            parent.join(format!("{base}.part")),
            parent.join(format!("{base}.lock")),
            parent.join(format!("{base}.meta")),
        ))
    }

    fn private_file(path: &Path) -> Result<File> {
        let mut opt = OpenOptions::new();
        opt.read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = match opt.create_new(true).open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => opt
                .create_new(false)
                .open(path)
                .with_context(|| format!("open secure resume file {}", path.display()))?,
            Err(err) => return Err(err).with_context(|| format!("create {}", path.display())),
        };
        let meta = file.metadata()?;
        if !meta.file_type().is_file()
            || meta.nlink() != 1
            || meta.uid() != unsafe { libc::geteuid() }
            || (meta.mode() & 0o077) != 0
        {
            bail!(
                "unsafe resume file: expected owned private regular inode with exactly one link: {}",
                path.display()
            );
        }
        Ok(file)
    }

    fn exclusive_lock(file: &File) -> Result<()> {
        // Keep the inode and its lockfile permanently: unlinking a lockfile
        // would allow a second process to create a fresh, unlocked inode.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == -1 {
            return Err(io::Error::last_os_error()).context(
                "another MCH --resume is active for this source/target (or locking unsupported)",
            );
        }
        Ok(())
    }

    fn inode_unchanged(file: &File, path: &Path) -> Result<()> {
        let fd = file.metadata()?;
        let name = fs::symlink_metadata(path)
            .with_context(|| format!("resume file disappeared: {}", path.display()))?;
        if !name.file_type().is_file()
            || fd.dev() != name.dev()
            || fd.ino() != name.ino()
            || fd.nlink() != 1
        {
            bail!(
                "resume staging path changed or is no longer safe: {}",
                path.display()
            );
        }
        Ok(())
    }

    // The manifest binds a partial copy to the original source inode, size and
    // modification time. A matching prefix alone cannot detect a changed tail.
    fn source_fingerprint(meta: &fs::Metadata) -> String {
        format!(
            "MCH-RESUME-1\n{}:{}:{}:{}:{}\n",
            meta.dev(),
            meta.ino(),
            meta.len(),
            meta.mtime(),
            meta.mtime_nsec(),
        )
    }

    fn validate_manifest(path: &Path, existed: bool, initial_source: &fs::Metadata) -> Result<()> {
        let mut file = private_file(path)?;
        let expected = source_fingerprint(initial_source);
        if existed {
            if file.metadata()?.len() > 256 {
                bail!("resume source metadata manifest is oversized; refusing");
            }
            let mut saved = String::new();
            file.read_to_string(&mut saved)
                .context("read saved resume source identity")?;
            if saved != expected {
                bail!(
                    "resume source identity, size or modification time changed since partial copy; refusing"
                );
            }
        } else {
            file.write_all(expected.as_bytes())
                .context("write persistent source identity for resume")?;
            file.sync_all().context("sync resume source identity")?;
        }
        Ok(())
    }

    // Recheck both the opened source inode and its current pathname.
    // This narrows the risk of deleting a newly replaced file on --move.
    // An adversarial replacement between this check and unlink is still
    // outside our race-safety guarantees.
    fn require_original_source(
        source: &Path,
        handle: &File,
        original: &fs::Metadata,
    ) -> Result<()> {
        let path = fs::symlink_metadata(source)
            .with_context(|| format!("source no longer accessible: {}", source.display()))?;
        let fd = handle.metadata().context("stat open original source")?;
        for meta in [&path, &fd] {
            if !meta.file_type().is_file()
                || meta.dev() != original.dev()
                || meta.ino() != original.ino()
                || meta.len() != original.len()
                || meta.mtime() != original.mtime()
                || meta.mtime_nsec() != original.mtime_nsec()
            {
                bail!(
                    "resume source changed since transfer began; refusing source deletion: {}",
                    source.display()
                );
            }
        }
        Ok(())
    }

    // Every staged byte is compared anew against CURRENT source content.
    fn verify_prefix(source: &mut File, stage: &mut File, bytes: u64) -> Result<()> {
        source.seek(SeekFrom::Start(0))?;
        stage.seek(SeekFrom::Start(0))?;
        let mut left = bytes;
        let mut source_buf = vec![0_u8; BLOCK];
        let mut stage_buf = vec![0_u8; BLOCK];
        while left > 0 {
            let n = left.min(BLOCK as u64) as usize;
            source
                .read_exact(&mut source_buf[..n])
                .context("read source during resume-prefix verification")?;
            stage
                .read_exact(&mut stage_buf[..n])
                .context("read staging during resume-prefix verification")?;
            if source_buf[..n] != stage_buf[..n] {
                bail!(
                    "resume prefix mismatch: partial copy differs from current source; refusing to overwrite"
                );
            }
            left -= n as u64;
        }
        Ok(())
    }

    fn show_transfer(copied: u64, reused: u64, total: u64, since: Instant, finished: bool) {
        let copied_total = copied.saturating_add(reused);
        let percent = if total == 0 {
            100.0
        } else {
            (copied_total as f64 * 100.0 / total as f64).min(100.0)
        };
        let seconds = since.elapsed().as_secs_f64().max(0.001);
        let rate = copied as f64 / seconds;
        let eta = if copied_total == total {
            String::from("0s")
        } else if rate > 0.0 {
            format!("{}s", ((total - copied_total) as f64 / rate).ceil() as u64)
        } else {
            String::from("unknown")
        };
        eprintln!(
            "RESUME {}: {percent:.1}% | {reused} B existing verified | {copied} B newly copied | {total} B total | {:.1} MiB/s new-data rate | copy ETA {eta}",
            if finished { "COPIED" } else { "COPYING" },
            rate / 1048576.0
        );
    }

    fn transfer(
        cli: &Cli,
        source: &mut File,
        stage: &mut File,
        reused: u64,
        total: u64,
    ) -> Result<()> {
        let bytes_written = AtomicU64::new(0);
        let began = Instant::now();
        std::thread::scope(|scope| -> Result<()> {
            let (done, receiver) = mpsc::channel::<()>();
            let tracker = &bytes_written;
            let reporter = if cli.show_progress() {
                Some(scope.spawn(move || {
                    loop {
                        match receiver.recv_timeout(Duration::from_secs(1)) {
                            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                                show_transfer(
                                    tracker.load(Ordering::Relaxed),
                                    reused,
                                    total,
                                    began,
                                    true,
                                );
                                break;
                            }
                            Err(RecvTimeoutError::Timeout) => {
                                show_transfer(
                                    tracker.load(Ordering::Relaxed),
                                    reused,
                                    total,
                                    began,
                                    false,
                                );
                            }
                        }
                    }
                }))
            } else {
                None
            };
            let result = (|| {
                source.seek(SeekFrom::Start(reused))?;
                stage.seek(SeekFrom::Start(reused))?;
                let mut buffer = vec![0_u8; BLOCK];
                let mut remaining = total - reused;
                while remaining != 0 {
                    let size = remaining.min(BLOCK as u64) as usize;
                    source
                        .read_exact(&mut buffer[..size])
                        .context("read source while resuming")?;
                    stage
                        .write_all(&buffer[..size])
                        .context("write persistent resume staging")?;
                    bytes_written.fetch_add(size as u64, Ordering::Relaxed);
                    remaining -= size as u64;
                }
                stage.flush().context("flush staged resume data")?;
                stage.sync_all().context("sync staged resume data")?;
                Ok(())
            })();
            let _ = done.send(());
            if let Some(reporter) = reporter {
                reporter
                    .join()
                    .map_err(|_| anyhow!("resume progress thread panicked"))?;
            }
            result
        })
    }

    pub(crate) fn copy(
        cli: &Cli,
        source: &Path,
        destination: &Path,
        source_times: Option<(FileTime, FileTime)>,
    ) -> Result<()> {
        let initial_meta = fs::symlink_metadata(source)
            .with_context(|| format!("stat source {}", source.display()))?;
        if !initial_meta.file_type().is_file() {
            bail!("--resume supports only regular non-symlink source files");
        }
        crate::engine::check_destination_file(source, destination, cli.overwrite)?;
        let parent = destination.parent().context("destination has no parent")?;
        // If resume is moving the only surviving original, reject a newly
        // created destination tree whose ancestor directory entries have not
        // yet been durably committed by the caller.
        if cli.move_mode && !parent.is_dir() {
            bail!(
                "--resume --move requires an existing destination parent directory: {}",
                parent.display()
            );
        }
        crate::engine::ensure_directory(parent)?;
        let (partial_path, lock_path, manifest_path) = staging_paths(source, destination)?;
        let lock = private_file(&lock_path)?;
        exclusive_lock(&lock)?;

        let partial_exists = fs::symlink_metadata(&partial_path).is_ok();
        let manifest_exists = fs::symlink_metadata(&manifest_path).is_ok();
        if partial_exists != manifest_exists {
            bail!(
                "incomplete resume staging/manifest pair: {} and {}. Refusing automatic repair; inspect both files before manually removing stale state",
                partial_path.display(),
                manifest_path.display()
            );
        }
        let mut stage = private_file(&partial_path)?;
        validate_manifest(&manifest_path, manifest_exists, &initial_meta)?;
        inode_unchanged(&stage, &partial_path)?;
        let reused = stage.metadata()?.len();
        if reused > initial_meta.len() {
            bail!(
                "resume staging is larger than source: {} > {} bytes",
                reused,
                initial_meta.len()
            );
        }
        let mut src = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(source)
            .with_context(|| {
                format!("open source without symlink following {}", source.display())
            })?;
        let opened_meta = src.metadata()?;
        if !opened_meta.is_file()
            || opened_meta.dev() != initial_meta.dev()
            || opened_meta.ino() != initial_meta.ino()
            || opened_meta.len() != initial_meta.len()
        {
            bail!("source changed after resume planning; refusing");
        }

        verify_prefix(&mut src, &mut stage, reused)?;
        if !cli.quiet {
            println!("RESUME: {reused} existing bytes compared and verified against source");
        }
        transfer(cli, &mut src, &mut stage, reused, initial_meta.len())?;
        if stage.metadata()?.len() != initial_meta.len() {
            bail!("staged file size changed during resume; refusing");
        }
        // The source may have changed during the transfer. Hash independently,
        // then ensure its metadata and inode still match the original handle.
        let src_digest = crate::hashing::hash_file(source, cli.hash)
            .context("hash entire source before publishing resumed copy")?;
        let stage_digest = crate::hashing::hash_file(&partial_path, cli.hash)
            .context("hash entire staged resumed copy")?;
        if src_digest != stage_digest {
            bail!("resume full-file {} verification FAILED", cli.hash.label());
        }
        require_original_source(source, &src, &initial_meta)
            .context("source changed while resuming; refusing to publish destination")?;
        inode_unchanged(&stage, &partial_path)?;
        if let Some((atime, mtime)) = source_times {
            filetime::set_file_times(&partial_path, atime, mtime)
                .context("apply source timestamps to verified resumed stage")?;
        }
        // NEVER broaden staging permissions before the publish rename.
        // If a process crashes after chmod and before rename, reopening a
        // 0644 stage would fail our strict owner-private resume checks.
        stage.sync_all().context("sync private staged metadata")?;
        crate::engine::check_destination_file(source, destination, cli.overwrite)?;
        inode_unchanged(&stage, &partial_path)?;
        crate::engine::atomic_replace(&partial_path, destination)
            .context("publish fully verified resumed copy")?;
        // The inode is now the FINAL destination, not a resumable .part.
        // Set permissions via the already-open handle, avoiding a pathname
        // race, then sync the final metadata before removing any source.
        stage
            .set_permissions(opened_meta.permissions())
            .context("apply source permissions to published resumed file")?;
        stage
            .sync_all()
            .context("sync final resumed file permissions")?;
        drop(stage);
        if cli.move_mode {
            // A synced *file* alone is not enough to durably record the rename.
            // Never remove the only source until the destination directory's
            // new entry is synced. This requires a filesystem that supports it.
            fs::File::open(parent)
                .with_context(|| {
                    format!("open destination directory for sync: {}", parent.display())
                })?
                .sync_all()
                .with_context(|| {
                    format!(
                        "sync resumed destination directory before source deletion: {}",
                        parent.display()
                    )
                })?;
            require_original_source(source, &src, &initial_meta)
                .context("source changed before resumed move cleanup")?;
        }
        fs::remove_file(&manifest_path)
            .context("remove resume manifest after publishing verified file")?;

        cli.report(
            &format!(
                "RESUME {} VERIFIED {} -> {}",
                cli.hash.label(),
                source.display(),
                destination.display()
            ),
            true,
        );
        if cli.show_progress() {
            eprintln!("RESUME HASH VERIFIED: {} complete", cli.hash.label());
        }
        if cli.move_mode {
            fs::remove_file(source)
                .with_context(|| format!("remove verified moved source {}", source.display()))?;
            cli.report(&format!("MOVED {}", source.display()), true);
        }
        if !cli.quiet {
            println!(
                "DONE: 1 resumed file{}",
                if cli.move_mode {
                    " (source removed after verification)"
                } else {
                    ""
                }
            );
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn derived_staging_paths_depend_on_source_and_target() {
            let t = tempfile::tempdir().unwrap();
            let a = t.path().join("a");
            let b = t.path().join("b");
            fs::write(&a, b"test").unwrap();
            fs::write(&b, b"test").unwrap();
            let (p1, l1, m1) = staging_paths(&a, &t.path().join("target")).unwrap();
            let (p2, _, _) = staging_paths(&b, &t.path().join("target")).unwrap();
            let (p3, _, _) = staging_paths(&a, &t.path().join("elsewhere")).unwrap();
            assert_ne!(p1, p2);
            assert_ne!(p1, p3);
            assert_ne!(p1, l1);
            assert_ne!(p1, m1);
            assert!(p1.file_name().unwrap().to_string_lossy().ends_with(".part"));
        }

        #[test]
        fn dangerous_symlink_staging_is_refused_without_modifying_target() {
            let t = tempfile::tempdir().unwrap();
            let src = t.path().join("source");
            fs::write(&src, b"source").unwrap();
            let stage = t.path().join("stage");
            std::os::unix::fs::symlink(&src, &stage).unwrap();
            assert!(private_file(&stage).is_err());
            assert_eq!(fs::read(&src).unwrap(), b"source");
        }

        #[test]
        fn replaced_source_file_is_rejected_even_with_same_size_and_mtime() {
            let t = tempfile::tempdir().unwrap();
            let source = t.path().join("original.bin");
            let previous = t.path().join("saved-original.bin");
            fs::write(&source, b"OLD!").unwrap();
            let initial = fs::symlink_metadata(&source).unwrap();
            let open_original = File::open(&source).unwrap();
            fs::rename(&source, &previous).unwrap();
            fs::write(&source, b"NEW!").unwrap();
            filetime::set_file_times(
                &source,
                FileTime::from_last_access_time(&initial),
                FileTime::from_last_modification_time(&initial),
            )
            .unwrap();
            let error = require_original_source(&source, &open_original, &initial)
                .expect_err("replaced original must never be deleted");
            assert!(error.to_string().contains("source changed"), "{error:#}");
            assert_eq!(fs::read(source).unwrap(), b"NEW!");
            assert_eq!(fs::read(previous).unwrap(), b"OLD!");
        }

        #[test]
        fn prefix_corruption_is_rejected_without_modification() {
            let t = tempfile::tempdir().unwrap();
            let a = t.path().join("source");
            let b = t.path().join("partial");
            fs::write(&a, b"abcdef").unwrap();
            fs::write(&b, b"abcDEF").unwrap();
            let mut src = File::open(&a).unwrap();
            let mut stage = File::open(&b).unwrap();
            assert!(verify_prefix(&mut src, &mut stage, 6).is_err());
            assert_eq!(fs::read(&b).unwrap(), b"abcDEF");
        }
    }
}
