// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Private experimental Unix persisted job-plan/journal state.
// Used only by the unmerged --resume-dir pilot, NOT by public v0.2.1.
// The caller must supply a private 0700 directory. No directory is auto-created.
// State directory ancestors now open via pinned NOFOLLOW dirfds;
// power-loss and hostile same-user modification remain unproven.
use crate::batch_plan::JobPlan;
use anyhow::{Context, Result, ensure};
use std::cell::RefCell;
use std::fs::{File, Metadata};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;
const PLAN_NAME: &std::ffi::CStr = c"plan.v1";
const JOURNAL_NAME: &std::ffi::CStr = c"journal.v1";
const LOCK_NAME: &std::ffi::CStr = c"lock.v1";

pub(crate) struct LockedStore {
    directory: File,
    _lock: File,
    // Fully checked once under flock. Subsequent appends validate inode stamps.
    cached: RefCell<Option<JournalSession>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    ino: u64,
    len: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

impl FileStamp {
    fn read(file: &File) -> Result<Self> {
        let meta: Metadata = file.metadata()?;
        secure_fd(file, true)?;
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            mtime_sec: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        })
    }
}

struct JournalSession {
    plan: File,
    journal: File,
    plan_stamp: FileStamp,
    journal_stamp: FileStamp,
    fingerprint: [u8; 32],
    planned_files: u64,
    // The validated JobPlan is borrowed immutably for this runtime session.
    // Avoid recalculating its O(tree size) fingerprint on every append.
    plan_address: usize,
    last: Option<u64>,
    commitment: [u8; 32],
}

// Ephemeral incremental commitment to every journal event verified during
// this run. Rebuilt from the persisted checksummed V1 journal on restart.
fn extend_commitment(previous: [u8; 32], item: &crate::batch_journal::VerifiedEvent) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"MCH-BATCH-RUNTIME-COMMITMENT-V1");
    digest.update(&previous);
    digest.update(&item.file_index.to_le_bytes());
    digest.update(&item.full_file_digest);
    *digest.finalize().as_bytes()
}

fn secure_fd(file: &File, regular: bool) -> Result<()> {
    let meta = file.metadata()?;
    let owner = unsafe { libc::geteuid() };
    ensure!(
        meta.uid() == owner,
        "state inode is not owned by current user"
    );
    ensure!(
        meta.mode() & 0o777 == if regular { 0o600 } else { 0o700 },
        "state inode has unsafe mode"
    );
    if regular {
        ensure!(meta.is_file(), "state entry is not a regular file");
        ensure!(meta.nlink() == 1, "state entry is hardlinked");
    } else {
        ensure!(meta.is_dir(), "state directory is not a directory");
    }
    Ok(())
}

fn open_relative(directory: &File, name: &std::ffi::CStr, flags: i32) -> Result<File> {
    // SAFETY: directory is an owned, open directory descriptor; name is static and
    // NUL-terminated with no slash. The returned raw descriptor is uniquely owned.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("open state {name:?}"));
    }
    // SAFETY: openat succeeded and returned a fresh owned fd.
    let file = unsafe { File::from_raw_fd(fd) };
    if let Err(err) = secure_fd(&file, true) {
        drop(file);
        return Err(err).with_context(|| format!("validate state {name:?}"));
    }
    assert_named_file(directory, name, &file)?;
    Ok(file)
}

// Fail closed if a state file was replaced after the file descriptor opened.
fn assert_named_file(dir: &File, name: &std::ffi::CStr, file: &File) -> Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: dir and name are valid and fstatat populates stat on success.
    let result = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("state filename disappeared");
    }
    let stat = unsafe { stat.assume_init() };
    let meta = file.metadata()?;
    #[allow(clippy::unnecessary_cast)]
    let unchanged = stat.st_mode & libc::S_IFMT == libc::S_IFREG
        && stat.st_nlink == 1
        && stat.st_dev as u64 == meta.dev()
        && stat.st_ino as u64 == meta.ino();
    ensure!(unchanged, "state inode replaced while active");
    Ok(())
}

fn read_checked(file: File) -> Result<Vec<u8>> {
    let len = file.metadata()?.len();
    ensure!(len <= MAX_STATE_BYTES, "state file too large");
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_STATE_BYTES,
        "state size changed while reading"
    );
    Ok(bytes)
}

impl LockedStore {
    // Exactly one of (new plan+new journal) or (matching plan+matching journal)
    // may be used. Incomplete initialization fails closed; no deletion/repair.
    pub(crate) fn begin(&self, plan: &JobPlan) -> Result<Vec<crate::batch_journal::VerifiedEvent>> {
        match self.persist_plan(plan) {
            Ok(()) => self.init_journal(plan)?,
            Err(error)
                if error.chain().any(|source| {
                    source
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == ErrorKind::AlreadyExists)
                }) => {}
            Err(error) => return Err(error),
        }
        // Read, decode and authenticate saved state once per exclusive run.
        self.install_session(plan)
    }

    pub(crate) fn open(private_dir: &Path) -> Result<Self> {
        // Pin every path ancestor with openat/NOFOLLOW, rather than only
        // protecting the last component of the state path. Android's SELinux
        // policy requires O_PATH for some ancestors.
        let anchor = crate::batch_verify::root_directory(private_dir.as_os_str().as_bytes())
            .context("pin complete state directory path without symlinks")?;
        let identity = anchor.metadata()?;
        // O_PATH is insufficient for fsync; reopen "." relative to the pinned
        // inode with a readable directory handle.
        // SAFETY: anchor is a live directory descriptor, and c"." is fixed.
        let fd = unsafe {
            libc::openat(
                anchor.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("open pinned state directory for sync and writes");
        }
        // SAFETY: successful openat returns a unique owned fd.
        let directory = unsafe { File::from_raw_fd(fd) };
        let now = directory.metadata()?;
        ensure!(
            identity.dev() == now.dev() && identity.ino() == now.ino(),
            "state directory inode changed while opening"
        );
        secure_fd(&directory, false)?;
        let lock = open_relative(&directory, LOCK_NAME, libc::O_RDWR | libc::O_CREAT)?;
        // SAFETY: flock only inspects the live fd and its flags.
        let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        ensure!(result == 0, "another job owns the state lock");
        assert_named_file(&directory, LOCK_NAME, &lock)?;
        directory.sync_all()?;
        Ok(Self {
            directory,
            _lock: lock,
            cached: RefCell::new(None),
        })
    }

    pub(crate) fn persist_plan(&self, plan: &JobPlan) -> Result<()> {
        let encoded = plan.encode()?;
        ensure!(encoded.len() as u64 <= MAX_STATE_BYTES, "plan too large");
        let mut file = open_relative(
            &self.directory,
            PLAN_NAME,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        assert_named_file(&self.directory, PLAN_NAME, &file)?;
        self.directory.sync_all()?;
        crate::batch_fault::kill_if("plan_synced");
        Ok(())
    }

    fn load_matching_plan(&self, current: &JobPlan) -> Result<()> {
        let file = open_relative(&self.directory, PLAN_NAME, libc::O_RDONLY)?;
        let saved = read_checked(file.try_clone()?)?;
        assert_named_file(&self.directory, PLAN_NAME, &file)?;
        let plan = JobPlan::decode(&saved)?;
        ensure!(
            saved == current.encode()? && plan.fingerprint() == current.fingerprint(),
            "saved job plan does not match current source/destination"
        );
        Ok(())
    }

    pub(crate) fn init_journal(&self, current: &JobPlan) -> Result<()> {
        self.load_matching_plan(current)?;
        let mut file = open_relative(
            &self.directory,
            JOURNAL_NAME,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        let encoded = crate::batch_journal::encode(&[], &current.fingerprint());
        file.write_all(&encoded)?;
        file.sync_all()?;
        assert_named_file(&self.directory, JOURNAL_NAME, &file)?;
        self.directory.sync_all()?;
        crate::batch_fault::kill_if("journal_initialized");
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn load_journal(
        &self,
        current: &JobPlan,
    ) -> Result<Vec<crate::batch_journal::VerifiedEvent>> {
        self.load_matching_plan(current)?;
        let journal = open_relative(&self.directory, JOURNAL_NAME, libc::O_RDONLY)?;
        let raw = read_checked(journal.try_clone()?)?;
        assert_named_file(&self.directory, JOURNAL_NAME, &journal)?;
        crate::batch_journal::decode(&raw, &current.fingerprint(), current.regular_files())
    }

    // A successful batch MUST fully decode every record at the end.
    // Filesystems with coarse timestamps can miss same-size in-process
    // mutations in the per-append inode-stamp fast path.
    pub(crate) fn verify_final(&self, current: &JobPlan) -> Result<()> {
        self.load_matching_plan(current)?;
        let file = open_relative(&self.directory, JOURNAL_NAME, libc::O_RDONLY)?;
        let stamp_before = FileStamp::read(&file)?;
        let raw = read_checked(file.try_clone()?)?;
        assert_named_file(&self.directory, JOURNAL_NAME, &file)?;
        ensure!(
            FileStamp::read(&file)? == stamp_before,
            "journal changed during final full validation"
        );
        let events =
            crate::batch_journal::decode(&raw, &current.fingerprint(), current.regular_files())?;
        ensure!(
            events.len() as u64 == current.regular_files(),
            "incomplete journal at the end of directory resume"
        );
        // Events are strictly increasing, in-range and distinct per decoder.
        // Exactly N records for N files therefore covers the entire plan.
        ensure!(
            self.cached
                .borrow()
                .as_ref()
                .is_some_and(|cache| cache.journal_stamp.len == stamp_before.len
                    && cache.last == events.last().map(|event| event.file_index)
                    && cache.commitment
                        == events.iter().fold(current.fingerprint(), |chain, event| {
                            extend_commitment(chain, event)
                        })),
            "validated journal differs from completed writer session"
        );
        Ok(())
    }

    // Only the first append of a new session decodes the complete plan and
    // journal. The original V1 format is preserved byte-for-byte.
    fn install_session(
        &self,
        current: &JobPlan,
    ) -> Result<Vec<crate::batch_journal::VerifiedEvent>> {
        let plan = open_relative(&self.directory, PLAN_NAME, libc::O_RDONLY)?;
        let plan_before = FileStamp::read(&plan)?;
        let saved_plan = read_checked(plan.try_clone()?)?;
        assert_named_file(&self.directory, PLAN_NAME, &plan)?;
        ensure!(
            FileStamp::read(&plan)? == plan_before,
            "saved plan changed while loading journal session"
        );
        let decoded_plan = JobPlan::decode(&saved_plan)?;
        ensure!(
            saved_plan == current.encode()? && decoded_plan.fingerprint() == current.fingerprint(),
            "saved job plan does not match current source/destination"
        );
        let journal = open_relative(&self.directory, JOURNAL_NAME, libc::O_RDWR)?;
        let journal_before = FileStamp::read(&journal)?;
        let raw = read_checked(journal.try_clone()?)?;
        assert_named_file(&self.directory, JOURNAL_NAME, &journal)?;
        ensure!(
            FileStamp::read(&journal)? == journal_before,
            "saved journal changed while loading session"
        );
        let events =
            crate::batch_journal::decode(&raw, &current.fingerprint(), current.regular_files())?;
        ensure!(
            self.cached.borrow().is_none(),
            "cannot initialize a second journal session on the same lock"
        );
        *self.cached.borrow_mut() = Some(JournalSession {
            plan,
            journal,
            plan_stamp: plan_before,
            journal_stamp: journal_before,
            fingerprint: current.fingerprint(),
            planned_files: current.regular_files(),
            plan_address: current as *const JobPlan as usize,
            last: events.last().map(|e| e.file_index),
            commitment: events.iter().fold(current.fingerprint(), |chain, event| {
                extend_commitment(chain, event)
            }),
        });
        Ok(events)
    }

    pub(crate) fn record_verified(
        &self,
        current: &JobPlan,
        file_index: u64,
        full_digest: [u8; 32],
    ) -> Result<()> {
        ensure!(
            file_index < current.regular_files(),
            "event outside job plan"
        );
        if self.cached.borrow().is_none() {
            // Unit-test callers may use persist_plan/init_journal directly.
            // In the runtime begin() always loads the cache beforehand.
            self.install_session(current)?;
        }

        // Take before I/O: if any write, sync or inode check fails, discard
        // the cache and revalidate the entire on-disk journal next time.
        let mut session = self
            .cached
            .borrow_mut()
            .take()
            .context("journal session missing after initialization")?;
        let outcome = (|| -> Result<()> {
            ensure!(
                session.plan_address == current as *const JobPlan as usize
                    && session.planned_files == current.regular_files(),
                "journal session bound to a different immutable plan"
            );
            assert_named_file(&self.directory, PLAN_NAME, &session.plan)?;
            assert_named_file(&self.directory, JOURNAL_NAME, &session.journal)?;
            ensure!(
                FileStamp::read(&session.plan)? == session.plan_stamp,
                "saved plan changed since initial full validation"
            );
            ensure!(
                FileStamp::read(&session.journal)? == session.journal_stamp,
                "journal changed outside the exclusive writer session"
            );
            if let Some(last) = session.last {
                ensure!(file_index > last, "reordered or duplicate event");
            }

            let event = crate::batch_journal::VerifiedEvent {
                file_index,
                full_file_digest: full_digest,
            };
            let updated_commitment = extend_commitment(session.commitment, &event);
            let frame = crate::batch_journal::encode(&[event], &session.fingerprint);
            let offset = crate::batch_journal::journal_header_len();
            let appended = &frame[offset..];
            ensure!(
                session
                    .journal_stamp
                    .len
                    .checked_add(appended.len() as u64)
                    .is_some_and(|n| n <= MAX_STATE_BYTES),
                "journal capacity exhausted"
            );
            // Do not append if a concurrent writer extended the journal
            // after metadata verification.
            let end = session.journal.seek(SeekFrom::End(0))?;
            ensure!(
                end == session.journal_stamp.len,
                "journal length changed before append"
            );
            if cfg!(debug_assertions)
                && std::env::var("MCH_BATCH_TEST_SIGKILL_AT").ok().as_deref()
                    == Some("journal_torn")
            {
                session.journal.write_all(&appended[..5])?;
                session.journal.sync_all()?;
                crate::batch_fault::kill_if("journal_torn");
            }
            session.journal.write_all(appended)?;
            session.journal.sync_all()?;
            assert_named_file(&self.directory, JOURNAL_NAME, &session.journal)?;
            let after = FileStamp::read(&session.journal)?;
            ensure!(
                after.dev == session.journal_stamp.dev
                    && after.ino == session.journal_stamp.ino
                    && after.len == end + appended.len() as u64,
                "journal inode or size changed during append"
            );
            session.journal_stamp = after;
            session.last = Some(file_index);
            session.commitment = updated_commitment;
            crate::batch_fault::kill_if("journal_event_synced");
            Ok(())
        })();
        if outcome.is_ok() {
            *self.cached.borrow_mut() = Some(session);
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self};
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        JobPlan,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let source = root.join("source");
        let destination = root.join("target");
        let state = root.join("private-state");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("first"), b"one").unwrap();
        fs::write(source.join("second"), b"two").unwrap();
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let plan = JobPlan::build(&source, &destination).unwrap();
        (tmp, state, source, plan)
    }

    #[test]
    fn cached_journal_rejects_in_place_modification_without_appending() {
        let (_temp, state, _source, plan) = fixture();
        let store = LockedStore::open(&state).unwrap();
        assert!(store.begin(&plan).unwrap().is_empty());
        store.record_verified(&plan, 0, [1; 32]).unwrap();
        let path = state.join("journal.v1");
        let mut original = fs::read(&path).unwrap();
        original[1] ^= 0x55;
        fs::write(&path, &original).unwrap();
        // Some filesystems report identical ctime/mtime for a fast
        // same-length overwrite; such a mutation must still make the
        // mandatory final full journal validation fail.
        let attempted = store.record_verified(&plan, 1, [2; 32]);
        if attempted.is_ok() {
            assert!(store.verify_final(&plan).is_err());
        }
        assert!(fs::read(&path).unwrap().starts_with(&original));
        assert!(store.load_journal(&plan).is_err());
    }

    #[test]
    fn cached_journal_rejects_replaced_inode_even_with_identical_bytes() {
        let (_temp, state, _source, plan) = fixture();
        let store = LockedStore::open(&state).unwrap();
        store.begin(&plan).unwrap();
        store.record_verified(&plan, 0, [1; 32]).unwrap();
        let original = state.join("journal.v1");
        let replacement = state.join("replacement");
        fs::copy(&original, &replacement).unwrap();
        fs::rename(&replacement, &original).unwrap();
        let bytes = fs::read(&original).unwrap();
        assert!(store.record_verified(&plan, 1, [2; 32]).is_err());
        assert_eq!(fs::read(original).unwrap(), bytes);
    }

    #[test]
    fn cached_plan_rejects_in_place_mutation_before_another_append() {
        let (_temp, state, _source, plan) = fixture();
        let store = LockedStore::open(&state).unwrap();
        store.begin(&plan).unwrap();
        store.record_verified(&plan, 0, [1; 32]).unwrap();
        let plan_file = state.join("plan.v1");
        let mut changed = fs::read(&plan_file).unwrap();
        changed[0] ^= 0x80;
        fs::write(&plan_file, &changed).unwrap();
        let journal_before = fs::read(state.join("journal.v1")).unwrap();
        assert!(store.record_verified(&plan, 1, [2; 32]).is_err());
        assert_eq!(fs::read(state.join("journal.v1")).unwrap(), journal_before);
        assert_eq!(fs::read(plan_file).unwrap(), changed);
    }

    #[test]
    fn cached_journal_refuses_external_truncation_and_preserves_it() {
        let (_temp, state, _source, plan) = fixture();
        let store = LockedStore::open(&state).unwrap();
        store.begin(&plan).unwrap();
        store.record_verified(&plan, 0, [1; 32]).unwrap();
        let path = state.join("journal.v1");
        let mut torn = fs::read(&path).unwrap();
        torn.truncate(torn.len() - 3);
        fs::write(&path, &torn).unwrap();
        assert!(store.record_verified(&plan, 1, [2; 32]).is_err());
        assert_eq!(fs::read(&path).unwrap(), torn);
        assert!(store.load_journal(&plan).is_err());
    }

    #[test]
    fn cached_session_reloads_and_checks_complete_history_after_reopen() {
        let (_temp, state, _source, plan) = fixture();
        {
            let store = LockedStore::open(&state).unwrap();
            store.begin(&plan).unwrap();
            store.record_verified(&plan, 0, [9; 32]).unwrap();
        }
        let store = LockedStore::open(&state).unwrap();
        let saved = store.begin(&plan).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].file_index, 0);
        assert_eq!(saved[0].full_file_digest, [9; 32]);
        store.record_verified(&plan, 1, [8; 32]).unwrap();
        assert_eq!(store.load_journal(&plan).unwrap().len(), 2);
    }

    #[test]
    #[ignore = "manual 1k/10k/50k synthetic journal stress benchmark; fsyncs each event"]
    fn journal_append_scaling_1000_10000_50000() {
        use std::time::Instant;
        for count in [1000usize, 10_000, 50_000] {
            let temp = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(temp.path()).unwrap();
            let state = root.join("state");
            fs::create_dir(&state).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
            let plan = JobPlan::synthetic_for_journal(count);
            let store = LockedStore::open(&state).unwrap();
            let init = Instant::now();
            assert!(store.begin(&plan).unwrap().is_empty());
            let init_elapsed = init.elapsed();
            let start = Instant::now();
            for index in 0..count {
                let digest = *blake3::hash(&index.to_le_bytes()).as_bytes();
                store.record_verified(&plan, index as u64, digest).unwrap();
                if index > 0 && index % 10_000 == 0 {
                    eprintln!("journal_only_heartbeat count={count} appended={index}");
                }
            }
            let append_elapsed = start.elapsed();
            let validate = Instant::now();
            store.verify_final(&plan).unwrap();
            let validate_elapsed = validate.elapsed();
            let journal_bytes = fs::metadata(state.join("journal.v1")).unwrap().len();
            drop(store);
            let reopened = LockedStore::open(&state).unwrap();
            let reopen_start = Instant::now();
            let events = reopened.begin(&plan).unwrap();
            let reopen_elapsed = reopen_start.elapsed();
            assert_eq!(events.len(), count);
            assert_eq!(events.last().unwrap().file_index, count as u64 - 1);
            reopened.verify_final(&plan).unwrap();
            eprintln!(
                "JOURNAL_ONLY_BENCH files={count} bytes={journal_bytes} init_s={:.3} append_s={:.3} final_verify_s={:.3} reopen_s={:.3}",
                init_elapsed.as_secs_f64(),
                append_elapsed.as_secs_f64(),
                validate_elapsed.as_secs_f64(),
                reopen_elapsed.as_secs_f64()
            );
        }
    }

    #[test]
    fn persistent_files_survive_reopen_and_are_private() {
        let (_tmp, state, _source, plan) = fixture();
        {
            let store = LockedStore::open(&state).unwrap();
            store.persist_plan(&plan).unwrap();
            store.init_journal(&plan).unwrap();
            store
                .record_verified(&plan, 0, *blake3::hash(b"one").as_bytes())
                .unwrap();
            assert_eq!(store.load_journal(&plan).unwrap().len(), 1);
            for name in ["plan.v1", "journal.v1", "lock.v1"] {
                let meta = fs::metadata(state.join(name)).unwrap();
                assert_eq!(meta.permissions().mode() & 0o777, 0o600);
                assert_eq!(meta.nlink(), 1);
            }
        }
        let store = LockedStore::open(&state).unwrap();
        store.load_matching_plan(&plan).unwrap();
        store
            .record_verified(&plan, 1, *blake3::hash(b"two").as_bytes())
            .unwrap();
        assert_eq!(store.load_journal(&plan).unwrap().len(), 2);
        assert!(store.persist_plan(&plan).is_err());
        assert!(store.init_journal(&plan).is_err());
        assert!(store.record_verified(&plan, 1, [0; 32]).is_err());
    }

    #[test]
    fn lock_prevents_second_writer_and_recovers_after_drop() {
        let (_tmp, state, _source, _plan) = fixture();
        let first = LockedStore::open(&state).unwrap();
        assert!(LockedStore::open(&state).is_err());
        drop(first);
        assert!(LockedStore::open(&state).is_ok());
    }

    #[test]
    fn tampering_with_persisted_plan_or_journal_fails_closed() {
        let (_tmp, state, _source, plan) = fixture();
        let store = LockedStore::open(&state).unwrap();
        store.persist_plan(&plan).unwrap();
        store.init_journal(&plan).unwrap();
        let path = state.join("plan.v1");
        let mut bytes = fs::read(&path).unwrap();
        let original_len = bytes.len();
        bytes.truncate(original_len - 3);
        fs::write(&path, &bytes).unwrap();
        assert!(store.load_matching_plan(&plan).is_err());
        assert!(store.load_journal(&plan).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn torn_journal_never_gets_automatically_truncated() {
        let (_tmp, state, _source, plan) = fixture();
        let store = LockedStore::open(&state).unwrap();
        store.persist_plan(&plan).unwrap();
        store.init_journal(&plan).unwrap();
        let path = state.join("journal.v1");
        let mut damaged = fs::read(&path).unwrap();
        damaged.extend_from_slice(&[1, 2, 3]);
        fs::write(&path, &damaged).unwrap();
        assert!(store.load_journal(&plan).is_err());
        assert!(store.record_verified(&plan, 0, [0; 32]).is_err());
        assert_eq!(fs::read(&path).unwrap(), damaged);
    }

    #[test]
    fn symlink_and_insecure_permissions_fail_closed() {
        let (_tmp, state, _source, plan) = fixture();
        let target = state.join("outside");
        fs::write(&target, b"untouched").unwrap();
        symlink(&target, state.join("plan.v1")).unwrap();
        let store = LockedStore::open(&state).unwrap();
        assert!(store.persist_plan(&plan).is_err());
        assert!(store.load_matching_plan(&plan).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"untouched");
        fs::remove_file(state.join("plan.v1")).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(LockedStore::open(&state).is_err());
    }

    #[test]
    fn hardlinked_state_file_cannot_be_reused() {
        let (_tmp, state, _source, plan) = fixture();
        let store = LockedStore::open(&state).unwrap();
        store.persist_plan(&plan).unwrap();
        let copy = state.join("alias");
        if let Err(error) = fs::hard_link(state.join("plan.v1"), &copy) {
            // Some Android private app sandboxes forbid hardlink creation.
            assert!(matches!(
                error.kind(),
                ErrorKind::PermissionDenied | ErrorKind::Unsupported
            ));
            return;
        }
        assert!(store.load_matching_plan(&plan).is_err());
    }

    #[test]
    fn fifo_replacing_a_journal_does_not_block_open() {
        use std::os::unix::ffi::OsStrExt;
        let (_tmp, state, _source, plan) = fixture();
        let store = LockedStore::open(&state).unwrap();
        store.persist_plan(&plan).unwrap();
        store.init_journal(&plan).unwrap();
        let journal = state.join("journal.v1");
        fs::remove_file(&journal).unwrap();
        let name = std::ffi::CString::new(journal.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is a single private temp fixture path; no real data.
        let result = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            assert!(matches!(
                error.kind(),
                ErrorKind::PermissionDenied | ErrorKind::Unsupported
            ));
            return;
        }
        assert!(store.load_journal(&plan).is_err());
        assert!(store.record_verified(&plan, 0, [0; 32]).is_err());
    }

    #[test]
    fn symlinked_lock_never_opens_target() {
        let (_tmp, state, _source, _plan) = fixture();
        let target = state.join("outside");
        fs::write(&target, b"safe").unwrap();
        symlink(&target, state.join("lock.v1")).unwrap();
        assert!(LockedStore::open(&state).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"safe");
    }
}

#[cfg(test)]
mod additional_tests {
    use super::*;
    use std::fs::{self};
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn changed_source_plan_is_not_accepted_after_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let src = root.join("src");
        let dst = root.join("dst");
        let state = root.join("state");
        fs::create_dir(&src).unwrap();
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(src.join("file"), b"old").unwrap();
        let before = JobPlan::build(&src, &dst).unwrap();
        {
            let store = LockedStore::open(&state).unwrap();
            store.persist_plan(&before).unwrap();
            store.init_journal(&before).unwrap();
        }
        fs::write(src.join("file"), b"changed content").unwrap();
        let after = JobPlan::build(&src, &dst).unwrap();
        let store = LockedStore::open(&state).unwrap();
        assert!(store.load_matching_plan(&after).is_err());
        assert!(store.load_journal(&after).is_err());
        assert_eq!(fs::read(src.join("file")).unwrap(), b"changed content");
    }

    #[test]
    fn journal_symlink_is_never_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let src = root.join("src");
        let state = root.join("state");
        fs::create_dir(&src).unwrap();
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(src.join("file"), b"contents").unwrap();
        let plan = JobPlan::build(&src, &root.join("dst")).unwrap();
        let target = root.join("important");
        fs::write(&target, b"preserve").unwrap();
        let store = LockedStore::open(&state).unwrap();
        store.persist_plan(&plan).unwrap();
        symlink(&target, state.join("journal.v1")).unwrap();
        assert!(store.init_journal(&plan).is_err());
        assert!(store.load_journal(&plan).is_err());
        assert_eq!(fs::read(target).unwrap(), b"preserve");
    }

    #[test]
    fn symlinked_state_ancestor_is_rejected_without_creating_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let state_parent = root.join("private-parent");
        let state = state_parent.join("state");
        fs::create_dir(&state_parent).unwrap();
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let linked_parent = root.join("linked-parent");
        symlink(&state_parent, &linked_parent).unwrap();
        assert!(LockedStore::open(&linked_parent.join("state")).is_err());
        assert!(fs::read_dir(&state).unwrap().next().is_none());
        assert!(LockedStore::open(&state).is_ok());
    }

    #[test]
    fn symlinked_state_directory_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let state = root.join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&state, root.join("state-link")).unwrap();
        assert!(LockedStore::open(&root.join("state-link")).is_err());
        assert!(fs::read_dir(state).unwrap().next().is_none());
    }

    #[test]
    fn verified_rehash_can_be_recorded_and_is_required_again_after_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let src = root.join("src");
        let dst = root.join("dst");
        let state = root.join("state");
        fs::create_dir(&src).unwrap();
        fs::create_dir(&dst).unwrap();
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(src.join("file"), b"verified content").unwrap();
        fs::write(dst.join("file"), b"verified content").unwrap();
        let plan = JobPlan::build(&src, &dst).unwrap();

        // Crash window after publishing but before journal append:
        // existing target still needs an independent full rehash.
        let digest = crate::batch_verify::verify_completed(&plan, 0, None).unwrap();
        {
            let store = LockedStore::open(&state).unwrap();
            store.persist_plan(&plan).unwrap();
            store.init_journal(&plan).unwrap();
            store.record_verified(&plan, 0, digest).unwrap();
        }
        let store = LockedStore::open(&state).unwrap();
        let entries = store.load_journal(&plan).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            crate::batch_verify::verify_completed(
                &plan,
                entries[0].file_index,
                Some(&entries[0].full_file_digest)
            )
            .unwrap(),
            digest
        );

        // Do not trust a previously verified journal event after tampering.
        fs::write(dst.join("file"), b"tampered content").unwrap();
        assert!(
            crate::batch_verify::verify_completed(&plan, 0, Some(&entries[0].full_file_digest))
                .is_err()
        );
        assert_eq!(store.load_journal(&plan).unwrap(), entries);
        assert_eq!(fs::read(src.join("file")).unwrap(), b"verified content");
    }

    #[test]
    fn plan_fingerprint_is_not_file_content_integrity() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let src = root.join("src");
        fs::create_dir(&src).unwrap();
        let path = src.join("file");
        fs::write(&path, b"AAAA").unwrap();
        let original_mtime =
            filetime::FileTime::from_last_modification_time(&fs::metadata(&path).unwrap());
        let before = JobPlan::build(&src, &root.join("dst"))
            .unwrap()
            .fingerprint();
        fs::write(&path, b"BBBB").unwrap();
        filetime::set_file_mtime(&path, original_mtime).unwrap();
        let after = JobPlan::build(&src, &root.join("dst"))
            .unwrap()
            .fingerprint();
        assert_eq!(
            before, after,
            "metadata is not a substitute for verifying contents"
        );
        assert_ne!(blake3::hash(b"AAAA"), blake3::hash(b"BBBB"));
    }
}
