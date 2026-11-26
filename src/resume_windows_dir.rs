// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native NTFS directory resume. A synced record binds each stage's file ID
//! before publication, allowing recovery on either side of the rename.
use super::{
    checked, complete_stage, file_id, fingerprint, open_directory, pin_directories, require_ntfs,
    state, validate_path,
};
use crate::{Cli, HashAlg, engine::folded_destination_key, hashing::hash_open_file};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

type Id = [u8; 24];
const WORKSPACE: &str = ".mch-winresume-work";
const LEDGER: &str = ".mch-winresume-directory.job";
const HEADER: usize = 32;
const RECORD: usize = 24 + 32;

struct Root {
    path: PathBuf,
    id: Id,
    _pins: Vec<File>,
}

impl Root {
    fn open(input: &Path) -> Result<Self> {
        validate_path(input)?;
        let pins = pin_directories(&std::path::absolute(input)?)?;
        let dir = pins.last().context("missing root directory handle")?;
        require_ntfs(dir)?;
        let handle = dir.as_raw_handle();
        // Use the physical volume namespace for all later opens, including SUBST aliases.
        let size =
            unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, VOLUME_NAME_GUID) };
        ensure!(size > 0, "cannot resolve local NTFS volume path");
        let mut words = vec![0; size as usize];
        let used = unsafe {
            GetFinalPathNameByHandleW(handle, words.as_mut_ptr(), size, VOLUME_NAME_GUID)
        };
        ensure!(used > 0 && used < size, "unstable volume path");
        let path = PathBuf::from(OsString::from_wide(&words[..used as usize]));
        ensure!(
            path.parent().is_some(),
            "a Windows resume root cannot be a whole volume"
        );
        let id = file_id(dir)?;
        let physical_pins = pin_directories(&path)?;
        ensure!(
            file_id(physical_pins.last().context("unresolved physical root")?)? == id,
            "physical Windows root changed while opening"
        );
        Ok(Self {
            path,
            id,
            _pins: physical_pins,
        })
    }
    fn workspace(mut self, security: &state::PrivateState, target: &Root) -> Result<Self> {
        let path = self.path.join(WORKSPACE);
        let create = !exists(&path)?;
        if create {
            ensure!(
                fs::read_dir(&self.path)?.next().is_none(),
                "a new job requires an empty state directory"
            );
            ensure!(
                fs::read_dir(&target.path)?.next().is_none(),
                "a new Windows directory resume requires an empty destination"
            );
        } else {
            for entry in fs::read_dir(&self.path)? {
                ensure!(
                    entry?.file_name() == WORKSPACE,
                    "unexpected file in the dedicated state directory"
                );
            }
        }
        let guard = security.directory(&path, create, 0)?;
        self.id = file_id(&guard)?;
        self.path = path;
        self._pins.push(guard);
        Ok(self)
    }
}

// The kernel releases this mutex if a process is terminated. Use the target
// identity so even a different state folder or drive spelling selects the same lock.
struct TargetLock(OwnedHandle);

impl TargetLock {
    fn acquire(id: &Id) -> Result<Self> {
        let label = format!(r"Global\MCH-WinDirResume-{}", hex::encode(id));
        let wide = state::wide(std::ffi::OsStr::new(&label))?;
        let raw = unsafe { CreateMutexW(std::ptr::null(), 0, wide.as_ptr()) };
        if raw.is_null() {
            return Err(std::io::Error::last_os_error()).context("open directory resume mutex");
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        match unsafe { WaitForSingleObject(raw, 0) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(handle)),
            WAIT_TIMEOUT => anyhow::bail!("another directory resume already owns this destination"),
            _ => Err(std::io::Error::last_os_error()).context("lock directory resume destination"),
        }
    }
}
impl Drop for TargetLock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0.as_raw_handle());
        }
    }
}

fn overlaps(a: &Root, b: &Root) -> bool {
    let left = folded_destination_key(&a.path);
    let right = folded_destination_key(&b.path);
    a.id == b.id
        || a.path
            .ancestors()
            .any(|p| folded_destination_key(p) == right)
        || b.path
            .ancestors()
            .any(|p| folded_destination_key(p) == left)
}

fn open_regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("open file for Windows directory resume: {}", path.display()))?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    checked(unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) })?;
    ensure!(
        info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) == 0
            && info.nNumberOfLinks == 1
            && unsafe { GetFileType(file.as_raw_handle()) } == FILE_TYPE_DISK,
        "expected an ordinary file with one link: {}",
        path.display()
    );
    Ok(file)
}

#[derive(PartialEq, Eq)]
struct Item {
    id: Id,
    content: Option<Content>,
}
#[derive(PartialEq, Eq)]
struct Content {
    bytes: u64,
    modified: u64,
    digest: String,
}
type Plan = BTreeMap<PathBuf, Item>;

fn pin_relative_directory(
    root: &Root,
    relative: &Path,
    known: &BTreeMap<PathBuf, Id>,
) -> Result<Vec<File>> {
    let mut chain = Vec::new();
    let mut prefix = PathBuf::new();
    for part in relative.components() {
        prefix.push(part);
        let file = open_directory(&root.path.join(&prefix))?;
        ensure!(
            Some(&file_id(&file)?) == known.get(&prefix),
            "directory identity changed: {}",
            prefix.display()
        );
        chain.push(file);
    }
    Ok(chain)
}

fn scan(source: &Root) -> Result<Plan> {
    let mut plan = Plan::new();
    let mut dirs = BTreeMap::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(dir) = pending.pop() {
        let _pins = pin_relative_directory(source, &dir, &dirs)?;
        let mut names = HashSet::new();
        for child in fs::read_dir(source.path.join(&dir))? {
            let child = child?;
            let name = child.file_name();
            // Validate the leaf without allowing ambiguous names or a private state prefix.
            super::validate_components(Path::new(&name))?;
            ensure!(
                names.insert(folded_destination_key(Path::new(&name))),
                "ambiguous destination name: {:?}",
                name
            );
            let relative = dir.join(name);
            let path = child.path();
            let meta = fs::symlink_metadata(&path)?;
            ensure!(
                meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                "unsupported source reparse point: {}",
                path.display()
            );
            let item = if meta.is_dir() {
                let id = file_id(&open_directory(&path)?)?;
                dirs.insert(relative.clone(), id);
                pending.push(relative.clone());
                Item { id, content: None }
            } else {
                let mut file = open_regular(&path)?;
                let meta = file.metadata()?;
                let content = Content {
                    bytes: meta.len(),
                    modified: meta.last_write_time(),
                    digest: hash_open_file(&mut file, HashAlg::Blake3, None)?,
                };
                Item {
                    id: file_id(&file)?,
                    content: Some(content),
                }
            };
            ensure!(
                plan.insert(relative, item).is_none(),
                "duplicate source entry"
            );
        }
    }
    Ok(plan)
}

fn plan_key(roots: [&Root; 3], plan: &Plan) -> [u8; 32] {
    fn path_hash(hasher: &mut blake3::Hasher, path: &Path) {
        let os = path.as_os_str();
        hasher.update(&(os.encode_wide().count() as u64).to_le_bytes());
        for word in os.encode_wide() {
            hasher.update(&word.to_le_bytes());
        }
    }
    let mut h = blake3::Hasher::new_derive_key("MCH Windows directory resume plan v1");
    for root in roots {
        h.update(&root.id);
        path_hash(&mut h, &root.path);
    }
    for (name, item) in plan {
        path_hash(&mut h, name);
        h.update(&item.id);
        if let Some(data) = &item.content {
            h.update(b"F");
            h.update(&data.bytes.to_le_bytes());
            h.update(&data.modified.to_le_bytes());
            h.update(data.digest.as_bytes());
        } else {
            h.update(b"D");
        }
    }
    *h.finalize().as_bytes()
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

struct Journal {
    file: File,
    key: [u8; 32],
    data: Vec<u8>,
}

impl Journal {
    fn open(
        security: &state::PrivateState,
        folder: &Root,
        target: &Root,
        key: [u8; 32],
        count: usize,
    ) -> Result<Self> {
        let ledger = folder.path.join(LEDGER);
        if !exists(&ledger)? {
            ensure!(
                fs::read_dir(&folder.path)?.next().is_none(),
                "a new job requires an empty state directory"
            );
            ensure!(
                fs::read_dir(&target.path)?.next().is_none(),
                "a new Windows directory resume requires an empty destination"
            );
        }
        let (mut file, _) = security.open(&ledger, OPEN_ALWAYS)?;
        let len = usize::try_from(file.metadata()?.len())?;
        ensure!(
            len <= count
                .checked_mul(RECORD)
                .and_then(|n| n.checked_add(HEADER))
                .context("plan size overflow")?,
            "directory resume journal exceeds current plan size"
        );
        if len >= HEADER {
            let tail = (len - HEADER) % RECORD;
            ensure!(
                tail == 0 || tail >= size_of::<Id>(),
                "incomplete NTFS identity in the final journal record; keep the job state and use fresh destination and state directories"
            );
        }
        let mut data = Vec::with_capacity(len);
        file.read_to_end(&mut data)?;
        let mut journal = Self { file, key, data };
        if len < HEADER {
            ensure!(
                fs::read_dir(&target.path)?.next().is_none(),
                "incomplete Windows job header and occupied destination"
            );
            for entry in fs::read_dir(&folder.path)? {
                ensure!(
                    entry?.file_name() == LEDGER,
                    "incomplete header with unexpected state"
                );
            }
        }
        journal
            .extend(0, &key)
            .context("source plan or job root changed")?;
        if len >= HEADER {
            // A killed writer may have written a whole record but not yet flushed it.
            journal
                .file
                .sync_all()
                .context("sync reopened directory journal")?;
        }
        Ok(journal)
    }

    // Append only the missing suffix. A process termination can leave the final
    // header or record short; every byte already present must match its reconstruction.
    fn extend(&mut self, offset: usize, expected: &[u8]) -> Result<()> {
        ensure!(
            offset <= self.data.len(),
            "nonsequential Windows resume journal"
        );
        let saved = (self.data.len() - offset).min(expected.len());
        ensure!(
            self.data[offset..offset + saved] == expected[..saved],
            "Windows resume journal mismatch"
        );
        if saved < expected.len() {
            self.file.seek(SeekFrom::End(0))?;
            self.file.write_all(&expected[saved..])?;
            self.file.sync_all()?;
            self.data.extend_from_slice(&expected[saved..]);
        }
        Ok(())
    }

    fn record(&self, index: usize, id: &Id) -> [u8; RECORD] {
        let mut hash = blake3::Hasher::new_keyed(&self.key);
        hash.update(&(index as u64).to_le_bytes());
        hash.update(id);
        let mut result = [0; RECORD];
        result[..24].copy_from_slice(id);
        result[24..].copy_from_slice(hash.finalize().as_bytes());
        result
    }

    fn recorded(&self, index: usize) -> Result<Option<Id>> {
        let offset = HEADER + index * RECORD;
        if let Some(record) = self.data.get(offset..offset + RECORD) {
            let id: Id = record[..24].try_into()?;
            ensure!(
                record == self.record(index, &id),
                "damaged Windows directory journal at entry {index}"
            );
            return Ok(Some(id));
        }
        Ok(None)
    }

    fn verify_disk(&mut self) -> Result<()> {
        self.file.rewind()?;
        let expected = blake3::hash(&self.data);
        let mut actual = blake3::Hasher::new();
        actual.update_reader(&mut self.file)?;
        ensure!(
            actual.finalize() == expected,
            "Windows directory journal changed during verification"
        );
        Ok(())
    }

    fn prepare(&mut self, index: usize, id: &Id) -> Result<()> {
        let record = self.record(index, id);
        self.extend(HEADER + index * RECORD, &record)
    }
}

fn verify_visible(path: &Path, item: &Item, expected: &Id) -> Result<()> {
    if let Some(content) = &item.content {
        let mut file = open_regular(path)?;
        ensure!(
            &file_id(&file)? == expected
                && file.metadata()?.len() == content.bytes
                && hash_open_file(&mut file, HashAlg::Blake3, None)? == content.digest,
            "completed file changed: {}",
            path.display()
        );
    } else {
        let dir = open_directory(path)?;
        ensure!(
            &file_id(&dir)? == expected,
            "completed directory changed: {}",
            path.display()
        );
    }
    Ok(())
}

fn visible_tree(
    target: &Root,
    plan: &Plan,
    indexes: &BTreeMap<&Path, usize>,
    journal: &Journal,
) -> Result<BTreeMap<PathBuf, Id>> {
    let mut found = BTreeMap::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let _pins = pin_relative_directory(target, &relative, &found)?;
        for child in fs::read_dir(target.path.join(&relative))? {
            let child = child?;
            let name = relative.join(child.file_name());
            let index = *indexes
                .get(name.as_path())
                .with_context(|| format!("unplanned destination entry: {}", name.display()))?;
            let item = &plan[&name];
            let id = journal.recorded(index)?.with_context(|| {
                format!(
                    "destination exists without a prepared identity: {}",
                    name.display()
                )
            })?;
            verify_visible(&child.path(), item, &id)?;
            if item.content.is_none() {
                pending.push(name.clone());
            }
            found.insert(name, id);
        }
    }
    Ok(found)
}

fn stage_name(index: usize) -> String {
    format!(".mch-winresume-{index:016x}.part")
}

fn check_state(folder: &Root, journal: &Journal) -> Result<()> {
    let full = (journal.data.len() - HEADER) / RECORD;
    let mut stages = 0;
    for entry in fs::read_dir(&folder.path)? {
        let name = entry?.file_name();
        if name == LEDGER {
            continue;
        }
        ensure!(
            name == stage_name(full).as_str()
                || full
                    .checked_sub(1)
                    .is_some_and(|n| name == stage_name(n).as_str()),
            "unexpected entry in Windows directory resume state: {:?}",
            name
        );
        stages += 1;
    }
    ensure!(stages <= 1, "multiple active Windows resume stages");
    Ok(())
}

pub(crate) fn run(cli: &Cli) -> Result<()> {
    let source = Root::open(&cli.sources[0]).context("open Windows source tree")?;
    let target = Root::open(&cli.destination).context("open Windows destination tree")?;
    let folder = Root::open(
        cli.resume_dir_state
            .as_deref()
            .context("missing resume state")?,
    )
    .context("open Windows job state")?;
    ensure!(
        !overlaps(&source, &target) && !overlaps(&source, &folder) && !overlaps(&target, &folder),
        "source, destination and state directories overlap"
    );
    ensure!(
        target.id[..8] == folder.id[..8],
        "Windows state and destination must use the same NTFS volume"
    );

    let _target_lock = TargetLock::acquire(&target.id)?;
    cli.report("RESUME-DIR: checking the source tree", true);
    let plan = scan(&source)?;
    let source_dirs = plan
        .iter()
        .filter(|(_, item)| item.content.is_none())
        .map(|(p, item)| (p.clone(), item.id))
        .collect();
    let indexes = plan
        .keys()
        .enumerate()
        .map(|(i, p)| (p.as_path(), i))
        .collect();
    let security = state::PrivateState::new()?;
    let folder = folder.workspace(&security, &target)?;
    let key = plan_key([&source, &target, &folder], &plan);
    let mut journal = Journal::open(&security, &folder, &target, key, plan.len())?;
    check_state(&folder, &journal)?;
    let mut visible = visible_tree(&target, &plan, &indexes, &journal)?;
    for (index, (relative, item)) in plan.iter().enumerate() {
        let dst = target.path.join(relative);
        let part = folder.path.join(stage_name(index));
        let parent = relative.parent().context("planned entry has no parent")?;
        let _target_parents = pin_relative_directory(&target, parent, &visible)?;
        if visible.contains_key(relative) {
            ensure!(!exists(&part)?, "published entry also has an active stage");
            cli.report(&format!("RESUME-DIR VERIFIED {}", relative.display()), true);
            continue;
        }
        let _source_parents = pin_relative_directory(&source, parent, &source_dirs)?;
        let prepared = journal.data.len() > HEADER + index * RECORD;
        let staged = exists(&part)?;
        ensure!(
            !prepared || (staged && journal.data.len() <= HEADER + (index + 1) * RECORD),
            "previously prepared destination is missing: {}",
            dst.display()
        );
        let stage = if let Some(content) = &item.content {
            let mut src = open_regular(&source.path.join(relative))?;
            ensure!(
                file_id(&src)? == item.id,
                "planned source file was replaced: {}",
                relative.display()
            );
            let identity = fingerprint(&src)?;
            let (mut file, _) =
                security.open(&part, if staged { OPEN_EXISTING } else { CREATE_NEW })?;
            ensure!(
                prepared || file.metadata()?.len() == 0,
                "unrecorded directory stage contains data"
            );
            journal.prepare(index, &file_id(&file)?)?;
            ensure!(
                complete_stage(cli, &mut src, &mut file, &identity)? == content.digest,
                "planned source contents changed: {}",
                relative.display()
            );
            file
        } else {
            let file = security.directory(&part, !staged, DELETE)?;
            ensure!(
                fs::read_dir(&part)?.next().is_none(),
                "staged directory must be empty before publication"
            );
            journal.prepare(index, &file_id(&file)?)?;
            file
        };
        let id = file_id(&stage)?;
        state::publish(&stage, &dst)
            .with_context(|| format!("publish directory job entry {}", dst.display()))?;
        drop(stage);
        verify_visible(&dst, item, &id)?;
        visible.insert(relative.clone(), id);
        cli.report(
            &format!("RESUME-DIR CHECKPOINT {}", relative.display()),
            true,
        );
    }
    cli.report("RESUME-DIR: verifying the completed tree", true);
    ensure!(
        scan(&source)? == plan,
        "source tree changed during Windows directory resume"
    );
    let completed = visible_tree(&target, &plan, &indexes, &journal)?;
    ensure!(
        completed.len() == plan.len(),
        "final directory verification found missing entries"
    );
    ensure!(
        journal.data.len() == HEADER + plan.len() * RECORD,
        "incomplete directory resume journal"
    );
    for entry in fs::read_dir(&folder.path)? {
        ensure!(
            entry?.file_name() == LEDGER,
            "completed job has unexpected state"
        );
    }
    journal.verify_disk()?;
    if !cli.quiet {
        println!(
            "DONE: {} verified tree entries; directory resume state retained",
            completed.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    struct Job {
        temp: tempfile::TempDir,
        src: PathBuf,
        dst: PathBuf,
        state: PathBuf,
    }

    impl Job {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let src = temp.path().join("source");
            let dst = temp.path().join("target");
            let state = temp.path().join("private-state");
            for dir in [&src, &dst, &state] {
                fs::create_dir(dir).unwrap();
            }
            Self {
                temp,
                src,
                dst,
                state,
            }
        }
        fn run(&self) -> Result<()> {
            let cli = Cli::parse_from([
                "mch",
                "--resume-dir",
                "--resume-dir-state",
                self.state.to_str().unwrap(),
                self.src.to_str().unwrap(),
                self.dst.to_str().unwrap(),
            ]);
            run(&cli)
        }
    }
    #[test]
    fn foreign_destination_and_overlapping_state_are_refused_before_writes() {
        let mut job = Job::new();
        fs::write(job.src.join("a"), b"first").unwrap();
        fs::write(job.dst.join("unrelated"), b"preserve").unwrap();
        assert!(job.run().is_err());
        assert!(!job.dst.join("a").exists());
        assert_eq!(fs::read_dir(&job.state).unwrap().count(), 0);
        fs::remove_file(job.dst.join("unrelated")).unwrap();
        job.state = job.src.join("state");
        fs::create_dir(&job.state).unwrap();
        assert!(job.run().is_err());
        assert_eq!(fs::read_dir(&job.state).unwrap().count(), 0);
    }
    #[test]
    fn second_worker_cannot_lock_same_destination_using_another_state() {
        let job = Job::new();
        let id = Root::open(&job.dst).unwrap().id;
        let held = TargetLock::acquire(&id).unwrap();
        std::thread::spawn(move || assert!(TargetLock::acquire(&id).is_err()))
            .join()
            .unwrap();
        drop(held);
        assert!(TargetLock::acquire(&id).is_ok());
    }
    #[test]
    fn recover_short_final_intent_from_same_staged_file() {
        let job = Job::new();
        fs::write(job.src.join("a"), b"earlier file").unwrap();
        fs::write(job.src.join("z"), b"last file").unwrap();
        job.run().unwrap();
        let stage = job.state.join(WORKSPACE).join(stage_name(1));
        fs::rename(job.dst.join("z"), &stage).unwrap();
        let ledger = job.state.join(WORKSPACE).join(LEDGER);
        let original = fs::read(&ledger).unwrap();
        let id_end = HEADER + RECORD + size_of::<Id>();
        fs::write(&ledger, &original[..id_end - 1]).unwrap();
        assert!(job.run().is_err());
        assert_eq!(fs::read(&ledger).unwrap(), original[..id_end - 1]);
        assert_eq!(fs::read(&stage).unwrap(), b"last file");
        assert!(!job.dst.join("z").exists());
        fs::write(&ledger, &original[..id_end]).unwrap();
        job.run().unwrap();
        assert_eq!(fs::read(&ledger).unwrap(), original);
        assert!(!stage.exists());
        assert_eq!(fs::read(job.dst.join("z")).unwrap(), b"last file");
    }
    #[test]
    fn incomplete_file_identity_never_adopts_a_replacement_stage() {
        let job = Job::new();
        fs::write(job.src.join("a"), b"earlier").unwrap();
        fs::write(job.src.join("z"), b"last file").unwrap();
        job.run().unwrap();

        let workspace = job.state.join(WORKSPACE);
        let ledger = workspace.join(LEDGER);
        let stage = workspace.join(stage_name(1));
        let published = job.dst.join("z");
        fs::rename(&published, job.temp.path().join("original-object")).unwrap();
        let (mut replacement, _) = state::PrivateState::new()
            .unwrap()
            .open(&stage, CREATE_NEW)
            .unwrap();
        replacement.write_all(b"last").unwrap();
        drop(replacement);
        let complete = fs::read(&ledger).unwrap();
        let offset = HEADER + RECORD;
        for saved in 1..=size_of::<Id>() {
            let shortened = &complete[..offset + saved];
            fs::write(&ledger, shortened).unwrap();
            assert!(job.run().is_err(), "accepted replacement at {saved} bytes");
            assert_eq!(fs::read(&ledger).unwrap(), shortened);
            assert_eq!(fs::read(&stage).unwrap(), b"last");
            assert!(!published.exists());
            assert_eq!(fs::read(job.dst.join("a")).unwrap(), b"earlier");
        }
    }

    #[test]
    fn changed_partial_and_wrong_prepared_id_are_preserved() {
        let job = Job::new();
        fs::write(job.src.join("data"), b"original payload").unwrap();
        job.run().unwrap();
        let part = job.state.join(WORKSPACE).join(stage_name(0));
        fs::rename(job.dst.join("data"), &part).unwrap();
        fs::write(&part, b"broken").unwrap();
        assert!(job.run().is_err());
        assert_eq!(fs::read(&part).unwrap(), b"broken");
        assert!(!job.dst.join("data").exists());
        fs::rename(&part, job.temp.path().join("previous-stage")).unwrap();
        let (mut replacement, _) = state::PrivateState::new()
            .unwrap()
            .open(&part, CREATE_NEW)
            .unwrap();
        replacement.write_all(b"orig").unwrap();
        drop(replacement);
        assert!(job.run().is_err());
        assert_eq!(fs::read(&part).unwrap(), b"orig");
        assert!(!job.dst.join("data").exists());
    }

    #[test]
    fn changed_source_and_damaged_journal_leave_published_file_intact() {
        let job = Job::new();
        fs::write(job.src.join("a"), b"original").unwrap();
        job.run().unwrap();
        let ledger = job.state.join(WORKSPACE).join(LEDGER);
        let mut bytes = fs::read(&ledger).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&ledger, &bytes).unwrap();
        assert!(job.run().is_err());
        assert_eq!(fs::read(&ledger).unwrap(), bytes);
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&ledger, bytes).unwrap();
        fs::write(job.src.join("a"), b"modified").unwrap();
        assert!(job.run().is_err());
        assert_eq!(fs::read(job.dst.join("a")).unwrap(), b"original");
    }
    #[test]
    fn source_hardlinks_rejected_before_writes_and_replaced_target_not_adopted() {
        let job = Job::new();
        fs::write(job.src.join("a"), b"test").unwrap();
        fs::hard_link(job.src.join("a"), job.src.join("alias")).unwrap();
        assert!(job.run().is_err());
        assert_eq!(fs::read_dir(&job.state).unwrap().count(), 0);
        fs::remove_file(job.src.join("alias")).unwrap();
        job.run().unwrap();
        fs::rename(job.dst.join("a"), job.temp.path().join("saved")).unwrap();
        fs::write(job.dst.join("a"), b"test").unwrap();
        assert!(job.run().is_err());
    }
}
