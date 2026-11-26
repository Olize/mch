// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Private experimental Unix job-plan validation and versioned V2 codec.
// Directory enumeration is delegated to descriptor-relative batch_walk.
// Private batch writer, manifest/lock and directory creator now use pinned
// dirfds. Adversarial same-user mutation requires separate security review.
use anyhow::{Context, Result, bail, ensure};
use std::collections::BTreeSet;
use std::fs::Metadata;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const MAX_ENTRIES: usize = 100_000;
const MAX_PLAN_BYTES: usize = 8 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntryKind {
    Directory,
    RegularFile,
}

impl EntryKind {
    fn as_byte(self) -> u8 {
        match self {
            Self::Directory => 1,
            Self::RegularFile => 2,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) relative: Vec<u8>,
    pub(crate) kind: EntryKind,
    device: u64,
    inode: u64,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
}

#[derive(Debug)]
pub(crate) struct PlannedFile<'a> {
    pub(crate) relative: &'a [u8],
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) size: u64,
    pub(crate) mtime_sec: i64,
    pub(crate) mtime_nsec: i64,
}

pub(crate) struct JobPlan {
    source_root: Vec<u8>,
    target_root: Vec<u8>,
    source_identity: (u64, u64),
    target_identity: Option<(u64, u64)>,
    entries: Vec<Entry>,
    file_indices: Vec<usize>,
}

pub(crate) fn validate_relative(raw: &[u8]) -> Result<()> {
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_PATH_BYTES,
        "invalid path length"
    );
    ensure!(!raw.contains(&0), "NUL in relative path");
    ensure!(raw[0] != b'/', "absolute relative path");
    for component in raw.split(|byte| *byte == b'/') {
        ensure!(!component.is_empty(), "empty path component");
        ensure!(component != b"." && component != b"..", "path traversal");
    }
    Ok(())
}

fn validate_absolute(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "absolute root path required");
    let raw = path.as_os_str().as_bytes();
    ensure!(
        !raw.contains(&0) && raw.len() <= MAX_PATH_BYTES,
        "invalid root path"
    );
    for component in path.components() {
        ensure!(
            !matches!(component, Component::CurDir | Component::ParentDir),
            "un-normalized root path"
        );
    }
    // Normalize double slashes and reject paths that designate filesystem root.
    let clean = path.components().collect::<PathBuf>();
    ensure!(
        clean != Path::new("/"),
        "filesystem root is not an allowed job root"
    );
    Ok(clean)
}

pub(crate) fn entry(relative: &Path, kind: EntryKind, meta: &Metadata) -> Result<Entry> {
    let raw = relative.as_os_str().as_bytes().to_vec();
    validate_relative(&raw)?;
    let nanos = meta.mtime_nsec();
    ensure!((0..1_000_000_000).contains(&nanos), "invalid timestamp");
    Ok(Entry {
        relative: raw,
        kind,
        device: meta.dev(),
        inode: meta.ino(),
        size: if kind == EntryKind::Directory {
            0
        } else {
            meta.len()
        },
        mtime_sec: meta.mtime(),
        mtime_nsec: nanos,
    })
}

impl JobPlan {
    fn index_files(entries: &[Entry]) -> Vec<usize> {
        entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.kind == EntryKind::RegularFile)
            .map(|(index, _)| index)
            .collect()
    }

    pub(crate) fn build(source: &Path, target: &Path) -> Result<Self> {
        Self::scan(source, target, false)
    }

    pub(crate) fn verify_completed_tree(&self, source: &Path, target: &Path) -> Result<()> {
        let current = Self::scan(source, target, true)?;
        ensure!(
            current.fingerprint() == self.fingerprint(),
            "source tree changed during directory resume; refusing success"
        );
        Ok(())
    }

    fn scan(source: &Path, target: &Path, require_targets: bool) -> Result<Self> {
        let source = validate_absolute(source)?;
        let target = validate_absolute(target)?;
        ensure!(
            !source.starts_with(&target) && !target.starts_with(&source),
            "source and target trees must not overlap"
        );
        // Every source/target component is inspected relative to a pinned
        // directory descriptor; concurrent entry swaps fail closed.
        let (source_meta, target_meta, mut entries) =
            crate::batch_walk::collect(&source, &target, require_targets)?;
        entries.sort_by(|a, b| a.relative.cmp(&b.relative));
        let mut seen = BTreeSet::new();
        let mut budget = source.as_os_str().len() + target.as_os_str().len();
        for item in &entries {
            validate_relative(&item.relative)?;
            let path = Path::new(std::ffi::OsStr::from_bytes(&item.relative));
            ensure!(
                seen.insert(crate::engine::folded_destination_key(path)),
                "ambiguous directory-resume destination: {}",
                path.display()
            );
            budget = budget
                .checked_add(item.relative.len() + 64)
                .context("plan byte count overflow")?;
            ensure!(budget <= MAX_PLAN_BYTES, "plan byte limit exceeded");
        }
        let file_indices = Self::index_files(&entries);
        Ok(Self {
            source_root: source.as_os_str().as_bytes().to_vec(),
            target_root: target.as_os_str().as_bytes().to_vec(),
            source_identity: (source_meta.dev(), source_meta.ino()),
            target_identity: target_meta.map(|meta| (meta.dev(), meta.ino())),
            entries,
            file_indices,
        })
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        let mut h = blake3::Hasher::new();
        h.update(b"MCH-PRIVATE-BATCH-PLAN-V2\0BLAKE3\0COPY-ONLY\0");
        field(&mut h, &self.source_root);
        field(&mut h, &self.target_root);
        h.update(&self.source_identity.0.to_le_bytes());
        h.update(&self.source_identity.1.to_le_bytes());
        match self.target_identity {
            None => {
                h.update(&[0]);
            }
            Some((device, inode)) => {
                h.update(&[1]);
                h.update(&device.to_le_bytes());
                h.update(&inode.to_le_bytes());
            }
        }
        h.update(&(self.entries.len() as u64).to_le_bytes());
        for item in &self.entries {
            field(&mut h, &item.relative);
            h.update(&[item.kind.as_byte()]);
            h.update(&item.device.to_le_bytes());
            h.update(&item.inode.to_le_bytes());
            h.update(&item.size.to_le_bytes());
            h.update(&item.mtime_sec.to_le_bytes());
            h.update(&item.mtime_nsec.to_le_bytes());
        }
        *h.finalize().as_bytes()
    }
}

#[cfg(test)]
impl JobPlan {
    /// Synthetic, immutable V2 plan for journal-only scaling tests.
    /// No real files are created, copied or modified.
    pub(crate) fn synthetic_for_journal(count: usize) -> Self {
        assert!(count <= MAX_ENTRIES);
        let entries = (0..count)
            .map(|i| Entry {
                relative: format!("f{i:06}").into_bytes(),
                kind: EntryKind::RegularFile,
                device: 1,
                inode: i as u64 + 100,
                size: 1,
                mtime_sec: 1,
                mtime_nsec: 0,
            })
            .collect::<Vec<_>>();
        Self {
            source_root: b"/mch-synthetic-source".to_vec(),
            target_root: b"/mch-synthetic-target".to_vec(),
            source_identity: (1, 2),
            target_identity: Some((1, 3)),
            file_indices: (0..count).collect(),
            entries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::ErrorKind;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;

    fn roots() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        // On macOS, /var is a system symlink. Use physical test paths.
        let physical = fs::canonicalize(temp.path()).unwrap();
        let source = physical.join("source");
        let target = physical.join("dest");
        fs::create_dir(&source).unwrap();
        (temp, source, target)
    }

    #[test]
    fn nested_and_empty_directories_have_stable_ordered_identity() {
        let (_tmp, src, dst) = roots();
        fs::create_dir(src.join("empty")).unwrap();
        fs::create_dir(src.join("nested")).unwrap();
        fs::write(src.join("nested").join("b"), b"two").unwrap();
        fs::write(src.join("nested").join("a"), b"one").unwrap();
        let first = JobPlan::build(&src, &dst).unwrap();
        let second = JobPlan::build(&src, &dst).unwrap();
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.entries.len(), 4);
        assert_eq!(
            first
                .entries
                .iter()
                .map(|e| e.relative.clone())
                .collect::<Vec<_>>(),
            [b"empty".as_slice(), b"nested", b"nested/a", b"nested/b"]
                .iter()
                .map(|s| s.to_vec())
                .collect::<Vec<_>>()
        );
        assert_ne!(
            first.fingerprint(),
            JobPlan::build(&src, &dst.with_extension("other"))
                .unwrap()
                .fingerprint()
        );
    }

    #[test]
    fn final_walk_requires_planned_targets_including_empty_directories() {
        let (_tmp, src, dst) = roots();
        fs::create_dir_all(src.join("outer/empty")).unwrap();
        fs::write(src.join("payload"), b"bytes").unwrap();
        fs::create_dir(&dst).unwrap();
        let plan = JobPlan::build(&src, &dst).unwrap();
        fs::create_dir(dst.join("outer")).unwrap();
        fs::write(dst.join("payload"), b"bytes").unwrap();
        assert!(plan.verify_completed_tree(&src, &dst).is_err());
        fs::create_dir(dst.join("outer/empty")).unwrap();
        plan.verify_completed_tree(&src, &dst).unwrap();
        fs::remove_file(dst.join("payload")).unwrap();
        assert!(plan.verify_completed_tree(&src, &dst).is_err());
    }

    #[test]
    fn raw_non_utf8_names_are_preserved() {
        let (_tmp, src, dst) = roots();
        let name = std::ffi::OsString::from_vec(vec![b'f', 0xff]);
        if let Err(error) = fs::write(src.join(&name), b"data") {
            // macOS APFS normally rejects invalid UTF-8 filenames with EILSEQ.
            // Still validate the raw-byte path grammar without a filesystem inode.
            #[cfg(target_os = "macos")]
            {
                assert_eq!(error.raw_os_error(), Some(libc::EILSEQ));
                assert!(validate_relative(name.as_bytes()).is_ok());
                return;
            }
            #[cfg(not(target_os = "macos"))]
            panic!("creating raw-byte filename failed unexpectedly: {error}");
        }
        let plan = JobPlan::build(&src, &dst).unwrap();
        assert_eq!(plan.entries[0].relative, name.as_bytes());
    }

    #[test]
    fn traversal_and_malformed_relative_names_are_rejected() {
        for name in [
            b"".as_slice(),
            b".",
            b"..",
            b"a/../b",
            b"a/./b",
            b"/abs",
            b"a//b",
            b"a/",
            b"a\0b",
        ] {
            assert!(validate_relative(name).is_err(), "{name:?}");
        }
        assert!(validate_relative(&vec![b'x'; MAX_PATH_BYTES + 1]).is_err());
        assert!(validate_relative(b"ok with spaces/\xff").is_ok());
    }

    #[test]
    fn nested_or_overlapping_roots_are_rejected() {
        let (_tmp, src, dst) = roots();
        assert!(JobPlan::build(&src, &src).is_err());
        assert!(JobPlan::build(&src, &src.join("inside")).is_err());
        assert!(JobPlan::build(&src, src.parent().unwrap()).is_err());
        assert!(JobPlan::build(Path::new("../relative"), &dst).is_err());
        assert!(JobPlan::build(&src, &dst.join("..")).is_err());
    }

    #[test]
    fn symlinked_source_entries_and_target_paths_are_rejected() {
        let (_tmp, src, dst) = roots();
        symlink("/etc", src.join("link")).unwrap();
        assert!(JobPlan::build(&src, &dst).is_err());
        fs::remove_file(src.join("link")).unwrap();
        fs::create_dir(&dst).unwrap();
        fs::create_dir(src.join("folder")).unwrap();
        symlink("/tmp", dst.join("folder")).unwrap();
        assert!(JobPlan::build(&src, &dst).is_err());
        assert!(
            dst.join("folder")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(JobPlan::build(&src, &src.join("link")).is_err());
        fs::remove_file(dst.join("folder")).unwrap();
        fs::write(src.join("regular"), b"source data").unwrap();
        symlink("/etc/passwd", dst.join("regular")).unwrap();
        assert!(JobPlan::build(&src, &dst).is_err());
        assert!(
            dst.join("regular")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn source_and_target_hardlinks_are_rejected() {
        let (_tmp, src, dst) = roots();
        fs::write(src.join("one"), b"x").unwrap();
        if let Err(error) = fs::hard_link(src.join("one"), src.join("two")) {
            // Some Android/Termux filesystems forbid hardlink creation.
            assert!(matches!(
                error.kind(),
                ErrorKind::PermissionDenied | ErrorKind::Unsupported
            ));
            return;
        }
        assert!(JobPlan::build(&src, &dst).is_err());
        fs::remove_file(src.join("two")).unwrap();
        fs::create_dir(&dst).unwrap();
        fs::write(dst.join("other"), b"y").unwrap();
        if let Err(error) = fs::hard_link(dst.join("other"), dst.join("one")) {
            assert!(matches!(
                error.kind(),
                ErrorKind::PermissionDenied | ErrorKind::Unsupported
            ));
            return;
        }
        assert!(JobPlan::build(&src, &dst).is_err());
    }

    #[test]
    fn special_entries_are_rejected_without_modifying_them() {
        let (_tmp, src, dst) = roots();
        let sock = src.join("socket");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert!(JobPlan::build(&src, &dst).is_err());
        assert!(sock.exists());
        assert!(!dst.exists(), "plan validation must never create output");
    }

    #[test]
    fn root_symlink_and_non_dir_parent_are_rejected() {
        let (_tmp, src, dst) = roots();
        let link = src.parent().unwrap().join("source-link");
        symlink(&src, &link).unwrap();
        assert!(JobPlan::build(&link, &dst).is_err());
        let bad = src.parent().unwrap().join("bad");
        fs::write(&bad, b"x").unwrap();
        assert!(JobPlan::build(&src, &bad.join("x")).is_err());
    }

    #[test]
    fn changing_file_metadata_invalidates_the_fingerprint() {
        let (_tmp, src, dst) = roots();
        fs::write(src.join("data"), b"123").unwrap();
        let first = JobPlan::build(&src, &dst).unwrap().fingerprint();
        fs::write(src.join("data"), b"123456789").unwrap();
        let second = JobPlan::build(&src, &dst).unwrap().fingerprint();
        assert_ne!(first, second);
    }
}

// Private binary representation of the immutable job plan.
// The checksum detects accidental corruption; it is not authentication.
const PLAN_MAGIC: &[u8] = b"MCH-BATCH-PLAN-V2\n";

struct PlanReader<'a> {
    rest: &'a [u8],
}

impl<'a> PlanReader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        ensure!(self.rest.len() >= length, "truncated plan");
        let (head, tail) = self.rest.split_at(length);
        self.rest = tail;
        Ok(head)
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }

    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into()?))
    }

    fn bytes(&mut self) -> Result<Vec<u8>> {
        let length = usize::try_from(self.u64()?).context("plan length overflows usize")?;
        ensure!(length <= MAX_PATH_BYTES, "plan path too long");
        Ok(self.take(length)?.to_vec())
    }
}

fn wire_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
}

impl JobPlan {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        ensure!(self.entries.len() <= MAX_ENTRIES, "too many plan entries");
        let mut out = Vec::new();
        out.extend_from_slice(PLAN_MAGIC);
        wire_bytes(&mut out, &self.source_root);
        wire_bytes(&mut out, &self.target_root);
        out.extend_from_slice(&self.source_identity.0.to_le_bytes());
        out.extend_from_slice(&self.source_identity.1.to_le_bytes());
        match self.target_identity {
            None => out.push(0),
            Some((device, inode)) => {
                out.push(1);
                out.extend_from_slice(&device.to_le_bytes());
                out.extend_from_slice(&inode.to_le_bytes());
            }
        }
        out.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for item in &self.entries {
            wire_bytes(&mut out, &item.relative);
            out.push(item.kind.as_byte());
            out.extend_from_slice(&item.device.to_le_bytes());
            out.extend_from_slice(&item.inode.to_le_bytes());
            out.extend_from_slice(&item.size.to_le_bytes());
            out.extend_from_slice(&item.mtime_sec.to_le_bytes());
            out.extend_from_slice(&item.mtime_nsec.to_le_bytes());
            ensure!(out.len() <= MAX_PLAN_BYTES, "encoded plan too large");
        }
        let digest = blake3::hash(&out);
        out.extend_from_slice(digest.as_bytes());
        ensure!(out.len() <= MAX_PLAN_BYTES, "encoded plan too large");
        Ok(out)
    }

    pub(crate) fn decode(input: &[u8]) -> Result<Self> {
        ensure!(input.len() <= MAX_PLAN_BYTES, "plan size limit exceeded");
        ensure!(input.len() >= PLAN_MAGIC.len() + 32, "plan is too short");
        let (body, digest) = input.split_at(input.len() - 32);
        ensure!(
            blake3::hash(body).as_bytes() == digest,
            "plan checksum mismatch"
        );
        let mut reader = PlanReader { rest: body };
        ensure!(
            reader.take(PLAN_MAGIC.len())? == PLAN_MAGIC,
            "plan format mismatch"
        );
        let source_root = reader.bytes()?;
        let target_root = reader.bytes()?;
        let source_identity = (reader.u64()?, reader.u64()?);
        let target_identity = match reader.take(1)?[0] {
            0 => None,
            1 => Some((reader.u64()?, reader.u64()?)),
            _ => bail!("invalid target root identity marker"),
        };
        use std::os::unix::ffi::OsStringExt;
        let source = PathBuf::from(std::ffi::OsString::from_vec(source_root.clone()));
        let target = PathBuf::from(std::ffi::OsString::from_vec(target_root.clone()));
        ensure!(
            validate_absolute(&source)?.as_os_str().as_bytes() == source_root,
            "source root not canonical"
        );
        ensure!(
            validate_absolute(&target)?.as_os_str().as_bytes() == target_root,
            "target root not canonical"
        );
        ensure!(
            !source.starts_with(&target) && !target.starts_with(&source),
            "overlapping plan roots"
        );
        let count = usize::try_from(reader.u64()?).context("plan count overflow")?;
        ensure!(count <= MAX_ENTRIES, "too many plan entries");
        let mut entries = Vec::with_capacity(count);
        let mut previous: Option<Vec<u8>> = None;
        for _ in 0..count {
            let relative = reader.bytes()?;
            validate_relative(&relative)?;
            if let Some(ref earlier) = previous {
                ensure!(earlier < &relative, "duplicate or unordered plan entries");
            }
            let kind = match reader.take(1)?[0] {
                1 => EntryKind::Directory,
                2 => EntryKind::RegularFile,
                _ => bail!("unknown entry kind"),
            };
            let device = reader.u64()?;
            let inode = reader.u64()?;
            let size = reader.u64()?;
            let mtime_sec = reader.i64()?;
            let mtime_nsec = reader.i64()?;
            ensure!(
                (0..1_000_000_000).contains(&mtime_nsec),
                "invalid timestamp"
            );
            ensure!(
                kind != EntryKind::Directory || size == 0,
                "directory has file size"
            );
            previous = Some(relative.clone());
            entries.push(Entry {
                relative,
                kind,
                device,
                inode,
                size,
                mtime_sec,
                mtime_nsec,
            });
        }
        ensure!(reader.rest.is_empty(), "trailing bytes in plan");
        let file_indices = Self::index_files(&entries);
        Ok(Self {
            source_root,
            target_root,
            source_identity,
            target_identity,
            entries,
            file_indices,
        })
    }

    // Stable journal indices enumerate regular files only; directories do not
    // consume an index. This is necessary for journal validation and rehashing.
    pub(crate) fn regular_entry(&self, index: u64) -> Result<PlannedFile<'_>> {
        let index = usize::try_from(index).context("file index overflow")?;
        let entry_index = self
            .file_indices
            .get(index)
            .context("file index outside immutable plan")?;
        let item = &self.entries[*entry_index];
        Ok(PlannedFile {
            relative: &item.relative,
            device: item.device,
            inode: item.inode,
            size: item.size,
            mtime_sec: item.mtime_sec,
            mtime_nsec: item.mtime_nsec,
        })
    }

    pub(crate) fn roots(&self) -> (&[u8], &[u8]) {
        (&self.source_root, &self.target_root)
    }

    pub(crate) fn root_identities(&self) -> ((u64, u64), Option<(u64, u64)>) {
        (self.source_identity, self.target_identity)
    }

    // A non-root source ancestor is checked by inode, not pathname alone.
    pub(crate) fn planned_directory_inode(&self, relative: &[u8]) -> Result<(u64, u64)> {
        // The immutable plan is sorted by byte-exact relative path.
        // Avoid a linear scan for every file under a shared ancestor.
        let index = self
            .entries
            .binary_search_by(|entry| entry.relative.as_slice().cmp(relative))
            .map_err(|_| anyhow::anyhow!("source ancestor missing from immutable plan"))?;
        let item = &self.entries[index];
        ensure!(
            item.kind == EntryKind::Directory,
            "source ancestor is not a directory"
        );
        Ok((item.device, item.inode))
    }

    pub(crate) fn directory_names(&self) -> Vec<&[u8]> {
        self.entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::Directory)
            .map(|entry| entry.relative.as_slice())
            .collect()
    }

    pub(crate) fn regular_files(&self) -> u64 {
        self.file_indices.len() as u64
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;
    use std::fs;

    fn built() -> JobPlan {
        let root = tempfile::tempdir().unwrap();
        let physical = fs::canonicalize(root.path()).unwrap();
        let source = physical.join("source");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("empty")).unwrap();
        fs::write(source.join("alpha"), b"test").unwrap();
        JobPlan::build(&source, &physical.join("target")).unwrap()
    }

    #[test]
    fn versioned_plan_round_trip_and_file_count() {
        let plan = built();
        let recovered = JobPlan::decode(&plan.encode().unwrap()).unwrap();
        assert_eq!(recovered.fingerprint(), plan.fingerprint());
        assert_eq!(recovered.regular_files(), 1);
        assert_eq!(recovered.entries.len(), 2);
    }

    #[test]
    fn indexed_regular_file_lookup_is_stable_across_many_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let src = root.join("src");
        fs::create_dir(&src).unwrap();
        fs::create_dir(src.join("empty")).unwrap();
        for n in 0..300 {
            fs::write(src.join(format!("{n:04}.bin")), [n as u8]).unwrap();
        }
        let plan = JobPlan::build(&src, &root.join("target")).unwrap();
        assert_eq!(plan.regular_files(), 300);
        for n in 0..300_u64 {
            assert_eq!(
                plan.regular_entry(n).unwrap().relative,
                format!("{n:04}.bin").as_bytes()
            );
        }
        assert!(plan.regular_entry(300).is_err());
        let decoded = JobPlan::decode(&plan.encode().unwrap()).unwrap();
        assert_eq!(decoded.regular_files(), 300);
        assert_eq!(decoded.regular_entry(299).unwrap().relative, b"0299.bin");
    }

    #[test]
    fn all_truncations_and_mutations_fail_closed() {
        let original = built().encode().unwrap();
        for end in 0..original.len() {
            assert!(
                JobPlan::decode(&original[..end]).is_err(),
                "accepted {end} bytes"
            );
        }
        for offset in 0..original.len() {
            let mut changed = original.clone();
            changed[offset] ^= 0xff;
            assert!(
                JobPlan::decode(&changed).is_err(),
                "accepted changed byte {offset}"
            );
        }
        let mut extra = original;
        extra.push(0);
        assert!(JobPlan::decode(&extra).is_err());
    }

    #[test]
    fn invalid_path_and_record_semantics_are_rejected_even_with_valid_checksum() {
        let good = built().encode().unwrap();
        // Restore a valid checksum after changing semantics to rule out checksum-only validation.
        let mutate = |offset: usize, value: u8| {
            let mut data = good.clone();
            data[offset] = value;
            let digest_start = data.len() - 32;
            let digest = blake3::hash(&data[..digest_start]);
            data[digest_start..].copy_from_slice(digest.as_bytes());
            data
        };
        assert!(JobPlan::decode(&mutate(0, b'X')).is_err());
        // The first encoded path is an absolute source; inject NUL into it.
        let source_start = PLAN_MAGIC.len() + 8;
        assert!(JobPlan::decode(&mutate(source_start, 0)).is_err());
    }
}
