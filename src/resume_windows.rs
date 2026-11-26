// SPDX-License-Identifier: AGPL-3.0-or-later
use super::transfer::{transfer, verify_prefix};
use crate::Cli;
use anyhow::{Context, Result, ensure};
use filetime::FileTime;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::null_mut;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::WindowsProgramming::{DRIVE_FIXED, DRIVE_REMOVABLE};

#[path = "resume_windows_dir.rs"]
mod directory;
#[path = "resume_windows_state.rs"]
mod state;
pub(crate) use directory::run as copy_directory;
use state::{PrivateState, checked, wide};

pub(crate) fn validate_windows_paths(source: &Path, destination: &Path) -> Result<()> {
    validate_path(source)?;
    validate_path(destination)?;
    let meta = fs::symlink_metadata(source).context("stat Windows resume source")?;
    ensure!(
        meta.is_file() && meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "Windows --resume requires one regular source file"
    );
    Ok(())
}

fn validate_components(path: &Path) -> Result<()> {
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => ensure!(
                matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
                    && path.has_root(),
                "Windows --resume requires a local drive path"
            ),
            Component::Normal(name) => {
                let text = name.to_string_lossy();
                let base = text
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .trim_end()
                    .to_ascii_uppercase();
                let numbered_device = base
                    .strip_prefix("COM")
                    .or_else(|| base.strip_prefix("LPT"))
                    .is_some_and(|s| {
                        matches!(
                            s,
                            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                        )
                    });
                ensure!(
                    !text.contains(':')
                        && !text.ends_with([' ', '.'])
                        && !numbered_device
                        && !matches!(
                            base.as_str(),
                            "CON" | "NUL" | "AUX" | "PRN" | "CONIN$" | "CONOUT$"
                        )
                        && !text.to_ascii_lowercase().starts_with(".mch-winresume-"),
                    "Windows --resume requires ordinary file names"
                );
            }
            Component::ParentDir => {
                anyhow::bail!("Windows --resume requires paths without parent traversal")
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_path(path: &Path) -> Result<()> {
    validate_components(path)?;
    let absolute = std::path::absolute(path)?;
    let root = absolute.ancestors().last().context("missing drive root")?;
    let root = wide(root.as_os_str())?;
    ensure!(
        matches!(
            unsafe { GetDriveTypeW(root.as_ptr()) },
            DRIVE_FIXED | DRIVE_REMOVABLE
        ),
        "Windows --resume requires local drives"
    );
    Ok(())
}

// Hold each directory without delete sharing, from its drive root down.
// A retry never follows a junction or depends on a parent that changed names.
fn pin_directories(parent: &Path) -> Result<Vec<File>> {
    let mut held = Vec::new();
    for path in parent.ancestors().collect::<Vec<_>>().into_iter().rev() {
        held.push(open_directory(path)?);
    }
    Ok(held)
}

fn open_directory(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("open existing resume directory {}", path.display()))?;
    let attr = file.metadata()?.file_attributes();
    ensure!(
        attr & FILE_ATTRIBUTE_DIRECTORY != 0 && attr & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "resume directory is a reparse point or not a directory"
    );
    Ok(file)
}

fn require_ntfs(file: &File) -> Result<()> {
    let mut name = [0u16; 32];
    checked(unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    })?;
    let end = name
        .iter()
        .position(|&word| word == 0)
        .unwrap_or(name.len());
    ensure!(
        name[..end].iter().copied().eq("NTFS".encode_utf16()),
        "Windows --resume requires local NTFS"
    );
    Ok(())
}

fn state_names(source: &Path, target: &Path) -> Result<(PathBuf, PathBuf)> {
    let mut key = blake3::Hasher::new();
    key.update(b"MCH-winresume-1\0");
    for path in [source, target] {
        let words: Vec<_> = path.as_os_str().encode_wide().collect();
        key.update(&(words.len() as u64).to_le_bytes());
        for word in words {
            key.update(&word.to_le_bytes());
        }
    }
    let parent = target.parent().context("missing target directory")?;
    let stem = format!(".mch-winresume-{}", key.finalize().to_hex());
    Ok((
        parent.join(format!("{stem}.meta")),
        parent.join(format!("{stem}.part")),
    ))
}

fn file_id(source: &File) -> Result<[u8; 24]> {
    let mut id = FILE_ID_INFO::default();
    checked(unsafe {
        GetFileInformationByHandleEx(
            source.as_raw_handle(),
            FileIdInfo,
            (&raw mut id).cast(),
            std::mem::size_of_val(&id) as u32,
        )
    })?;
    ensure!(
        id.FileId.Identifier != [0; 16],
        "source file has no stable ID"
    );
    let mut key = [0u8; 24];
    key[..8].copy_from_slice(&id.VolumeSerialNumber.to_le_bytes());
    key[8..].copy_from_slice(&id.FileId.Identifier);
    Ok(key)
}

fn fingerprint(source: &File) -> Result<String> {
    let id = file_id(source)?;
    let meta = source.metadata()?;
    Ok(format!(
        "MCH-WINRESUME-1\n{}:{}:{}:{}\n",
        u64::from_le_bytes(id[..8].try_into()?),
        hex::encode(&id[8..]),
        meta.len(),
        meta.last_write_time()
    ))
}

fn complete_stage(cli: &Cli, src: &mut File, stage: &mut File, identity: &str) -> Result<String> {
    let metadata = src.metadata()?;
    let reused = stage.metadata()?.len();
    ensure!(
        reused <= metadata.len(),
        "resume staging is larger than source"
    );
    verify_prefix(src, stage, reused)?;
    if !cli.quiet {
        println!("RESUME: {reused} existing bytes compared and verified against source");
    }
    transfer(cli, src, stage, reused, metadata.len())?;
    src.rewind()?;
    stage.rewind()?;
    let digest = crate::hashing::hash_open_file(src, cli.hash, None)?;
    ensure!(
        stage.metadata()?.len() == metadata.len()
            && digest == crate::hashing::hash_open_file(stage, cli.hash, None)?,
        "Windows resume full-file verification failed"
    );
    ensure!(
        fingerprint(src)? == identity,
        "Windows resume source changed"
    );
    Ok(digest)
}

pub(crate) fn copy(
    cli: &Cli,
    source: &Path,
    destination: &Path,
    times: Option<(FileTime, FileTime)>,
    _overwrite_target: Option<&crate::engine::OverwriteTarget>,
) -> Result<()> {
    let _source_dirs = pin_directories(source.parent().context("missing source parent")?)?;
    let parent = destination.parent().context("missing target parent")?;
    let target_dirs = pin_directories(parent)?;
    require_ntfs(
        target_dirs
            .last()
            .context("missing target directory handle")?,
    )?;
    let mut src = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(source)
        .context("open read-locked resume source")?;
    let metadata = src.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
            && unsafe { GetFileType(src.as_raw_handle()) } == FILE_TYPE_DISK,
        "expected an ordinary Windows source file"
    );
    require_ntfs(&src)?;
    let source_path = fs::canonicalize(source)?;
    let target =
        fs::canonicalize(parent)?.join(destination.file_name().context("missing target name")?);
    crate::engine::check_destination_file(source, destination, false)?;
    if cli.dry_run {
        cli.report(
            &format!(
                "RESUME DRY RUN {} -> {}",
                source.display(),
                destination.display()
            ),
            true,
        );
        return Ok(());
    }
    let (manifest_path, part) = state_names(&source_path, &target)?;
    let security = PrivateState::new()?;
    let (mut manifest, existing) = security.open(&manifest_path, OPEN_ALWAYS)?;
    let identity = fingerprint(&src)?;
    let (mut stage, _) = if existing {
        ensure!(
            manifest.metadata()?.len() == identity.len() as u64,
            "incomplete or changed Windows resume manifest"
        );
        let mut saved = Vec::new();
        manifest.read_to_end(&mut saved)?;
        ensure!(
            saved == identity.as_bytes(),
            "Windows resume source identity, size or modification time changed"
        );
        security.open(&part, OPEN_EXISTING)?
    } else {
        let stage = match security.open(&part, CREATE_NEW) {
            Ok(stage) => stage,
            Err(error) => {
                state::remove_on_close(&manifest)?;
                return Err(error).context("could not create a new Windows part file");
            }
        };
        manifest.write_all(identity.as_bytes())?;
        manifest.sync_all()?;
        stage
    };
    complete_stage(cli, &mut src, &mut stage, &identity)?;
    if let Some((atime, mtime)) = times {
        filetime::set_file_handle_times(&stage, Some(atime), Some(mtime))?;
    }
    stage.sync_all()?;
    state::publish(&stage, &target)
        .context("publish verified Windows file without replacing any existing target")?;
    state::remove_on_close(&manifest).context("remove completed Windows resume manifest")?;
    if metadata.permissions().readonly() {
        stage.set_permissions(metadata.permissions())?;
    }
    cli.report(
        &format!(
            "RESUME {} VERIFIED {} -> {}",
            cli.hash.label(),
            source.display(),
            destination.display()
        ),
        true,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::io::Write;
    use tempfile::TempDir;

    fn job() -> (TempDir, PathBuf, PathBuf, Cli) {
        let temp = tempfile::tempdir().unwrap();
        let src = temp.path().join("original");
        let dst = temp.path().join("copied");
        fs::write(&src, b"first and last block").unwrap();
        let cli = Cli::parse_from([
            "mch",
            "--resume",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ]);
        (temp, src, dst, cli)
    }

    fn seed(src: &Path, dst: &Path, prefix: &[u8]) -> (PathBuf, PathBuf) {
        let target = fs::canonicalize(dst.parent().unwrap())
            .unwrap()
            .join(dst.file_name().unwrap());
        let paths = state_names(&fs::canonicalize(src).unwrap(), &target).unwrap();
        let security = PrivateState::new().unwrap();
        let (mut meta, _) = security.open(&paths.0, CREATE_NEW).unwrap();
        meta.write_all(fingerprint(&File::open(src).unwrap()).unwrap().as_bytes())
            .unwrap();
        let (mut part, _) = security.open(&paths.1, CREATE_NEW).unwrap();
        part.write_all(prefix).unwrap();
        paths
    }

    #[test]
    fn verified_partial_is_completed_and_state_removed() {
        let (_dir, src, dst, cli) = job();
        let (meta, part) = seed(&src, &dst, b"first ");
        copy(&cli, &src, &dst, None, None).unwrap();
        assert_eq!(fs::read(&src).unwrap(), fs::read(&dst).unwrap());
        assert!(!meta.exists() && !part.exists());
    }

    #[test]
    fn corrupt_or_oversized_partial_preserves_both_inputs() {
        for prefix in [
            b"First ".as_slice(),
            b"the entire stage is far too long".as_slice(),
        ] {
            let (_dir, src, dst, cli) = job();
            let (_, part) = seed(&src, &dst, prefix);
            assert!(copy(&cli, &src, &dst, None, None).is_err());
            assert!(!dst.exists());
            assert_eq!(fs::read(&part).unwrap(), prefix);
            assert_eq!(fs::read(&src).unwrap(), b"first and last block");
        }
    }

    #[test]
    fn locked_or_hardlinked_state_is_refused() {
        let (dir, src, dst, cli) = job();
        let (meta, part) = seed(&src, &dst, b"first");
        let lock = PrivateState::new()
            .unwrap()
            .open(&meta, OPEN_EXISTING)
            .unwrap();
        assert!(copy(&cli, &src, &dst, None, None).is_err());
        drop(lock);
        fs::hard_link(&part, dir.path().join("second-name")).unwrap();
        assert!(copy(&cli, &src, &dst, None, None).is_err());
        assert_eq!(fs::read(&part).unwrap(), b"first");
        assert!(!dst.exists());
    }

    #[test]
    fn inherited_acl_or_replaced_source_is_refused() {
        let (dir, src, dst, cli) = job();
        let (_, part) = seed(&src, &dst, b"first");
        fs::rename(&src, dir.path().join("old")).unwrap();
        fs::write(&src, b"first and last block").unwrap();
        assert!(copy(&cli, &src, &dst, None, None).is_err());
        fs::remove_file(&part).unwrap();
        fs::write(&part, b"first").unwrap();
        assert!(
            PrivateState::new()
                .unwrap()
                .open(&part, OPEN_EXISTING)
                .is_err()
        );
        assert!(!dst.exists());
    }

    #[test]
    fn handle_publication_refuses_a_newly_occupied_target() {
        let (_dir, src, dst, _cli) = job();
        let (_, part) = seed(&src, &dst, b"first");
        let (file, _) = PrivateState::new()
            .unwrap()
            .open(&part, OPEN_EXISTING)
            .unwrap();
        fs::write(&dst, b"other copy").unwrap();
        assert!(state::publish(&file, &dst).is_err());
        assert_eq!(fs::read(&dst).unwrap(), b"other copy");
    }
}
