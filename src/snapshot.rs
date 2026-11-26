// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};

fn check_boundaries(root: &Path, frozen: bool) -> Result<()> {
    let device = fs::metadata(root)?.dev();
    let mount = crate::linux_tree::mount_id(root)?;
    let mut dirs = vec![root.to_owned()];
    while let Some(dir) = dirs.pop() {
        for item in fs::read_dir(dir)? {
            let path = item?.path();
            let meta = fs::symlink_metadata(&path)?;
            ensure!(
                meta.dev() == device && crate::linux_tree::mount_id(&path)? == mount,
                "mounted filesystem in snapshot source: {}",
                path.display()
            );
            if meta.is_dir() {
                ensure!(
                    meta.ino() != 256 && (!frozen || meta.ino() != 2),
                    "nested subvolume in snapshot source: {}",
                    path.display()
                );
                dirs.push(path);
            }
        }
    }
    Ok(())
}

pub(crate) fn capture(
    source: &Path,
    parent: &Path,
    destination: &Path,
    state: Option<&Path>,
) -> Result<PathBuf> {
    ensure!(
        fs::symlink_metadata(source)?.is_dir() && fs::symlink_metadata(parent)?.is_dir(),
        "source and snapshot parent must be real directories"
    );
    let source = fs::canonicalize(source)?;
    let parent = fs::canonicalize(parent)?;
    let name = source
        .file_name()
        .context("cannot snapshot the filesystem root")?;
    let result = parent.join(name);
    let destination = crate::engine::intended_path(destination)?;
    ensure!(
        !parent.starts_with(&source)
            && !source.starts_with(&destination)
            && !destination.starts_with(&source)
            && !result.starts_with(&destination)
            && !destination.starts_with(&result),
        "snapshot, source and destination must have distinct trees"
    );
    ensure!(
        fs::symlink_metadata(&result).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "snapshot path exists or is inaccessible: {}",
        result.display()
    );
    if let Some(state) = state {
        let state = fs::canonicalize(state).context("resolve private job state before snapshot")?;
        for tree in [&source, &destination, &result] {
            ensure!(
                !state.starts_with(tree) && !tree.starts_with(&state),
                "private job state overlaps source, snapshot or destination"
            );
        }
    }
    check_boundaries(&source, false)?;
    let status = Command::new("btrfs")
        .args(["subvolume", "snapshot", "-r"])
        .arg(&source)
        .arg(&parent)
        .status()
        .context("start btrfs-progs")?;
    ensure!(
        status.success(),
        "could not create a read-only Btrfs snapshot of {}",
        source.display()
    );
    // The named snapshot is intentionally retained, including on a subsequent copy error.
    let property = Command::new("btrfs")
        .args(["property", "get", "-ts"])
        .arg(&result)
        .arg("ro")
        .output()?;
    ensure!(
        property.status.success() && property.stdout == b"ro=true\n",
        "snapshot is not read-only: {}",
        result.display()
    );
    check_boundaries(&result, true)?;
    Ok(result)
}
