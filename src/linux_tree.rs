// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::{Context, Result, ensure};
use std::{ffi::CString, os::unix::ffi::OsStrExt, path::Path};

/// A bind mount may have the same device number as its parent filesystem.
pub(crate) fn mount_id(path: &Path) -> Result<u64> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statx>::zeroed();
    let flags = libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT;
    let rc = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            name.as_ptr(),
            flags,
            libc::STATX_MNT_ID,
            stat.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("inspect mount at {}", path.display()));
    }
    let stat = unsafe { stat.assume_init() };
    ensure!(
        stat.stx_mask & libc::STATX_MNT_ID != 0,
        "kernel did not report mount identity"
    );
    Ok(stat.stx_mnt_id)
}
