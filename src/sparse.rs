// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::{Context, Result};
use std::{
    fs::File,
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
};

/// Skip zero-filled runs in a new private staging file, including trailing holes.
pub(crate) fn copy(
    src: &mut File,
    dst: &mut File,
    progress: Option<&crate::progress::Progress>,
) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::{IO::DeviceIoControl, Ioctl::FSCTL_SET_SPARSE};
        let mut returned = 0;
        // A null input buffer explicitly marks the new file as sparse on NTFS.
        let ok = unsafe {
            DeviceIoControl(
                dst.as_raw_handle(),
                FSCTL_SET_SPARSE,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error())
                .context("filesystem cannot create a sparse file");
        }
    }
    let mut buffer = vec![0; 64 * 1024];
    let mut length = 0u64;
    loop {
        let n = match src.read(&mut buffer) {
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            result => result.context("read sparse input")?,
        };
        if n == 0 {
            break;
        }
        if buffer[..n].iter().all(|&b| b == 0) {
            dst.seek(SeekFrom::Current(n as i64))?;
        } else {
            dst.write_all(&buffer[..n])?;
        }
        length = length
            .checked_add(n as u64)
            .context("sparse length overflow")?;
        if let Some(p) = progress {
            p.add_bytes(n as u64);
        }
    }
    dst.set_len(length)?;
    Ok(())
}
