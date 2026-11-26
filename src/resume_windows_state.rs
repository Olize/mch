// SPDX-License-Identifier: AGPL-3.0-or-later
//! Create state with a protected current-user DACL and validate existing state by handle.
use anyhow::{Context, Result, ensure};
use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io;
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

pub(super) fn wide(value: &OsStr) -> Result<Vec<u16>> {
    let mut words: Vec<_> = value.encode_wide().collect();
    ensure!(!words.contains(&0), "embedded NUL in Windows path");
    words.push(0);
    Ok(words)
}

pub(super) fn checked(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) struct PrivateState {
    token_user: Vec<usize>,
    descriptor: Local,
}

impl PrivateState {
    pub(super) fn new() -> Result<Self> {
        let mut token = null_mut();
        checked(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut bytes = 0;
        unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut bytes) };
        ensure!(
            bytes as usize >= size_of::<TOKEN_USER>(),
            "missing Windows token user"
        );
        let mut user = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
        checked(unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                user.as_mut_ptr().cast(),
                bytes,
                &mut bytes,
            )
        })?;
        let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut sid_text = null_mut();
        checked(unsafe { ConvertSidToStringSidW(sid, &mut sid_text) })?;
        let _sid_text = Local(sid_text.cast());
        // The OS allocated a terminated SID string containing ASCII characters.
        let mut length = 0;
        unsafe {
            while *sid_text.add(length) != 0 {
                length += 1
            }
        };
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, length) })?;
        let sddl = wide(OsStr::new(&format!("O:{sid}D:P(A;;FA;;;{sid})")))?;
        let mut descriptor = null_mut();
        checked(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        })?;
        Ok(Self {
            token_user: user,
            descriptor: Local(descriptor),
        })
    }

    fn verify_owner_access(&self, file: &File) -> Result<()> {
        let (mut owner, mut acl, mut descriptor) = (null_mut(), null_mut(), null_mut());
        let error = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        };
        if error != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(error as i32).into());
        }
        let descriptor = Local(descriptor);
        let (mut control, mut revision) = (0, 0);
        checked(unsafe {
            GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision)
        })?;
        let current = unsafe { (*self.token_user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        ensure!(
            !owner.is_null()
                && unsafe { EqualSid(owner, current) } != 0
                && control & SE_DACL_PROTECTED != 0
                && !acl.is_null()
                && unsafe { (*acl).AceCount } == 1,
            "resume state must be owned by this user with a protected single-user DACL"
        );
        let mut entry = null_mut();
        checked(unsafe { GetAce(acl, 0, &mut entry) })?;
        let ace = entry.cast::<ACCESS_ALLOWED_ACE>();
        // ACCESS_ALLOWED_ACE_TYPE is zero. Check the header before interpreting the body.
        let header = unsafe { &*entry.cast::<ACE_HEADER>() };
        ensure!(
            header.AceType == 0
                && header.AceFlags == 0
                && usize::from(header.AceSize) >= size_of::<ACCESS_ALLOWED_ACE>(),
            "unexpected resume DACL entry"
        );
        ensure!(
            unsafe {
                (*ace).Mask == FILE_ALL_ACCESS
                    && EqualSid((&raw mut (*ace).SidStart).cast(), current) != 0
            },
            "resume state grants access to an unexpected principal"
        );
        Ok(())
    }

    pub(super) fn directory(
        &self,
        path: &Path,
        create: bool,
        extra_access: FILE_ACCESS_RIGHTS,
    ) -> Result<File> {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        if create {
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.descriptor.0,
                bInheritHandle: 0,
            };
            let name = wide(path.as_os_str())?;
            checked(unsafe { CreateDirectoryW(name.as_ptr(), &attributes) })?;
        }
        let file = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL | extra_access | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let attr = file.metadata()?.file_attributes();
        ensure!(
            attr & FILE_ATTRIBUTE_DIRECTORY != 0 && attr & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "expected an ordinary staging directory"
        );
        self.verify_owner_access(&file)?;
        Ok(file)
    }

    pub(super) fn open(
        &self,
        path: &Path,
        creation: FILE_CREATION_DISPOSITION,
    ) -> Result<(File, bool)> {
        let path_w = wide(path.as_os_str())?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor.0,
            bInheritHandle: 0,
        };
        let raw = unsafe {
            CreateFileW(
                path_w.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | DELETE,
                0,
                &attributes,
                creation,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        let last = unsafe { GetLastError() };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::from_raw_os_error(last as i32))
                .with_context(|| format!("open exclusive resume state {}", path.display()));
        }
        let file = unsafe { File::from_raw_handle(raw) };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        checked(unsafe { GetFileInformationByHandle(raw, &mut info) })?;
        ensure!(
            unsafe { GetFileType(raw) } == FILE_TYPE_DISK
                && info.dwFileAttributes
                    & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                    == 0
                && info.nNumberOfLinks == 1,
            "resume state must be an ordinary single-link file"
        );
        self.verify_owner_access(&file)?;
        Ok((
            file,
            creation == OPEN_ALWAYS && last == ERROR_ALREADY_EXISTS,
        ))
    }
}

pub(super) fn remove_on_close(file: &File) -> Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    checked(unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&raw const info).cast(),
            size_of_val(&info) as u32,
        )
    })?;
    Ok(())
}

pub(super) fn publish(file: &File, target: &Path) -> Result<()> {
    let name = wide(target.as_os_str())?;
    let bytes = (name.len() - 1) * size_of::<u16>();
    let length = (std::mem::offset_of!(FILE_RENAME_INFO, FileName) + bytes + size_of::<u16>())
        .max(size_of::<FILE_RENAME_INFO>());
    let mut buffer = vec![0usize; length.div_ceil(size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // Zero-initialization selects no replacement and a fully qualified destination.
    unsafe {
        (*info).FileNameLength = bytes.try_into()?;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            (&raw mut (*info).FileName).cast::<u16>(),
            name.len(),
        );
        checked(SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            info.cast(),
            length.try_into()?,
        ))?;
    }
    Ok(())
}
