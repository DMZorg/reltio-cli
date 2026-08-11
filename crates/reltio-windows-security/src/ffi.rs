//! Audited Win32 boundary.
//!
//! Every raw handle conversion, Windows API call, and pointer dereference for
//! this crate lives here. Public callers receive only owned Rust values and
//! path-redacted typed errors.

use std::ffi::c_void;
use std::fmt;
use std::fs::File;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GENERIC_ALL,
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
#[cfg(test)]
use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, CopySid,
    CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetSecurityDescriptorOwner, GetTokenInformation, INHERIT_ONLY_ACE, IsValidAcl,
    IsValidSecurityDescriptor, IsValidSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PRESENT, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    SECURITY_MAX_SID_SIZE, SID, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
#[cfg(test)]
use windows_sys::Win32::Security::{
    PROTECTED_DACL_SECURITY_INFORMATION, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_DELETE_CHILD, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_TYPE_DISK, FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_DATA, FILE_WRITE_EA, FileAttributeTagInfo, FileDispositionInfo, FileStandardInfo,
    GetDriveTypeW, GetFileInformationByHandleEx, GetFileType, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_EXISTING, READ_CONTROL, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT, SetFileInformationByHandle, WRITE_DAC, WRITE_OWNER,
};
#[cfg(test)]
use windows_sys::Win32::System::LibraryLoader::GetDllDirectoryW;
use windows_sys::Win32::System::LibraryLoader::SetDllDirectoryW;
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

use crate::{Error, ErrorKind, Result};

const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const COMMON_OPEN_FLAGS: u32 =
    FILE_FLAG_OPEN_REPARSE_POINT | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION;
const UNTRUSTED_ANCESTOR_MUTATION: u32 = DELETE
    | FILE_DELETE_CHILD
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;
const UNTRUSTED_EXECUTABLE_DIRECTORY_MUTATION: u32 =
    UNTRUSTED_ANCESTOR_MUTATION | FILE_WRITE_DATA | FILE_APPEND_DATA;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectKind {
    File,
    Directory,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct HandleInformation {
    pub(crate) directory: bool,
    pub(crate) length: u64,
    pub(crate) number_of_links: u32,
    pub(crate) reparse_point: bool,
}

struct OwnedSid {
    words: Vec<usize>,
    byte_length: u32,
}

impl fmt::Debug for OwnedSid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedSid")
            .field("byte_length", &self.byte_length)
            .finish_non_exhaustive()
    }
}

impl OwnedSid {
    fn copy_from(sid: PSID) -> Result<Self> {
        // SAFETY: Every caller passes a SID pointer returned by Windows while
        // its owning token/security-descriptor buffer is still alive.
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(Error::policy(
                ErrorKind::InsecurePolicy,
                "Windows returned an invalid security identifier",
            ));
        }
        // SAFETY: IsValidSid accepted this still-live SID pointer above.
        let byte_length = unsafe { GetLengthSid(sid) };
        if byte_length == 0 {
            return Err(last_error(
                "failed to measure a Windows security identifier",
            ));
        }
        let word_size = size_of::<usize>();
        let words = usize::try_from(byte_length)
            .unwrap_or(usize::MAX)
            .saturating_add(word_size - 1)
            / word_size;
        let mut storage = vec![0usize; words];
        let destination = storage.as_mut_ptr().cast::<c_void>();
        // SAFETY: `storage` has at least `byte_length` writable bytes and the
        // source remains valid for this call.
        if unsafe { CopySid(byte_length, destination, sid) } == 0 {
            return Err(last_error("failed to copy a Windows security identifier"));
        }
        Ok(Self {
            words: storage,
            byte_length,
        })
    }

    fn as_ptr(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast::<c_void>()
    }

    fn equals(&self, other: PSID) -> bool {
        if other.is_null() {
            return false;
        }
        // SAFETY: Callers provide a pointer into a live Windows-owned buffer.
        if unsafe { IsValidSid(other) } == 0 {
            return false;
        }
        // SAFETY: `self` owns a copied valid SID and Windows validated `other`.
        (unsafe { EqualSid(self.as_ptr(), other) }) != 0
    }
}

struct LocalAllocation {
    pointer: *mut c_void,
}

impl fmt::Debug for LocalAllocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalAllocation(..)")
    }
}

impl LocalAllocation {
    fn new(pointer: *mut c_void, operation: &'static str) -> Result<Self> {
        if pointer.is_null() {
            Err(Error::policy(ErrorKind::InsecurePolicy, operation))
        } else {
            Ok(Self { pointer })
        }
    }
}

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            // SAFETY: This wrapper is created only for allocations documented
            // by Windows as requiring exactly one LocalFree call.
            let _ = unsafe { LocalFree(self.pointer) };
        }
    }
}

#[derive(Debug)]
struct LocalSecurityDescriptor {
    allocation: LocalAllocation,
}

impl LocalSecurityDescriptor {
    fn parse(sddl: &str) -> Result<Self> {
        let wide = wide_text(sddl)?;
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let mut descriptor_size = 0u32;
        // SAFETY: `wide` is NUL-terminated and the output pointers reference
        // initialized writable locals. Windows allocates the returned buffer.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                &mut descriptor_size,
            )
        } == 0
        {
            return Err(last_error(
                "failed to build a private Windows security descriptor",
            ));
        }
        let allocation = LocalAllocation::new(
            descriptor,
            "Windows returned a null private security descriptor",
        )?;
        // SAFETY: The successful conversion returned `descriptor`, which is
        // kept alive by `allocation` through this validation.
        if descriptor_size == 0 || unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
            return Err(Error::policy(
                ErrorKind::InsecurePolicy,
                "Windows returned an invalid private security descriptor",
            ));
        }
        Ok(Self { allocation })
    }

    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.allocation.pointer
    }

    #[cfg(test)]
    fn dacl(&self) -> Result<*mut ACL> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = null_mut();
        // SAFETY: `self` retains the valid descriptor allocation and all output
        // pointers refer to writable locals.
        if unsafe {
            GetSecurityDescriptorDacl(self.as_ptr(), &mut present, &mut dacl, &mut defaulted)
        } == 0
        {
            return Err(last_error(
                "failed to read a Windows security descriptor DACL",
            ));
        }
        if present == 0 || dacl.is_null() {
            return Err(Error::policy(
                ErrorKind::InsecurePolicy,
                "the Windows security descriptor has no concrete DACL",
            ));
        }
        Ok(dacl)
    }
}

/// Process-primary-token identity and immutable creation descriptors.
pub(crate) struct SecurityContext {
    user: OwnedSid,
    local_system: OwnedSid,
    administrators: OwnedSid,
    trusted_installer: OwnedSid,
    file_descriptor: LocalSecurityDescriptor,
    directory_descriptor: LocalSecurityDescriptor,
}

impl fmt::Debug for SecurityContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecurityContext(..)")
    }
}

impl SecurityContext {
    pub(crate) fn new() -> Result<Self> {
        let user = current_process_user()?;
        let user_text = sid_to_string(user.as_ptr())?;
        let local_system = well_known_sid(WinLocalSystemSid)?;
        let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
        let trusted_installer = sid_from_string(TRUSTED_INSTALLER_SID)?;
        let file_descriptor =
            LocalSecurityDescriptor::parse(&format!("O:{user_text}D:P(A;;FA;;;{user_text})"))?;
        let directory_descriptor =
            LocalSecurityDescriptor::parse(&format!("O:{user_text}D:P(A;OICI;FA;;;{user_text})"))?;
        Ok(Self {
            user,
            local_system,
            administrators,
            trusted_installer,
            file_descriptor,
            directory_descriptor,
        })
    }

    fn descriptor(&self, kind: ObjectKind) -> &LocalSecurityDescriptor {
        match kind {
            ObjectKind::File => &self.file_descriptor,
            ObjectKind::Directory => &self.directory_descriptor,
        }
    }

    fn security_attributes(&self, kind: ObjectKind) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: self.descriptor(kind).as_ptr(),
            bInheritHandle: 0,
        }
    }

    fn trusted_ancestor_sid(&self, sid: PSID) -> bool {
        self.user.equals(sid)
            || self.local_system.equals(sid)
            || self.administrators.equals(sid)
            || self.trusted_installer.equals(sid)
    }
}

pub(crate) fn create_private_directory(path: &Path, context: &SecurityContext) -> Result<()> {
    let path = wide_path(path)?;
    let attributes = context.security_attributes(ObjectKind::Directory);
    // SAFETY: The path is NUL-terminated, and the security descriptor owned by
    // `context` outlives this synchronous call.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        return Err(last_create_error(
            "failed to create a private Windows directory",
        ));
    }
    Ok(())
}

pub(crate) fn open_directory(path: &Path) -> Result<File> {
    open_file(
        path,
        FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        COMMON_OPEN_FLAGS | FILE_FLAG_BACKUP_SEMANTICS,
        None,
        "failed to open a Windows directory",
    )
}

pub(crate) fn create_private_temporary(path: &Path, context: &SecurityContext) -> Result<File> {
    open_file(
        path,
        GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        CREATE_NEW,
        COMMON_OPEN_FLAGS | FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        Some(context.security_attributes(ObjectKind::File)),
        "failed to create a private Windows temporary file",
    )
}

pub(crate) fn create_private_lock(path: &Path, context: &SecurityContext) -> Result<File> {
    open_file(
        path,
        GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        CREATE_NEW,
        COMMON_OPEN_FLAGS | FILE_ATTRIBUTE_NORMAL,
        Some(context.security_attributes(ObjectKind::File)),
        "failed to create a private Windows lock",
    )
}

pub(crate) fn open_existing_lock(path: &Path) -> Result<File> {
    open_file(
        path,
        GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        OPEN_EXISTING,
        COMMON_OPEN_FLAGS | FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
        None,
        "failed to open an existing Windows lock",
    )
}

pub(crate) fn open_file_for_read(path: &Path) -> Result<File> {
    open_file(
        path,
        GENERIC_READ | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        COMMON_OPEN_FLAGS | FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
        None,
        "failed to open a bounded Windows file",
    )
}

pub(crate) fn open_file_for_inspection(path: &Path) -> Result<File> {
    open_file(
        path,
        FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        COMMON_OPEN_FLAGS | FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
        None,
        "failed to inspect an existing Windows file",
    )
}

pub(crate) fn open_private_file_for_delete(path: &Path) -> Result<File> {
    open_file(
        path,
        FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        COMMON_OPEN_FLAGS | FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
        None,
        "failed to open a private Windows file for removal",
    )
}

pub(crate) fn require_fixed_local_drive(drive: u8) -> Result<()> {
    let root = [u16::from(drive), u16::from(b':'), u16::from(b'\\'), 0];
    // SAFETY: `root` is a live, NUL-terminated drive-root string.
    require_fixed_drive_type(unsafe { GetDriveTypeW(root.as_ptr()) })
}

pub(crate) fn reset_process_dll_directory() -> Result<()> {
    // SAFETY: A null path is the documented way to restore the default DLL
    // search order and registry-controlled Safe DLL Search Mode.
    if unsafe { SetDllDirectoryW(null()) } == 0 {
        return Err(last_error(
            "failed to restore the default Windows DLL search order",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn set_process_dll_directory_for_test(path: &Path) -> Result<()> {
    let path = wide_path(path)?;
    // SAFETY: The test path is NUL-terminated and remains live for this call.
    if unsafe { SetDllDirectoryW(path.as_ptr()) } == 0 {
        return Err(last_error("failed to set the Windows DLL test directory"));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn process_dll_directory_is_default_for_test() -> bool {
    // SAFETY: A zero-sized query with a null output buffer is documented and
    // returns zero when no custom DLL directory is configured.
    (unsafe { GetDllDirectoryW(0, null_mut()) }) == 0
}

fn require_fixed_drive_type(drive_type: u32) -> Result<()> {
    if drive_type != DRIVE_FIXED {
        return Err(Error::policy(
            ErrorKind::InvalidPath,
            "only fixed local Windows drives are supported",
        ));
    }
    Ok(())
}

fn open_file(
    path: &Path,
    desired_access: u32,
    share_mode: u32,
    creation_disposition: u32,
    flags: u32,
    security_attributes: Option<SECURITY_ATTRIBUTES>,
    operation: &'static str,
) -> Result<File> {
    let path = wide_path(path)?;
    let attributes_pointer = security_attributes.as_ref().map_or(null(), |attributes| {
        std::ptr::from_ref::<SECURITY_ATTRIBUTES>(attributes)
    });
    // SAFETY: `path` and any security descriptor are live and NUL-terminated
    // for this synchronous call; all scalar flags are valid Win32 bitfields.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            desired_access,
            share_mode,
            attributes_pointer,
            creation_disposition,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return if creation_disposition == CREATE_NEW {
            Err(last_create_error(operation))
        } else {
            Err(last_error(operation))
        };
    }
    // SAFETY: CreateFileW returned a fresh owned handle and this is its only owner.
    Ok(unsafe { File::from_raw_handle(handle) })
}

pub(crate) fn handle_information(file: &File) -> Result<HandleInformation> {
    let handle = raw_handle(file);
    // SAFETY: A shared `File` reference guarantees that its HANDLE remains
    // open for the duration of this call.
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err(Error::policy(
            ErrorKind::NotRegularFile,
            "non-disk Windows handles are refused",
        ));
    }

    let mut tag_information = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: The handle is live and the typed output buffer and byte count
    // exactly match FileAttributeTagInfo's documented structure.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            std::ptr::from_mut(&mut tag_information).cast::<c_void>(),
            u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>()).unwrap_or(u32::MAX),
        )
    } == 0
    {
        return Err(last_error("failed to inspect Windows reparse attributes"));
    }

    let mut standard_information = FILE_STANDARD_INFO::default();
    // SAFETY: The handle is live and the typed output buffer and byte count
    // exactly match FileStandardInfo's documented structure.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            std::ptr::from_mut(&mut standard_information).cast::<c_void>(),
            u32::try_from(size_of::<FILE_STANDARD_INFO>()).unwrap_or(u32::MAX),
        )
    } == 0
    {
        return Err(last_error("failed to inspect Windows file metadata"));
    }
    let length = u64::try_from(standard_information.EndOfFile).map_err(|_| {
        Error::policy(
            ErrorKind::NotRegularFile,
            "Windows reported a negative file length",
        )
    })?;

    Ok(HandleInformation {
        directory: standard_information.Directory,
        length,
        number_of_links: standard_information.NumberOfLinks,
        reparse_point: tag_information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || tag_information.ReparseTag != 0,
    })
}

pub(crate) fn inspect_private_policy(
    file: &File,
    context: &SecurityContext,
    kind: ObjectKind,
) -> Result<()> {
    let descriptor = security_descriptor(file)?;
    let parts = descriptor_parts(descriptor.as_ptr())?;
    if !context.user.equals(parts.owner) {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "the private Windows object is not owned by the process user",
        ));
    }
    if parts.control & SE_DACL_PROTECTED == 0 {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "the private Windows object has an unprotected DACL",
        ));
    }

    let ace_count = acl_ace_count(parts.dacl)?;
    if ace_count != 1 {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "the private Windows object has unexpected access entries",
        ));
    }
    let ace = basic_allowed_ace(parts.dacl, 0)?.ok_or_else(|| {
        Error::policy(
            ErrorKind::InsecurePolicy,
            "the private Windows object has a non-allow access entry",
        )
    })?;
    let expected_flags = match kind {
        ObjectKind::File => 0,
        ObjectKind::Directory => {
            u8::try_from(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE).unwrap_or(u8::MAX)
        }
    };
    if !context.user.equals(ace.sid) || ace.mask != FILE_ALL_ACCESS || ace.flags != expected_flags {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "the private Windows object has an unexpected allow entry",
        ));
    }
    Ok(())
}

pub(crate) fn inspect_ancestor_policy(file: &File, context: &SecurityContext) -> Result<()> {
    inspect_ancestor_policy_with_mask(
        file,
        context,
        UNTRUSTED_ANCESTOR_MUTATION,
        "a Windows path ancestor can be replaced by another principal",
    )
}

pub(crate) fn inspect_executable_directory_policy(
    file: &File,
    context: &SecurityContext,
) -> Result<()> {
    inspect_ancestor_policy_with_mask(
        file,
        context,
        UNTRUSTED_EXECUTABLE_DIRECTORY_MUTATION,
        "the Windows executable directory permits dependency planting by another principal",
    )
}

fn inspect_ancestor_policy_with_mask(
    file: &File,
    context: &SecurityContext,
    untrusted_mutation: u32,
    operation: &'static str,
) -> Result<()> {
    let descriptor = security_descriptor(file)?;
    let parts = descriptor_parts(descriptor.as_ptr())?;
    if !context.trusted_ancestor_sid(parts.owner) {
        return Err(Error::policy(
            ErrorKind::UnsafeAncestor,
            "a Windows path ancestor has a non-privileged owner",
        ));
    }

    for index in 0..acl_ace_count(parts.dacl)? {
        let header = ace_header(parts.dacl, index)?;
        let ace_type = u32::from(header.ace_type);
        if matches!(
            ace_type,
            ACCESS_DENIED_ACE_TYPE
                | ACCESS_DENIED_OBJECT_ACE_TYPE
                | ACCESS_DENIED_CALLBACK_ACE_TYPE
                | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
        ) {
            continue;
        }
        if matches!(
            ace_type,
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                | ACCESS_ALLOWED_COMPOUND_ACE_TYPE
                | ACCESS_ALLOWED_OBJECT_ACE_TYPE
        ) {
            return Err(Error::policy(
                ErrorKind::UnsafeAncestor,
                "a Windows path ancestor has an unsupported conditional allow entry",
            ));
        }
        if ace_type != ACCESS_ALLOWED_ACE_TYPE {
            return Err(Error::policy(
                ErrorKind::UnsafeAncestor,
                "a Windows path ancestor has an unknown DACL entry",
            ));
        }
        let ace = basic_allowed_ace(parts.dacl, index)?.ok_or_else(|| {
            Error::policy(
                ErrorKind::UnsafeAncestor,
                "a Windows path ancestor has an invalid allow entry",
            )
        })?;
        if u32::from(ace.flags) & INHERIT_ONLY_ACE != 0 || context.trusted_ancestor_sid(ace.sid) {
            continue;
        }
        if ace.mask & untrusted_mutation != 0 {
            return Err(Error::policy(ErrorKind::UnsafeAncestor, operation));
        }
    }
    Ok(())
}

#[derive(Debug)]
struct DescriptorParts {
    owner: PSID,
    dacl: *mut ACL,
    control: u16,
}

fn descriptor_parts(descriptor: PSECURITY_DESCRIPTOR) -> Result<DescriptorParts> {
    // SAFETY: `descriptor` comes from a live LocalSecurityDescriptor allocation
    // in the caller and remains alive until all returned interior pointers are used.
    if descriptor.is_null() || unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "Windows returned an invalid object security descriptor",
        ));
    }

    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: The descriptor is valid and both outputs are writable locals.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(last_error("failed to inspect Windows DACL controls"));
    }
    if revision == 0 || control & SE_DACL_PRESENT == 0 {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "the Windows object has no present DACL",
        ));
    }

    let mut owner = null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: The descriptor is valid and retained by the caller; Windows
    // returns an interior owner pointer through the writable local.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) } == 0 {
        return Err(last_error("failed to inspect the Windows object owner"));
    }
    // SAFETY: A successful owner query returned an interior pointer whose
    // descriptor allocation is still live.
    if owner.is_null() || unsafe { IsValidSid(owner) } == 0 {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "the Windows object has no valid owner",
        ));
    }

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = null_mut();
    // SAFETY: The descriptor is valid and all output pointers reference
    // writable locals; the returned DACL is interior to the live descriptor.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
    {
        return Err(last_error("failed to inspect the Windows object DACL"));
    }
    // SAFETY: A non-null DACL returned by the valid live descriptor may be
    // passed to IsValidAcl for structural validation.
    if dacl_present == 0 || dacl.is_null() || unsafe { IsValidAcl(dacl) } == 0 {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "the Windows object has an absent, null, or invalid DACL",
        ));
    }
    Ok(DescriptorParts {
        owner,
        dacl,
        control,
    })
}

fn security_descriptor(file: &File) -> Result<LocalSecurityDescriptor> {
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: The File keeps its handle live, unused outputs are null, and the
    // descriptor output points to a writable local. Success transfers one
    // LocalFree-owned allocation into LocalSecurityDescriptor below.
    let code = unsafe {
        GetSecurityInfo(
            raw_handle(file),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(Error::from_win32(
            "failed to read Windows security information from the open handle",
            code,
        ));
    }
    Ok(LocalSecurityDescriptor {
        allocation: LocalAllocation::new(
            descriptor,
            "Windows returned null security information for the open handle",
        )?,
    })
}

#[derive(Clone, Copy, Debug)]
struct AceHeaderView {
    ace_type: u8,
}

#[derive(Clone, Copy, Debug)]
struct AllowedAceView {
    flags: u8,
    mask: u32,
    sid: PSID,
}

fn acl_ace_count(dacl: *mut ACL) -> Result<u32> {
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: descriptor_parts validated this DACL and keeps its containing
    // descriptor live; the output buffer has the exact documented size.
    if unsafe {
        GetAclInformation(
            dacl,
            std::ptr::from_mut(&mut information).cast::<c_void>(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(u32::MAX),
            windows_sys::Win32::Security::AclSizeInformation,
        )
    } == 0
    {
        return Err(last_error("failed to enumerate a Windows DACL"));
    }
    Ok(information.AceCount)
}

fn ace_pointer(dacl: *mut ACL, index: u32) -> Result<*mut c_void> {
    let mut ace = null_mut();
    // SAFETY: The DACL was validated and is still live. GetAce validates the
    // index and returns an interior pointer through a writable local.
    if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
        return Err(last_error("failed to read a Windows DACL entry"));
    }
    Ok(ace)
}

fn ace_header(dacl: *mut ACL, index: u32) -> Result<AceHeaderView> {
    let pointer = ace_pointer(dacl, index)?;
    // SAFETY: GetAce returned a live entry in a validated ACL. Windows ACL
    // validation guarantees at least an ACE_HEADER; unaligned read is used.
    let header = unsafe { pointer.cast::<ACE_HEADER>().read_unaligned() };
    if usize::from(header.AceSize) < size_of::<ACE_HEADER>() {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "a Windows DACL entry is truncated",
        ));
    }
    Ok(AceHeaderView {
        ace_type: header.AceType,
    })
}

fn basic_allowed_ace(dacl: *mut ACL, index: u32) -> Result<Option<AllowedAceView>> {
    let pointer = ace_pointer(dacl, index)?;
    // SAFETY: GetAce returned a live entry in a validated ACL, and an
    // unaligned header read does not impose extra alignment requirements.
    let header = unsafe { pointer.cast::<ACE_HEADER>().read_unaligned() };
    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
        return Ok(None);
    }
    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    let ace_size = usize::from(header.AceSize);
    let sid_header_size = offset_of!(SID, SubAuthority);
    if ace_size < sid_offset + sid_header_size {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "a Windows allow entry is truncated",
        ));
    }
    // SAFETY: AceSize was checked against the full fixed prefix above.
    let allowed = unsafe { pointer.cast::<ACCESS_ALLOWED_ACE>().read_unaligned() };
    // SAFETY: `sid_offset` is within the validated AceSize and pointer addition
    // remains in this live ACE allocation.
    let sid = unsafe { pointer.cast::<u8>().add(sid_offset).cast::<c_void>() };
    // SAFETY: The fixed SID header was proven to fit in the live ACE above.
    let sub_authority_count = unsafe { *sid.cast::<u8>().add(offset_of!(SID, SubAuthorityCount)) };
    let sid_length = sid_header_size + usize::from(sub_authority_count) * size_of::<u32>();
    let sid_capacity = ace_size - sid_offset;
    if sid_length > sid_capacity {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "a Windows allow entry security identifier is truncated",
        ));
    }
    // SAFETY: The SID header and all subauthorities declared by that header
    // were proven to fit within the live ACE before Windows reads them.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "a Windows allow entry has an invalid security identifier",
        ));
    }
    // SAFETY: IsValidSid accepted the candidate pointer immediately above.
    let reported_sid_length = usize::try_from(unsafe { GetLengthSid(sid) }).unwrap_or(usize::MAX);
    if reported_sid_length != sid_length {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "a Windows allow entry has an inconsistent security identifier",
        ));
    }
    if sid_length != sid_capacity {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "a Windows allow entry has unsupported trailing data",
        ));
    }
    Ok(Some(AllowedAceView {
        flags: allowed.Header.AceFlags,
        mask: allowed.Mask,
        sid,
    }))
}

pub(crate) fn move_replace(_source_handle: &File, source: &Path, destination: &Path) -> Result<()> {
    let source = wide_path(source)?;
    let destination = wide_path(destination)?;
    // SAFETY: Both paths are NUL-terminated local paths. `_source_handle`
    // deliberately keeps the verified source object open through this call.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(last_error(
            "failed to atomically install the private Windows file",
        ));
    }
    Ok(())
}

pub(crate) fn delete_on_close(file: &File) -> Result<()> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: Temporary handles are opened with DELETE access, remain live via
    // `file`, and the input buffer exactly matches FileDispositionInfo.
    if unsafe {
        SetFileInformationByHandle(
            raw_handle(file),
            FileDispositionInfo,
            std::ptr::from_ref(&disposition).cast::<c_void>(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO>()).unwrap_or(u32::MAX),
        )
    } == 0
    {
        return Err(last_error(
            "failed to remove a private Windows temporary file",
        ));
    }
    Ok(())
}

fn current_process_user() -> Result<OwnedSid> {
    let mut token: HANDLE = null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle valid in this process,
    // and `token` is a writable output that receives a new owned handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error("failed to open the Windows process token"));
    }
    if token.is_null() || token == INVALID_HANDLE_VALUE {
        return Err(Error::policy(
            ErrorKind::InsecurePolicy,
            "Windows returned an invalid process-token handle",
        ));
    }
    // SAFETY: OpenProcessToken returned one fresh owned HANDLE.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };

    let mut required = 0u32;
    // SAFETY: The token handle is live. A null zero-length first query is the
    // documented sizing protocol, and `required` is writable.
    let first = unsafe {
        GetTokenInformation(
            raw_owned_handle(&token),
            TokenUser,
            null_mut(),
            0,
            &mut required,
        )
    };
    let first_error = std::io::Error::last_os_error();
    if first != 0
        || required < u32::try_from(size_of::<TOKEN_USER>()).unwrap_or(u32::MAX)
        || first_error.raw_os_error() != i32::try_from(ERROR_INSUFFICIENT_BUFFER).ok()
    {
        return Err(Error::io(
            "failed to size the Windows process-user information",
            first_error,
        ));
    }

    let word_size = size_of::<usize>();
    let words = usize::try_from(required)
        .unwrap_or(usize::MAX)
        .saturating_add(word_size - 1)
        / word_size;
    let mut information = vec![0usize; words];
    // SAFETY: The aligned `usize` buffer has at least `required` writable
    // bytes, and the token handle and output length remain live.
    if unsafe {
        GetTokenInformation(
            raw_owned_handle(&token),
            TokenUser,
            information.as_mut_ptr().cast::<c_void>(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(last_error(
            "failed to read the Windows process-user information",
        ));
    }
    // SAFETY: GetTokenInformation succeeded for TokenUser into an aligned
    // buffer at least TOKEN_USER bytes long.
    let token_user = unsafe { information.as_ptr().cast::<TOKEN_USER>().read() };
    OwnedSid::copy_from(token_user.User.Sid)
}

fn well_known_sid(sid_type: i32) -> Result<OwnedSid> {
    let words = usize::try_from(SECURITY_MAX_SID_SIZE)
        .unwrap_or(usize::MAX)
        .saturating_add(size_of::<usize>() - 1)
        / size_of::<usize>();
    let mut storage = vec![0usize; words];
    let mut byte_length = SECURITY_MAX_SID_SIZE;
    let sid = storage.as_mut_ptr().cast::<c_void>();
    // SAFETY: The aligned buffer is SECURITY_MAX_SID_SIZE bytes or larger and
    // the size output is writable; a null domain SID is documented here.
    if unsafe { CreateWellKnownSid(sid_type, null_mut(), sid, &mut byte_length) } == 0 {
        return Err(last_error(
            "failed to create a well-known Windows security identifier",
        ));
    }
    OwnedSid::copy_from(sid)
}

fn sid_from_string(text: &str) -> Result<OwnedSid> {
    let wide = wide_text(text)?;
    let mut sid = null_mut();
    // SAFETY: `wide` is NUL-terminated and `sid` is a writable output. On
    // success Windows transfers one LocalFree-owned allocation.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 {
        return Err(last_error(
            "failed to parse a trusted Windows security identifier",
        ));
    }
    let allocation =
        LocalAllocation::new(sid, "Windows returned a null trusted security identifier")?;
    OwnedSid::copy_from(allocation.pointer)
}

fn sid_to_string(sid: PSID) -> Result<String> {
    let mut string = null_mut();
    // SAFETY: The caller supplies a validated live SID and `string` is a
    // writable output receiving a LocalFree-owned NUL-terminated string.
    if unsafe { ConvertSidToStringSidW(sid, &mut string) } == 0 {
        return Err(last_error(
            "failed to format the Windows process-user identifier",
        ));
    }
    let allocation = LocalAllocation::new(
        string.cast::<c_void>(),
        "Windows returned a null process-user identifier string",
    )?;
    let string = allocation.pointer.cast::<u16>();
    let mut length = None;
    for index in 0..=256usize {
        // SAFETY: ConvertSidToStringSidW guarantees a NUL-terminated SID string;
        // valid SID strings are bounded well below this defensive limit.
        if unsafe { *string.add(index) } == 0 {
            length = Some(index);
            break;
        }
    }
    let length = length.ok_or_else(|| {
        Error::policy(
            ErrorKind::InsecurePolicy,
            "the Windows process-user identifier string is too long",
        )
    })?;
    // SAFETY: The scan found `length` initialized UTF-16 units before the NUL
    // in the still-live LocalFree allocation.
    let slice = unsafe { std::slice::from_raw_parts(string, length) };
    String::from_utf16(slice).map_err(|_| {
        Error::policy(
            ErrorKind::InsecurePolicy,
            "the Windows process-user identifier string is malformed",
        )
    })
}

fn wide_text(text: &str) -> Result<Vec<u16>> {
    if text.encode_utf16().any(|character| character == 0) {
        return Err(Error::policy(
            ErrorKind::InvalidPath,
            "embedded nulls are refused in Windows security strings",
        ));
    }
    Ok(text.encode_utf16().chain(std::iter::once(0)).collect())
}

fn wide_path(path: &Path) -> Result<Vec<u16>> {
    let encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.iter().any(|character| *character == 0) {
        return Err(Error::policy(
            ErrorKind::InvalidPath,
            "embedded nulls are refused in Windows paths",
        ));
    }
    let mut wide = r"\\?\".encode_utf16().collect::<Vec<_>>();
    wide.extend(encoded);
    wide.push(0);
    Ok(wide)
}

fn raw_handle(file: &File) -> HANDLE {
    file.as_raw_handle()
}

fn raw_owned_handle(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle()
}

fn last_error(operation: &'static str) -> Error {
    Error::io(operation, std::io::Error::last_os_error())
}

fn last_create_error(operation: &'static str) -> Error {
    let source = std::io::Error::last_os_error();
    if matches!(
        source.raw_os_error(),
        Some(code)
            if code == i32::try_from(ERROR_FILE_EXISTS).unwrap_or(i32::MAX)
                || code == i32::try_from(ERROR_ALREADY_EXISTS).unwrap_or(i32::MAX)
    ) {
        Error {
            kind: ErrorKind::AlreadyExists,
            operation,
            source: Some(source),
        }
    } else {
        Error::io(operation, source)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum TestPolicy {
    Broad,
    AncestorWorldAddFile,
    AncestorWorldAddDirectory,
    NullDacl,
    Unprotected,
}

#[cfg(test)]
pub(crate) fn open_for_policy_test(path: &Path) -> Result<File> {
    open_file(
        path,
        READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        COMMON_OPEN_FLAGS | FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
        None,
        "failed to open the Windows policy test file",
    )
}

#[cfg(test)]
pub(crate) fn apply_test_policy(
    file: &File,
    context: &SecurityContext,
    policy: TestPolicy,
) -> Result<()> {
    let broad;
    let (information, dacl) = match policy {
        TestPolicy::Broad => {
            broad = LocalSecurityDescriptor::parse("D:P(A;;FA;;;WD)")?;
            (
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                broad.dacl()?,
            )
        }
        TestPolicy::AncestorWorldAddFile | TestPolicy::AncestorWorldAddDirectory => {
            let user = sid_to_string(context.user.as_ptr())?;
            let mask = match policy {
                TestPolicy::AncestorWorldAddFile => "0x00000002",
                TestPolicy::AncestorWorldAddDirectory => "0x00000004",
                TestPolicy::Broad | TestPolicy::NullDacl | TestPolicy::Unprotected => {
                    unreachable!("matched add-child policy")
                }
            };
            broad = LocalSecurityDescriptor::parse(&format!(
                "D:P(A;OICI;FA;;;{user})(A;;{mask};;;WD)"
            ))?;
            (
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                broad.dacl()?,
            )
        }
        TestPolicy::NullDacl => (
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
        ),
        TestPolicy::Unprotected => (
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            context.file_descriptor.dacl()?,
        ),
    };
    // SAFETY: The test handle requests WRITE_DAC, all descriptor-backed DACLs
    // remain live through the call, and null is intentional for the null-DACL case.
    let code = unsafe {
        SetSecurityInfo(
            raw_handle(file),
            SE_FILE_OBJECT,
            information,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if code != ERROR_SUCCESS {
        return Err(Error::from_win32(
            "failed to apply a Windows policy test DACL",
            code,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::System::WindowsProgramming::{
        DRIVE_CDROM, DRIVE_NO_ROOT_DIR, DRIVE_RAMDISK, DRIVE_REMOTE, DRIVE_REMOVABLE, DRIVE_UNKNOWN,
    };

    use super::*;

    #[test]
    fn only_fixed_drive_types_are_accepted() {
        require_fixed_drive_type(DRIVE_FIXED).expect("fixed drive");
        for drive_type in [
            DRIVE_UNKNOWN,
            DRIVE_NO_ROOT_DIR,
            DRIVE_REMOVABLE,
            DRIVE_REMOTE,
            DRIVE_CDROM,
            DRIVE_RAMDISK,
        ] {
            assert_eq!(
                require_fixed_drive_type(drive_type)
                    .expect_err("non-fixed drive must fail")
                    .kind(),
                ErrorKind::InvalidPath
            );
        }
    }
}
