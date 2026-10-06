//! Conservative cache trust checks for Windows DACLs.
//!
//! Permit writes only by the current user, Administrators, and SYSTEM. Ancestors
//! also trust the OS maintenance service TrustedInstaller. Unknown ACE forms fail
//! closed: the scanner can always compile instead of using disk bytecode.

use std::{
    ffi::c_void,
    fs,
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::{Component, Path, Prefix},
    ptr,
};

use anyhow::{Context, Result, bail};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, GENERIC_ALL, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT},
        CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetTokenInformation,
        INHERIT_ONLY_ACE, InitializeSecurityDescriptor, IsValidSid, LookupAccountNameW,
        OWNER_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
        SECURITY_MAX_SID_SIZE, SetSecurityDescriptorOwner, TOKEN_QUERY, TOKEN_USER, TokenUser,
        WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid,
        WinLocalSystemSid,
    },
    Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
        FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
    },
    System::{
        SystemServices::{
            ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
        },
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns a valid token handle.
        unsafe { CloseHandle(self.0) };
    }
}

struct SecurityDescriptor(*mut c_void);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: GetNamedSecurityInfoW allocates this descriptor using LocalAlloc.
        unsafe { LocalFree(self.0) };
    }
}

struct TrustedSids {
    // u64 storage preserves alignment for TOKEN_USER and SID structures. Every SID
    // pointer remains inside these owned buffers for the duration of verification.
    token_user: Vec<u64>,
    administrators: Vec<u64>,
    system: Vec<u64>,
    owner_rights: Vec<u64>,
    trusted_installer: Option<Vec<u64>>,
}

impl TrustedSids {
    fn new() -> Result<Self> {
        let mut token = ptr::null_mut();
        // SAFETY: both APIs receive valid output pointers; the process pseudo-handle
        // is not owned. Token closes the returned real handle on all exit paths.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error()).context("open process token");
        }
        let token = Token(token);
        let mut size = 0;
        // SAFETY: querying the required buffer size accepts a null data buffer.
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut size) };
        if size == 0 {
            return Err(std::io::Error::last_os_error()).context("get token user size");
        }
        let mut token_user = vec![0_u64; (size as usize).div_ceil(8)];
        // SAFETY: storage is aligned and at least size bytes long.
        if unsafe {
            GetTokenInformation(token.0, TokenUser, token_user.as_mut_ptr().cast(), size, &mut size)
        } == 0
        {
            return Err(std::io::Error::last_os_error()).context("get token user");
        }
        Ok(Self {
            token_user,
            administrators: well_known_sid(WinBuiltinAdministratorsSid)?,
            system: well_known_sid(WinLocalSystemSid)?,
            owner_rights: well_known_sid(WinCreatorOwnerRightsSid)?,
            // Standard Windows volumes can be owned by this privileged OS service.
            // An unavailable service SID stays untrusted, preserving fail-closed behavior.
            trusted_installer: named_sid("NT SERVICE\\TrustedInstaller").ok(),
        })
    }

    fn user(&self) -> PSID {
        // SAFETY: GetTokenInformation successfully populated a TOKEN_USER buffer.
        unsafe { (*self.token_user.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    fn is_trusted(&self, sid: PSID, ancestor: bool) -> bool {
        // SAFETY: all pointers refer to validated, live OS-provided SID buffers.
        unsafe {
            IsValidSid(sid) != 0
                && (EqualSid(sid, self.user()) != 0
                    || EqualSid(sid, self.administrators.as_ptr().cast_mut().cast()) != 0
                    || EqualSid(sid, self.system.as_ptr().cast_mut().cast()) != 0
                    || (ancestor
                        && self.trusted_installer.as_ref().is_some_and(|installer| {
                            EqualSid(sid, installer.as_ptr().cast_mut().cast()) != 0
                        })))
        }
    }

    fn is_owner_rights(&self, sid: PSID) -> bool {
        // SAFETY: the OS supplied the ACE SID and the well-known SID remains live.
        unsafe {
            IsValidSid(sid) != 0 && EqualSid(sid, self.owner_rights.as_ptr().cast_mut().cast()) != 0
        }
    }
}

fn named_sid(account: &str) -> Result<Vec<u64>> {
    let name: Vec<u16> = account.encode_utf16().chain(Some(0)).collect();
    let mut sid_size = 0;
    let mut domain_size = 0;
    let mut kind = 0;
    // SAFETY: null output buffers are permitted when querying required sizes;
    // name is null-terminated and both size/type output pointers are valid.
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            ptr::null_mut(),
            &mut sid_size,
            ptr::null_mut(),
            &mut domain_size,
            &mut kind,
        )
    };
    if sid_size == 0 {
        return Err(std::io::Error::last_os_error()).context("resolve cache service SID size");
    }
    let mut sid = vec![0_u64; (sid_size as usize).div_ceil(8)];
    let mut domain = vec![0_u16; domain_size as usize];
    // SAFETY: both buffers are correctly aligned and sized for the preceding query.
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut kind,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("resolve cache service SID");
    }
    Ok(sid)
}

fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> Result<Vec<u64>> {
    let mut size = SECURITY_MAX_SID_SIZE;
    let mut sid = vec![0_u64; (size as usize).div_ceil(8)];
    // SAFETY: storage is aligned and can hold SECURITY_MAX_SID_SIZE bytes.
    if unsafe { CreateWellKnownSid(kind, ptr::null_mut(), sid.as_mut_ptr().cast(), &mut size) } == 0
    {
        return Err(std::io::Error::last_os_error()).context("create well-known SID");
    }
    Ok(sid)
}

fn with_user_owner<T>(operation: impl FnOnce(&SECURITY_ATTRIBUTES) -> Result<T>) -> Result<T> {
    let trusted = TrustedSids::new()?;
    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let descriptor_pointer = ptr::addr_of_mut!(descriptor).cast();
    // SAFETY: descriptor is correctly aligned, writable SECURITY_DESCRIPTOR storage.
    if unsafe { InitializeSecurityDescriptor(descriptor_pointer, SECURITY_DESCRIPTOR_REVISION) }
        == 0
    {
        return Err(std::io::Error::last_os_error()).context("initialize cache owner descriptor");
    }
    // SAFETY: descriptor is initialized and the SID remains owned by trusted until
    // the synchronous creation call completes. Only ownership is specified: the OS
    // still propagates the parent's inheritable DACL, which we verify before writes.
    if unsafe { SetSecurityDescriptorOwner(descriptor_pointer, trusted.user(), 0) } == 0 {
        return Err(std::io::Error::last_os_error()).context("set cache owner descriptor");
    }
    operation(&SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor_pointer,
        bInheritHandle: 0,
    })
}

fn wide_cache_path(path: &Path) -> Result<Vec<u16>> {
    if path.as_os_str().encode_wide().any(|character| character == 0) {
        bail!("cache path contains a NUL character");
    }
    // Direct Win32 calls need the extended-length namespace even when the host
    // application has not opted into long paths. Resolve relative/dot components
    // before adding that prefix; trust verification still uses the caller's route.
    let absolute = std::path::absolute(path).context("make cache creation path absolute")?;
    let absolute_name: Vec<u16> = absolute.as_os_str().encode_wide().collect();
    let Some(Component::Prefix(prefix)) = absolute.components().next() else {
        bail!("cache creation requires an absolute Windows filesystem path");
    };
    let mut name: Vec<u16> = match prefix.kind() {
        Prefix::Disk(_) => "\\\\?\\".encode_utf16().chain(absolute_name).collect(),
        Prefix::UNC(_, _) => {
            "\\\\?\\UNC\\".encode_utf16().chain(absolute_name.into_iter().skip(2)).collect()
        }
        Prefix::Verbatim(_) | Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) => absolute_name,
        _ => bail!("cache creation requires a Windows filesystem path"),
    };
    name.push(0);
    Ok(name)
}

pub(super) fn create_directory(path: &Path) -> Result<()> {
    let name = wide_cache_path(path)?;
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    with_user_owner(|attributes| {
        // SAFETY: name is null-terminated; attributes and its descriptor/SID remain
        // valid through this synchronous call. Creation assigns ownership atomically
        // and never changes an existing path, including a concurrently created one.
        if unsafe { CreateDirectoryW(name.as_ptr(), attributes) } != 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) {
            return Ok(());
        }
        Err(error).context("create user-owned cache directory")
    })
}

pub(super) fn create_file(path: &Path) -> Result<fs::File> {
    let name = wide_cache_path(path)?;
    with_user_owner(|attributes| {
        // SAFETY: name and security attributes remain live through the call. CREATE_NEW
        // refuses existing paths, and the returned handle is either invalid or uniquely
        // owned here. Share modes match Rust's normal OpenOptions behavior.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error()).context("create user-owned cache file");
        }
        // SAFETY: the valid, uniquely owned handle is transferred to File exactly once.
        Ok(unsafe { fs::File::from_raw_handle(handle) })
    })
}

pub(super) fn verify_directory(path: &Path) -> Result<()> {
    let trusted = TrustedSids::new()?;
    let metadata = fs::symlink_metadata(path)?;
    verify_not_reparse_point(&metadata)?;
    verify_dacl(path, &trusted, true, false)?;
    let absolute =
        if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir()?.join(path) };
    // Do not let canonicalization hide a replaceable junction/symlink on the
    // supplied route to an otherwise private directory.
    for ancestor in absolute.ancestors().skip(1) {
        verify_not_reparse_point(&fs::symlink_metadata(ancestor)?)?;
        verify_dacl(ancestor, &trusted, false, true)?;
    }
    let canonical = fs::canonicalize(path)?;
    for ancestor in canonical.ancestors().skip(1) {
        verify_dacl(ancestor, &trusted, false, true)?;
    }
    Ok(())
}

pub(super) fn verify_file(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    verify_not_reparse_point(metadata)?;
    verify_dacl(path, &TrustedSids::new()?, true, false)
}

fn verify_not_reparse_point(metadata: &fs::Metadata) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("cache location must not be a reparse point");
    }
    Ok(())
}

fn verify_dacl(
    path: &Path,
    trusted: &TrustedSids,
    require_user_owner: bool,
    ancestor: bool,
) -> Result<()> {
    let name = wide_cache_path(path)?;
    let mut owner = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: name is null-terminated and all output pointers are valid. The returned
    // descriptor owns the owner/DACL data until SecurityDescriptor is dropped.
    let result = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result as i32)).context("read cache DACL");
    }
    let _descriptor = SecurityDescriptor(descriptor);
    // SAFETY: owner is part of the successful security descriptor query.
    if owner.is_null()
        || !trusted.is_trusted(owner, ancestor)
        || (require_user_owner && unsafe { EqualSid(owner, trusted.user()) } == 0)
    {
        bail!("cache location has an untrusted owner");
    }
    if dacl.is_null() {
        bail!("cache location has an unrestricted DACL");
    }
    let write_mask = if ancestor {
        // Creating siblings at C:\ or under Users does not permit substitution. Deleting
        // a child or changing the parent's ACL/owner would permit replacing our cache.
        GENERIC_ALL
            | GENERIC_WRITE
            | DELETE
            | FILE_DELETE_CHILD
            | FILE_WRITE_ATTRIBUTES
            | FILE_WRITE_EA
            | WRITE_DAC
            | WRITE_OWNER
    } else {
        GENERIC_ALL
            | GENERIC_WRITE
            | DELETE
            | FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_ATTRIBUTES
            | FILE_WRITE_EA
            | FILE_DELETE_CHILD
            | WRITE_DAC
            | WRITE_OWNER
    };
    // SAFETY: dacl is OS-validated data within the descriptor allocation.
    for index in 0..unsafe { (*dacl).AceCount } {
        let mut ace = ptr::null_mut();
        // SAFETY: index is within the ACL's count and ace is a valid output pointer.
        if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 {
            return Err(std::io::Error::last_os_error()).context("read cache ACE");
        }
        // SAFETY: GetAce returns a valid ACE_HEADER belonging to the ACL.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0
            || header.AceType as u32 == ACCESS_DENIED_ACE_TYPE
        {
            continue;
        }
        if header.AceType as u32 != ACCESS_ALLOWED_ACE_TYPE {
            bail!("cache location uses an unsupported ACE type");
        }
        // SAFETY: the type check establishes ACCESS_ALLOWED_ACE; its SID starts at
        // SidStart and extends within the OS-validated variable-length ACE buffer.
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = ptr::addr_of!(allowed.SidStart).cast_mut().cast();
        // OWNER RIGHTS grants apply only to this object's owner, already validated
        // above. Python 3.13 uses this SID for its private mode-0700 directories.
        // Never treat this pseudo-SID as an acceptable object owner itself.
        if allowed.Mask & write_mask != 0
            && !trusted.is_trusted(sid, ancestor)
            && !trusted.is_owner_rights(sid)
        {
            bail!("cache location is writable by an untrusted account");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{io::Write, path::PathBuf};

    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Result<Self> {
            let path = std::env::temp_dir()
                .join(format!("kingfisher-windows-cache-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).ok();
        }
    }

    #[test]
    fn cache_creation_assigns_user_ownership_and_refuses_existing_files() -> Result<()> {
        let root = TestDirectory::new()?;
        // Dot components must be resolved before extending Win32 API names while
        // remaining visible to the original-route trust checks.
        fs::create_dir(root.path().join("nested"))?;
        let cache = root.path().join("nested").join("..").join("owned-cache");
        create_directory(&cache)?;
        verify_directory(&cache)?;

        let path = cache.join("entry.bin");
        let mut file = create_file(&path)?;
        verify_file(&path, &file.metadata()?)?;
        file.write_all(b"existing cache entry")?;
        drop(file);

        // Atomic creation must not truncate or take ownership of an existing entry.
        assert!(create_file(&path).is_err());
        assert_eq!(fs::read(&path)?, b"existing cache entry");
        assert_eq!(
            fs::read(root.path().join("owned-cache").join("entry.bin"))?,
            b"existing cache entry"
        );
        create_directory(&cache)?;
        verify_directory(&cache)?;
        Ok(())
    }

    #[test]
    fn cache_creation_supports_extended_length_paths() -> Result<()> {
        let root = TestDirectory::new()?;
        let mut parent = root.path().to_path_buf();
        while parent.as_os_str().encode_wide().count() <= 280 {
            parent.push("long-cache-directory-component");
        }
        let cache = parent.join("owned-cache");
        create_directory(&cache)?;
        verify_directory(&cache)?;
        let path = cache.join("entry.bin");
        let mut file = create_file(&path)?;
        verify_file(&path, &file.metadata()?)?;
        file.write_all(b"long path entry")?;
        drop(file);
        assert_eq!(fs::read(path)?, b"long path entry");
        Ok(())
    }
}
