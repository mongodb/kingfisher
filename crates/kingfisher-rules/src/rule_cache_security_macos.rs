//! Darwin extended ACLs can grant writes independently of POSIX mode bits.
//! Reject write grants conservatively; deny-only and read-only ACLs remain usable.

use std::{ffi::CString, fs::File, os::fd::AsRawFd, os::unix::ffi::OsStrExt, path::Path, ptr};

use anyhow::{Context, Result, bail};
use libc::{c_char, c_int, c_void};

// Darwin SDK sys/acl.h; libc's Rust bindings do not currently expose these APIs.
unsafe extern "C" {
    fn acl_get_file(path: *const c_char, kind: c_int) -> *mut c_void;
    fn acl_get_fd(fd: c_int) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
    fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> c_int;
    fn acl_free(acl: *mut c_void) -> c_int;
}

struct Acl(*mut c_void);

impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns a non-null ACL returned by acl_get_file/fd.
        unsafe { acl_free(self.0) };
    }
}

pub(super) fn verify_path(path: &Path) -> Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: the path is null-terminated; 0x100 is Darwin ACL_TYPE_EXTENDED.
    verify(unsafe { acl_get_file(path.as_ptr(), 0x100) })
}

pub(super) fn verify_file(file: &File) -> Result<()> {
    // SAFETY: the borrowed File owns a valid descriptor throughout this call.
    verify(unsafe { acl_get_fd(file.as_raw_fd()) })
}

fn verify(acl: *mut c_void) -> Result<()> {
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        // Darwin reports ENOENT when an existing inode has no extended ACL. The
        // caller has already validated the path or holds an open file descriptor.
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(error).context("read cache extended ACL");
    }
    let acl = Acl(acl);
    let mut entry_id = 0; // ACL_FIRST_ENTRY
    // Write/add, delete, append, delete-child, attributes, xattrs, security, ownership.
    const WRITE_MASK: u64 =
        (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 8) | (1 << 10) | (1 << 12) | (1 << 13);
    loop {
        let mut entry = ptr::null_mut();
        // SAFETY: acl is a valid OS-provided ACL; entry is a valid output pointer.
        if unsafe { acl_get_entry(acl.0, entry_id, &mut entry) } != 0 {
            let error = std::io::Error::last_os_error();
            // Darwin returns EINVAL at the end, including an empty ACL.
            if error.raw_os_error() == Some(libc::EINVAL) {
                return Ok(());
            }
            return Err(error).context("read cache extended ACL entry");
        }
        entry_id = -1; // ACL_NEXT_ENTRY
        let mut tag = 0;
        let mut mask = 0;
        // SAFETY: entry belongs to this ACL and both output pointers are valid.
        if unsafe { acl_get_tag_type(entry, &mut tag) } != 0
            || unsafe { acl_get_permset_mask_np(entry, &mut mask) } != 0
        {
            return Err(std::io::Error::last_os_error()).context("read cache ACL permissions");
        }
        if tag == 1 && mask & WRITE_MASK != 0 {
            // ACL_EXTENDED_ALLOW
            bail!("cache location has an extended ACL write grant");
        }
    }
}
