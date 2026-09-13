//! Small safe boundary around platform descriptor-based ACL APIs.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, warnings)]

use std::{fs::File, io};

/// Rejects access-control entries that can grant a non-owner access.
///
/// macOS deny-only entries are permitted. Linux access or default ACL xattrs
/// are rejected because protected files and directories use exact owner-only
/// mode bits and need no extended policy.
pub fn reject_non_owner_grants(file: &File) -> io::Result<()> {
    platform::reject_non_owner_grants(file)
}

/// Removes inherited extended ACL state from a newly created descriptor.
///
/// Call this before writing secret bytes or publishing the new directory.
pub fn clear_inherited_acl(file: &File) -> io::Result<()> {
    platform::clear_inherited_acl(file)
}

#[cfg(target_os = "macos")]
mod platform {
    use std::{ffi::c_void, fs::File, io, os::fd::AsRawFd, ptr};

    type Acl = *mut c_void;
    type AclEntry = *mut c_void;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;
    const ACL_NEXT_ENTRY: libc::c_int = -1;
    const ACL_EXTENDED_ALLOW: libc::c_int = 1;

    unsafe extern "C" {
        fn acl_free(value: *mut c_void) -> libc::c_int;
        fn acl_get_entry(acl: Acl, entry_id: libc::c_int, entry: *mut AclEntry) -> libc::c_int;
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> Acl;
        fn acl_get_tag_type(entry: AclEntry, tag: *mut libc::c_int) -> libc::c_int;
        fn acl_init(count: libc::c_int) -> Acl;
        fn acl_set_fd_np(fd: libc::c_int, acl: Acl, acl_type: libc::c_int) -> libc::c_int;
    }

    pub(super) fn reject_non_owner_grants(file: &File) -> io::Result<()> {
        // SAFETY: The descriptor is live for the call, and every returned ACL
        // object is released exactly once before this function returns.
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(error)
            };
        }
        let result = inspect_acl(acl);
        // SAFETY: `acl` is non-null and owned by this function.
        let released = unsafe { acl_free(acl) };
        if released != 0 {
            return Err(io::Error::last_os_error());
        }
        result
    }

    fn inspect_acl(acl: Acl) -> io::Result<()> {
        let mut entry = ptr::null_mut();
        let mut entry_id = ACL_FIRST_ENTRY;
        loop {
            // SAFETY: `acl` is a valid live ACL and `entry` points to writable
            // storage for the borrowed entry handle.
            let status = unsafe { acl_get_entry(acl, entry_id, &raw mut entry) };
            match status {
                0 => {
                    let mut tag = 0;
                    // SAFETY: A successful `acl_get_entry` returned a valid
                    // entry borrowed from the still-live ACL.
                    if unsafe { acl_get_tag_type(entry, &raw mut tag) } != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if tag == ACL_EXTENDED_ALLOW {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "protected descriptor has a non-owner ACL grant",
                        ));
                    }
                    entry_id = ACL_NEXT_ENTRY;
                }
                _ => {
                    let error = io::Error::last_os_error();
                    return if error.raw_os_error() == Some(libc::EINVAL) {
                        Ok(())
                    } else {
                        Err(error)
                    };
                }
            }
        }
    }

    pub(super) fn clear_inherited_acl(file: &File) -> io::Result<()> {
        // SAFETY: `acl_init(0)` creates an owned empty ACL object.
        let acl = unsafe { acl_init(0) };
        if acl.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: The descriptor and ACL remain live for the call.
        let status = unsafe { acl_set_fd_np(file.as_raw_fd(), acl, ACL_TYPE_EXTENDED) };
        let error = if status == 0 {
            None
        } else {
            Some(io::Error::last_os_error())
        };
        // SAFETY: `acl` is non-null and owned by this function.
        let released = unsafe { acl_free(acl) };
        if let Some(error) = error {
            return Err(error);
        }
        if released != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::{ffi::CString, fs::File, io, os::fd::AsRawFd, ptr};

    const ACL_NAMES: [&str; 2] = ["system.posix_acl_access", "system.posix_acl_default"];

    pub(super) fn reject_non_owner_grants(file: &File) -> io::Result<()> {
        for name in ACL_NAMES {
            let name = CString::new(name).map_err(io::Error::other)?;
            // SAFETY: The descriptor is live, the name is NUL-terminated, and
            // a null buffer with length zero requests only the xattr size.
            let result = unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), ptr::null_mut(), 0) };
            if result > 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "protected descriptor has an extended ACL",
                ));
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if !matches!(error.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub(super) fn clear_inherited_acl(file: &File) -> io::Result<()> {
        for name in ACL_NAMES {
            let name = CString::new(name).map_err(io::Error::other)?;
            // SAFETY: The descriptor is live and the name is NUL-terminated.
            let result = unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr()) };
            if result != 0 {
                let error = io::Error::last_os_error();
                if !matches!(error.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) {
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("supgang-acl supports only the Supgang macOS and Linux targets");

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::clear_inherited_acl;
    use super::reject_non_owner_grants;
    use std::{
        fs::{self, File, OpenOptions},
        os::unix::fs::OpenOptionsExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    #[cfg(target_os = "macos")]
    use std::{path::Path, process::Command};

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    struct TestFile {
        path: PathBuf,
        file: File,
    }

    impl TestFile {
        fn new() -> Self {
            let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("supgang-acl-{}-{serial}", std::process::id()));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap_or_else(|error| panic!("create ACL test file: {error}"));
            Self { path, file }
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _cleanup = fs::remove_file(&self.path);
        }
    }

    #[test]
    fn owner_only_descriptor_is_accepted() {
        let test_file = TestFile::new();
        reject_non_owner_grants(&test_file.file).unwrap_or_else(|error| panic!("owner-only descriptor: {error}"));
    }

    #[cfg(target_os = "macos")]
    fn chmod_acl(path: &Path, entry: &str) {
        let status = Command::new("/bin/chmod")
            .args(["+a", entry])
            .arg(path)
            .status()
            .unwrap_or_else(|error| panic!("run chmod: {error}"));
        assert!(status.success(), "chmod did not apply test ACL");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn allow_acl_is_rejected_and_can_be_cleared() {
        let test_file = TestFile::new();
        chmod_acl(&test_file.path, "everyone allow read");
        assert!(reject_non_owner_grants(&test_file.file).is_err());
        clear_inherited_acl(&test_file.file).unwrap_or_else(|error| panic!("clear ACL: {error}"));
        reject_non_owner_grants(&test_file.file).unwrap_or_else(|error| panic!("cleared ACL: {error}"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn deny_only_acl_is_accepted() {
        let test_file = TestFile::new();
        chmod_acl(&test_file.path, "everyone deny read");
        reject_non_owner_grants(&test_file.file).unwrap_or_else(|error| panic!("deny-only ACL: {error}"));
    }
}
