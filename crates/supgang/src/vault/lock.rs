//! One owner-only vault writer at a time.

use std::{
    fs, io,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use super::{LOCK_FILE_NAME, VaultError};
use crate::storage::{no_follow_flag, validate_directory, validate_owner_file_metadata};

pub(super) struct Lock {
    file: fs::File,
}

impl Lock {
    /// The vault's single-writer lock; a second writer is refused, not queued.
    pub(super) fn acquire(state_directory: &Path) -> Result<(PathBuf, Self), VaultError> {
        let directory = validate_directory(state_directory)?;
        let lock = Self::open(&directory, LOCK_FILE_NAME, false)?;
        Ok((directory, lock))
    }

    /// `wait` blocks for the audit lock, which is held only for one append.
    pub(super) fn open(directory: &Path, file_name: &str, wait: bool) -> Result<Self, VaultError> {
        let path = directory.join(file_name);
        let existed = fs::symlink_metadata(&path).is_ok();
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(no_follow_flag()?)
            .open(path)?;
        if !existed {
            supgang_acl::clear_inherited_acl(&file)?;
        }
        validate_owner_file_metadata(&file)?;
        let operation = if wait {
            rustix::fs::FlockOperation::LockExclusive
        } else {
            rustix::fs::FlockOperation::NonBlockingLockExclusive
        };
        match rustix::fs::flock(&file, operation) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::WOULDBLOCK => return Err(VaultError::Busy),
            Err(error) => return Err(io::Error::from_raw_os_error(error.raw_os_error()).into()),
        }
        Ok(Self { file })
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _result = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}
