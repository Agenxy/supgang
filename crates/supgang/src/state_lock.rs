//! Exclusive process ownership for mutable local Supgang state.

use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use thiserror::Error;

use crate::storage::{StorageError, no_follow_flag, sync_directory, validate_directory, validate_owner_file_metadata};

/// Name of the owner-only state ownership lock.
pub const STATE_LOCK_FILE_NAME: &str = "state.lock";

/// An exclusive lock held until this value is dropped.
pub struct StateLock {
    file: File,
}

impl core::fmt::Debug for StateLock {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("StateLock").field("file", &"<locked>").finish()
    }
}

/// A state-lock creation, validation, or contention failure.
#[derive(Debug, Error)]
pub enum StateLockError {
    /// State-directory validation failed.
    #[error("protected state directory failed validation")]
    Storage(#[from] StorageError),
    /// Another Supgang process currently owns mutable state.
    #[error("another Supgang process currently owns this state directory")]
    Busy,
    /// The operating system rejected the lock operation.
    #[error("local state ownership lock failed")]
    Io(#[from] io::Error),
}

impl StateLock {
    /// Acquires non-blocking exclusive ownership of one state directory.
    ///
    /// # Errors
    ///
    /// Rejects unsafe storage, symlinks, foreign ownership, permissive mode,
    /// lock contention, and operating-system failures.
    pub fn acquire(state_directory: impl AsRef<Path>) -> Result<Self, StateLockError> {
        let directory = validate_directory(state_directory.as_ref())?;
        let path = directory.join(STATE_LOCK_FILE_NAME);
        let existed = path.exists();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(no_follow_flag()?)
            .open(path)?;
        validate_owner_file_metadata(&file)?;
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::WOULDBLOCK => return Err(StateLockError::Busy),
            Err(error) => return Err(io::Error::from_raw_os_error(error.raw_os_error()).into()),
        }
        if !existed {
            file.sync_all()?;
            sync_directory(&directory)?;
        }
        Ok(Self { file })
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _result = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

#[cfg(test)]
mod tests {
    use super::{StateLock, StateLockError};
    use crate::state;

    #[test]
    fn second_process_owner_is_refused_until_release() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("state");
        let initialized = state::initialize(&directory)?;
        drop(initialized);
        let first = StateLock::acquire(&directory)?;
        assert!(matches!(StateLock::acquire(&directory), Err(StateLockError::Busy)));
        drop(first);
        let _second = StateLock::acquire(&directory)?;
        Ok(())
    }
}
