use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use super::{UpdateError, no_follow, updates_directory};

const UPDATE_LOCK_FILE: &str = "update.lock";

pub struct UpdateLock {
    file: File,
}

impl UpdateLock {
    pub fn acquire(state_directory: &Path) -> Result<Self, UpdateError> {
        let updates = updates_directory(state_directory, true)?;
        let path = updates.join(UPDATE_LOCK_FILE);
        let existed = path.symlink_metadata().is_ok();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(no_follow()?)
            .open(path)?;
        if !existed {
            supgang_acl::clear_inherited_acl(&file)?;
        }
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(UpdateError::InvalidBundle);
        }
        supgang_acl::reject_non_owner_grants(&file)?;
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::WOULDBLOCK => return Err(UpdateError::Busy),
            Err(error) => return Err(io::Error::from_raw_os_error(error.raw_os_error()).into()),
        }
        if !existed {
            file.sync_all()?;
            File::open(updates)?.sync_all()?;
        }
        Ok(Self { file })
    }
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        let _result = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

#[cfg(test)]
mod tests {
    use super::UpdateLock;
    use crate::update::UpdateError;

    #[test]
    fn update_state_has_one_cross_process_writer() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state = temporary.path().join("state");
        drop(crate::state::initialize(&state)?);
        let first = UpdateLock::acquire(&state)?;
        assert!(matches!(UpdateLock::acquire(&state), Err(UpdateError::Busy)));
        drop(first);
        let _next = UpdateLock::acquire(&state)?;
        Ok(())
    }
}
