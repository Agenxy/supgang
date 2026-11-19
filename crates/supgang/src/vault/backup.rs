//! The platform backup exclusion for LMS reservation state.

use std::path::Path;

#[cfg(target_os = "macos")]
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

use super::VaultError;
use crate::device_key::custody::{CustodyKind, SealedKey};

pub(super) fn exclude(path: &Path, key: &SealedKey) -> Result<(), VaultError> {
    if key.kind != CustodyKind::SecureEnclave {
        // File custody exists only in tests. Production vault access refuses it.
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        crate::device_key::secure_enclave::exclude_from_backup(path)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(crate::storage::no_follow_flag()?)
            .open(path)?;
        file.sync_all()?;
        crate::storage::sync_directory(path.parent().ok_or(VaultError::Corrupt)?)?;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Err(VaultError::Corrupt)
    }
}
