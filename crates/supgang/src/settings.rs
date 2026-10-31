//! Owner-only, bounded local settings with conservative defaults.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::storage::{self, no_follow_flag, sync_directory, validate_directory, validate_owner_file_metadata};

/// Name of the optional owner-only configuration document.
pub const SETTINGS_FILE_NAME: &str = "settings.toml";
/// Default number of historically signed addresses retried for each peer.
pub const DEFAULT_ADDRESS_HISTORY: usize = 16;
/// Smallest supported address-history budget.
pub const MIN_ADDRESS_HISTORY: usize = 8;
/// Largest supported address-history budget.
pub const MAX_ADDRESS_HISTORY: usize = 64;

const SETTINGS_LOCK_FILE_NAME: &str = "settings.lock";
const SETTINGS_VERSION: u16 = 1;
const MAX_SETTINGS_BYTES: u64 = 4 * 1024;
const TEMPORARY_ATTEMPTS: usize = 8;

/// Validated local runtime preferences.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    address_history: usize,
}

impl Settings {
    /// Returns the number of stale, authenticated addresses available only to
    /// bounded reconnection attempts.
    #[must_use]
    pub const fn address_history(self) -> usize {
        self.address_history
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            address_history: DEFAULT_ADDRESS_HISTORY,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SettingsDocument {
    version: u16,
    network: NetworkSettings,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NetworkSettings {
    address_history: usize,
}

impl From<Settings> for SettingsDocument {
    fn from(settings: Settings) -> Self {
        Self {
            version: SETTINGS_VERSION,
            network: NetworkSettings {
                address_history: settings.address_history,
            },
        }
    }
}

/// A settings validation, concurrency, or persistence failure.
#[derive(Debug, Error)]
pub enum SettingsError {
    /// The requested history budget is outside the fixed safety bounds.
    #[error("address history must be from 8 through 64")]
    InvalidAddressHistory,
    /// Another process currently owns the settings mutation lock.
    #[error("another settings change is in progress; retry the command")]
    Busy,
    /// The protected state directory failed validation.
    #[error("settings state directory failed validation")]
    Storage(#[from] storage::StorageError),
    /// The operating system rejected a settings-file operation.
    #[error("settings filesystem operation failed")]
    Io(#[from] io::Error),
    /// Existing bytes are malformed, oversized, or unsupported.
    #[error("settings file is invalid or corrupt")]
    InvalidFile,
}

/// Loads settings without creating a missing document.
///
/// # Errors
///
/// Rejects unsafe state paths, symlinks, permissive files, malformed TOML,
/// unknown fields, unsupported versions, and out-of-range values.
pub fn load(state_directory: &Path) -> Result<Settings, SettingsError> {
    let directory = validate_directory(state_directory)?;
    load_path(&directory.join(SETTINGS_FILE_NAME))
}

/// Atomically changes the retained reconnection-address budget.
///
/// # Errors
///
/// Rejects out-of-range values, unsafe storage, concurrent mutation, malformed
/// existing settings, and persistence failures.
pub fn set_address_history(state_directory: &Path, address_history: usize) -> Result<Settings, SettingsError> {
    let settings = validated_settings(address_history)?;
    let (directory, _lock) = SettingsLock::acquire(state_directory)?;
    let path = directory.join(SETTINGS_FILE_NAME);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let _existing = load_path(&path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    replace_path(&directory, &path, settings)?;
    Ok(settings)
}

fn validated_settings(address_history: usize) -> Result<Settings, SettingsError> {
    if !(MIN_ADDRESS_HISTORY..=MAX_ADDRESS_HISTORY).contains(&address_history) {
        return Err(SettingsError::InvalidAddressHistory);
    }
    Ok(Settings { address_history })
}

fn load_path(path: &Path) -> Result<Settings, SettingsError> {
    let mut file = match OpenOptions::new().read(true).custom_flags(no_follow_flag()?).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Settings::default()),
        Err(error) => return Err(error.into()),
    };
    validate_owner_file_metadata(&file)?;
    let length = file.metadata()?.len();
    if length == 0 || length > MAX_SETTINGS_BYTES {
        return Err(SettingsError::InvalidFile);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(length).map_err(|_| SettingsError::InvalidFile)?);
    Read::by_ref(&mut file)
        .take(MAX_SETTINGS_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()) != Ok(length) {
        return Err(SettingsError::InvalidFile);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| SettingsError::InvalidFile)?;
    let document: SettingsDocument = toml::from_str(text).map_err(|_| SettingsError::InvalidFile)?;
    if document.version != SETTINGS_VERSION {
        return Err(SettingsError::InvalidFile);
    }
    validated_settings(document.network.address_history).map_err(|_| SettingsError::InvalidFile)
}

fn replace_path(directory: &Path, path: &Path, settings: Settings) -> Result<(), SettingsError> {
    let text = toml::to_string(&SettingsDocument::from(settings)).map_err(|_| SettingsError::InvalidFile)?;
    if text.is_empty() || u64::try_from(text.len()).map_or(true, |length| length > MAX_SETTINGS_BYTES) {
        return Err(SettingsError::InvalidFile);
    }
    let temporary = temporary_path(directory)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(no_follow_flag()?)
            .open(&temporary)?;
        supgang_acl::clear_inherited_acl(&file)?;
        validate_owner_file_metadata(&file)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_directory(directory)?;
        Ok(())
    })();
    if result.is_err() {
        let _cleanup = fs::remove_file(&temporary);
    }
    result
}

fn temporary_path(directory: &Path) -> Result<PathBuf, SettingsError> {
    for _attempt in 0..TEMPORARY_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let candidate = directory.join(format!(".supgang-settings-{}.tmp", hex::encode(random)));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "could not allocate settings replacement").into())
}

struct SettingsLock {
    file: File,
}

impl SettingsLock {
    fn acquire(state_directory: &Path) -> Result<(PathBuf, Self), SettingsError> {
        let directory = validate_directory(state_directory)?;
        let path = directory.join(SETTINGS_LOCK_FILE_NAME);
        let existed = fs::symlink_metadata(&path).is_ok();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(no_follow_flag()?)
            .open(path)?;
        if !existed {
            supgang_acl::clear_inherited_acl(&file)?;
        }
        validate_owner_file_metadata(&file)?;
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::WOULDBLOCK => return Err(SettingsError::Busy),
            Err(error) => return Err(io::Error::from_raw_os_error(error.raw_os_error()).into()),
        }
        if !existed {
            file.sync_all()?;
            sync_directory(&directory)?;
        }
        Ok((directory, Self { file }))
    }
}

impl Drop for SettingsLock {
    fn drop(&mut self) {
        let _result = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::{DEFAULT_ADDRESS_HISTORY, SETTINGS_FILE_NAME, SettingsError, load, set_address_history};
    use crate::state;

    #[test]
    fn missing_settings_use_a_bounded_default_without_creating_a_file() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state_path = temporary.path().join("state");
        let initialized = state::initialize(&state_path)?;
        drop(initialized);
        assert_eq!(load(&state_path)?.address_history(), DEFAULT_ADDRESS_HISTORY);
        assert!(!state_path.join(SETTINGS_FILE_NAME).exists());
        Ok(())
    }

    #[test]
    fn settings_are_owner_only_bounded_and_replaceable() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state_path = temporary.path().join("state");
        let initialized = state::initialize(&state_path)?;
        drop(initialized);
        assert_eq!(set_address_history(&state_path, 32)?.address_history(), 32);
        assert_eq!(load(&state_path)?.address_history(), 32);
        assert_eq!(
            fs::metadata(state_path.join(SETTINGS_FILE_NAME))?.permissions().mode() & 0o777,
            0o600
        );
        assert!(matches!(
            set_address_history(&state_path, 7),
            Err(SettingsError::InvalidAddressHistory)
        ));
        Ok(())
    }

    #[test]
    fn unknown_permissive_and_symlinked_settings_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state_path = temporary.path().join("state");
        let initialized = state::initialize(&state_path)?;
        drop(initialized);
        let path = state_path.join(SETTINGS_FILE_NAME);
        fs::write(&path, "version = 1\nunknown = true\n[network]\naddress_history = 16\n")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert!(load(&state_path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(load(&state_path).is_err());
        fs::remove_file(&path)?;
        let target = temporary.path().join("target");
        fs::write(&target, "version = 1\n[network]\naddress_history = 16\n")?;
        std::os::unix::fs::symlink(&target, &path)?;
        assert!(load(&state_path).is_err());
        fs::remove_file(&path)?;
        let missing_target = temporary.path().join("missing-target");
        std::os::unix::fs::symlink(&missing_target, &path)?;
        assert!(set_address_history(&state_path, 16).is_err());
        assert!(fs::symlink_metadata(&path)?.file_type().is_symlink());
        Ok(())
    }
}
