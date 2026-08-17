//! Protected local identity and state-directory handling.

use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        prelude::MetadataExt,
    },
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    identity::{DeviceIdentity, IdentityError, RootIdentity},
    ids::HiveId,
    journal::{Journal, JournalError},
};

/// Name of the protected local identity file.
pub const IDENTITY_FILE_NAME: &str = "identity.key";
/// Name of the authoritative append-only state journal.
pub const JOURNAL_FILE_NAME: &str = "state.journal";
/// Name of a not-yet-authorized device identity.
pub const PENDING_FILE_NAME: &str = "pending.key";

const IDENTITY_MAGIC: &[u8; 8] = b"SUPGKEY3";
const IDENTITY_DOMAIN: &[u8] = b"supgang/identity-file/v3\0";
const KEY_BYTES: usize = 32;
const CHECKSUM_BYTES: usize = 32;
const ROOT_PRESENT_BYTES: usize = 1;
const IDENTITY_FILE_BYTES: usize =
    IDENTITY_MAGIC.len() + ROOT_PRESENT_BYTES + KEY_BYTES + KEY_BYTES + KEY_BYTES + CHECKSUM_BYTES;
const PENDING_MAGIC: &[u8; 8] = b"SUPGPND1";
const PENDING_DOMAIN: &[u8] = b"supgang/pending-identity/v1\0";
const PENDING_FILE_BYTES: usize = PENDING_MAGIC.len() + KEY_BYTES + KEY_BYTES + CHECKSUM_BYTES;

/// A loaded local hive identity.
pub struct LocalIdentity {
    /// Hive root identity retained only where admission authority is enabled.
    pub root: Option<RootIdentity>,
    /// Root verification key shared by every member.
    pub root_verifying_key: ed25519_dalek::VerifyingKey,
    /// Device signing identity.
    pub device: DeviceIdentity,
    /// Hive identifier associated with the protected key.
    pub hive_id: HiveId,
}

/// A locally protected device key awaiting root authorization.
pub struct PendingIdentity {
    /// Device key generated on the computer that will own it.
    pub device: DeviceIdentity,
    /// High-entropy nonce binding the request to one membership certificate.
    pub request_nonce: [u8; 32],
}

impl core::fmt::Debug for PendingIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PendingIdentity")
            .field("node_id", &self.device.node_id())
            .field("request_nonce", &"<redacted>")
            .finish()
    }
}

impl core::fmt::Debug for LocalIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LocalIdentity")
            .field("root_secret_available", &self.root.is_some())
            .field("root_verifying_key", &"<public>")
            .field("node_id", &self.device.node_id())
            .field("hive_id", &self.hive_id)
            .finish()
    }
}

/// A local initialization result with an open, validated journal.
#[derive(Debug)]
pub struct InitializedState {
    /// Newly generated local identity.
    pub identity: LocalIdentity,
    /// Empty durable journal initialized on disk.
    pub journal: Journal,
}

/// A protected local storage failure.
#[derive(Debug, Error)]
pub enum StorageError {
    /// The operating system rejected a filesystem operation.
    #[error("local state filesystem operation failed")]
    Io(#[from] io::Error),
    /// Secure random generation failed.
    #[error("local identity generation failed")]
    Identity(#[from] IdentityError),
    /// Journal initialization or validation failed.
    #[error("authoritative journal validation failed")]
    Journal(#[from] JournalError),
    /// The state path exists but is not a real directory.
    #[error("state path must be a real directory, not a file or symlink")]
    NotDirectory,
    /// The state directory or file is owned by another user.
    #[error("local state is not owned by the current user")]
    WrongOwner,
    /// The state directory grants access to another user.
    #[error("state directory permissions must be 0700")]
    InsecureDirectoryPermissions,
    /// The protected identity has already been initialized.
    #[error("Supgang is already initialized in this state directory")]
    AlreadyInitialized,
    /// A pending join identity already exists.
    #[error("a join request is already pending in this state directory")]
    PendingAlreadyExists,
    /// No pending join identity exists.
    #[error("no pending join request exists in this state directory")]
    MissingPendingIdentity,
    /// The protected identity file has an unexpected size, marker, or checksum.
    #[error("protected identity file is invalid or corrupt")]
    InvalidIdentityFile,
    /// The pending identity file is malformed or corrupt.
    #[error("pending join identity is invalid or corrupt")]
    InvalidPendingIdentity,
    /// The identity file grants access to another user.
    #[error("protected identity file permissions must be 0600")]
    InsecureIdentityPermissions,
    /// No supported home or state-directory environment is available.
    #[error("cannot determine a default state directory; pass --state-dir")]
    NoDefaultStateDirectory,
}

/// Returns the platform-conventional state directory without touching disk.
///
/// `SUPGANG_STATE_DIR` overrides the platform default. Linux honors
/// `XDG_STATE_HOME`; macOS uses the per-user Application Support directory.
///
/// # Errors
///
/// Returns an error when no explicit path and no home directory are available.
pub fn default_state_directory() -> Result<PathBuf, StorageError> {
    if let Some(path) = env::var_os("SUPGANG_STATE_DIR").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    #[cfg(target_os = "macos")]
    {
        let home = env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .ok_or(StorageError::NoDefaultStateDirectory)?;
        Ok(PathBuf::from(home).join("Library/Application Support/org.agenxy.supgang"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(path) = env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
            return Ok(PathBuf::from(path).join("supgang"));
        }
        let home = env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .ok_or(StorageError::NoDefaultStateDirectory)?;
        Ok(PathBuf::from(home).join(".local/state/supgang"))
    }
}

/// Creates a new protected identity and empty durable journal.
///
/// # Errors
///
/// Fails closed for an existing identity, unsafe ownership or permissions,
/// symlinks, random-source failures, and persistence failures.
pub fn initialize(path: impl AsRef<Path>) -> Result<InitializedState, StorageError> {
    let directory = prepare_directory(path.as_ref())?;
    let identity_path = directory.join(IDENTITY_FILE_NAME);
    if fs::symlink_metadata(&identity_path).is_ok() {
        return Err(StorageError::AlreadyInitialized);
    }

    let root = RootIdentity::generate()?;
    let identity = LocalIdentity {
        hive_id: root.hive_id(),
        root_verifying_key: root.verifying_key(),
        root: Some(root),
        device: DeviceIdentity::generate()?,
    };
    write_identity(&identity_path, &identity)?;
    sync_directory(&directory)?;

    let journal_path = directory.join(JOURNAL_FILE_NAME);
    let (journal, frames) = Journal::open(journal_path)?;
    if !frames.is_empty() {
        return Err(StorageError::AlreadyInitialized);
    }
    sync_directory(&directory)?;
    Ok(InitializedState { identity, journal })
}

/// Loads and validates the protected local identity.
///
/// # Errors
///
/// Rejects unsafe state directories, symlinks, foreign ownership, permissive
/// modes, malformed content, and checksum failures.
pub fn load_identity(path: impl AsRef<Path>) -> Result<LocalIdentity, StorageError> {
    let directory = validate_directory(path.as_ref())?;
    let identity_path = directory.join(IDENTITY_FILE_NAME);
    let no_follow = no_follow_flag()?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(no_follow)
        .open(identity_path)?;
    validate_owner_file_metadata(&file)?;
    let mut bytes = Vec::with_capacity(IDENTITY_FILE_BYTES);
    file.read_to_end(&mut bytes)?;
    decode_identity(&bytes)
}

/// Opens and validates the authoritative journal in an existing state directory.
///
/// # Errors
///
/// Rejects unsafe state directories and any journal integrity failure.
pub fn open_journal(path: impl AsRef<Path>) -> Result<(Journal, Vec<Vec<u8>>), StorageError> {
    let directory = validate_directory(path.as_ref())?;
    Journal::open(directory.join(JOURNAL_FILE_NAME)).map_err(Into::into)
}

/// Generates and durably protects a device key for an offline join request.
///
/// # Errors
///
/// Rejects an initialized or already-pending directory and all unsafe storage
/// conditions.
pub fn create_pending_identity(path: impl AsRef<Path>) -> Result<PendingIdentity, StorageError> {
    let directory = prepare_directory(path.as_ref())?;
    if fs::symlink_metadata(directory.join(IDENTITY_FILE_NAME)).is_ok() {
        return Err(StorageError::AlreadyInitialized);
    }
    let pending_path = directory.join(PENDING_FILE_NAME);
    if fs::symlink_metadata(&pending_path).is_ok() {
        return Err(StorageError::PendingAlreadyExists);
    }
    let mut request_nonce = [0_u8; KEY_BYTES];
    getrandom::fill(&mut request_nonce).map_err(|_| IdentityError::Random)?;
    let pending = PendingIdentity {
        device: DeviceIdentity::generate()?,
        request_nonce,
    };
    write_pending(&pending_path, &pending)?;
    sync_directory(&directory)?;
    Ok(pending)
}

/// Loads a protected pending join identity.
///
/// # Errors
///
/// Rejects missing, unsafe, malformed, or corrupt pending state.
pub fn load_pending_identity(path: impl AsRef<Path>) -> Result<PendingIdentity, StorageError> {
    let directory = validate_directory(path.as_ref())?;
    let pending_path = directory.join(PENDING_FILE_NAME);
    let no_follow = no_follow_flag()?;
    let mut file = match OpenOptions::new().read(true).custom_flags(no_follow).open(pending_path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(StorageError::MissingPendingIdentity),
        Err(error) => return Err(error.into()),
    };
    validate_owner_file_metadata(&file)?;
    let mut bytes = Vec::with_capacity(PENDING_FILE_BYTES);
    file.read_to_end(&mut bytes)?;
    decode_pending(&bytes)
}

/// Converts a pending key into a root-bound member identity and removes the
/// redundant pending secret after the new identity is synchronized.
///
/// # Errors
///
/// Rejects unsafe state, an existing identity, write failure, or cleanup
/// failure. The caller must have validated the root authorization first.
pub fn install_joined_identity(
    path: impl AsRef<Path>,
    pending: PendingIdentity,
    root_verifying_key: ed25519_dalek::VerifyingKey,
) -> Result<LocalIdentity, StorageError> {
    let directory = validate_directory(path.as_ref())?;
    let identity_path = directory.join(IDENTITY_FILE_NAME);
    if fs::symlink_metadata(&identity_path).is_ok() {
        return Err(StorageError::AlreadyInitialized);
    }
    let identity = LocalIdentity {
        hive_id: HiveId::from_root_verifying_key(&root_verifying_key.to_bytes()),
        root: None,
        root_verifying_key,
        device: pending.device,
    };
    write_identity(&identity_path, &identity)?;
    sync_directory(&directory)?;
    fs::remove_file(directory.join(PENDING_FILE_NAME))?;
    sync_directory(&directory)?;
    Ok(identity)
}

pub(crate) fn prepare_directory(path: &Path) -> Result<PathBuf, StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            validate_directory(path)
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn validate_directory(path: &Path) -> Result<PathBuf, StorageError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(StorageError::NotDirectory);
    }
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(StorageError::WrongOwner);
    }
    if metadata.mode() & 0o777 != 0o700 {
        return Err(StorageError::InsecureDirectoryPermissions);
    }
    Ok(path.to_path_buf())
}

fn write_identity(path: &Path, identity: &LocalIdentity) -> Result<(), StorageError> {
    let no_follow = no_follow_flag()?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600).custom_flags(no_follow);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Err(StorageError::AlreadyInitialized),
        Err(error) => return Err(error.into()),
    };
    validate_owner_file_metadata(&file)?;

    let mut root_secret = identity
        .root
        .as_ref()
        .map_or([0; KEY_BYTES], RootIdentity::secret_bytes);
    let mut device_secret = identity.device.secret_bytes();
    let mut payload = Vec::with_capacity(IDENTITY_FILE_BYTES);
    payload.extend_from_slice(IDENTITY_MAGIC);
    payload.push(u8::from(identity.root.is_some()));
    payload.extend_from_slice(&identity.root_verifying_key.to_bytes());
    payload.extend_from_slice(&root_secret);
    payload.extend_from_slice(&device_secret);
    payload.extend_from_slice(&identity_checksum(&payload));
    let write_result = file.write_all(&payload).and_then(|()| file.sync_all());
    root_secret.zeroize();
    device_secret.zeroize();
    payload.zeroize();
    write_result.map_err(Into::into)
}

fn write_pending(path: &Path, pending: &PendingIdentity) -> Result<(), StorageError> {
    let no_follow = no_follow_flag()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(no_follow)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                StorageError::PendingAlreadyExists
            } else {
                error.into()
            }
        })?;
    validate_owner_file_metadata(&file)?;
    let mut device_secret = pending.device.secret_bytes();
    let mut payload = Vec::with_capacity(PENDING_FILE_BYTES);
    payload.extend_from_slice(PENDING_MAGIC);
    payload.extend_from_slice(&device_secret);
    payload.extend_from_slice(&pending.request_nonce);
    payload.extend_from_slice(&pending_checksum(&payload));
    let result = file.write_all(&payload).and_then(|()| file.sync_all());
    device_secret.zeroize();
    payload.zeroize();
    result.map_err(Into::into)
}

fn decode_identity(bytes: &[u8]) -> Result<LocalIdentity, StorageError> {
    if bytes.len() != IDENTITY_FILE_BYTES || bytes.get(..IDENTITY_MAGIC.len()) != Some(IDENTITY_MAGIC) {
        return Err(StorageError::InvalidIdentityFile);
    }
    let data_end = IDENTITY_MAGIC.len() + ROOT_PRESENT_BYTES + KEY_BYTES + KEY_BYTES + KEY_BYTES;
    let data = bytes.get(..data_end).ok_or(StorageError::InvalidIdentityFile)?;
    let stored_checksum = bytes.get(data_end..).ok_or(StorageError::InvalidIdentityFile)?;
    if identity_checksum(data).as_slice() != stored_checksum {
        return Err(StorageError::InvalidIdentityFile);
    }
    let marker_index = IDENTITY_MAGIC.len();
    let root_key_start = marker_index + ROOT_PRESENT_BYTES;
    let root_key_end = root_key_start + KEY_BYTES;
    let root_secret_end = root_key_end + KEY_BYTES;
    let device_end = root_secret_end + KEY_BYTES;
    let marker = *bytes.get(marker_index).ok_or(StorageError::InvalidIdentityFile)?;
    let root_key_bytes: [u8; KEY_BYTES] = bytes
        .get(root_key_start..root_key_end)
        .ok_or(StorageError::InvalidIdentityFile)?
        .try_into()
        .map_err(|_| StorageError::InvalidIdentityFile)?;
    let root_verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&root_key_bytes).map_err(|_| StorageError::InvalidIdentityFile)?;
    let root_secret = bytes
        .get(root_key_end..root_secret_end)
        .ok_or(StorageError::InvalidIdentityFile)?;
    let root = match marker {
        0 if root_secret.iter().all(|byte| *byte == 0) => None,
        1 => {
            let root = RootIdentity::from_secret_bytes(root_secret)?;
            if root.verifying_key() != root_verifying_key {
                return Err(StorageError::InvalidIdentityFile);
            }
            Some(root)
        }
        _ => return Err(StorageError::InvalidIdentityFile),
    };
    let device = DeviceIdentity::from_secret_bytes(
        bytes
            .get(root_secret_end..device_end)
            .ok_or(StorageError::InvalidIdentityFile)?,
    )?;
    Ok(LocalIdentity {
        hive_id: HiveId::from_root_verifying_key(&root_verifying_key.to_bytes()),
        root_verifying_key,
        root,
        device,
    })
}

fn decode_pending(bytes: &[u8]) -> Result<PendingIdentity, StorageError> {
    if bytes.len() != PENDING_FILE_BYTES || bytes.get(..PENDING_MAGIC.len()) != Some(PENDING_MAGIC) {
        return Err(StorageError::InvalidPendingIdentity);
    }
    let data_end = PENDING_MAGIC.len() + KEY_BYTES + KEY_BYTES;
    let data = bytes.get(..data_end).ok_or(StorageError::InvalidPendingIdentity)?;
    let stored_checksum = bytes.get(data_end..).ok_or(StorageError::InvalidPendingIdentity)?;
    if pending_checksum(data).as_slice() != stored_checksum {
        return Err(StorageError::InvalidPendingIdentity);
    }
    let device_start = PENDING_MAGIC.len();
    let device_end = device_start + KEY_BYTES;
    let nonce_end = device_end + KEY_BYTES;
    let device = DeviceIdentity::from_secret_bytes(
        bytes
            .get(device_start..device_end)
            .ok_or(StorageError::InvalidPendingIdentity)?,
    )?;
    let request_nonce = bytes
        .get(device_end..nonce_end)
        .ok_or(StorageError::InvalidPendingIdentity)?
        .try_into()
        .map_err(|_| StorageError::InvalidPendingIdentity)?;
    Ok(PendingIdentity { device, request_nonce })
}

fn identity_checksum(data: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_DOMAIN);
    hasher.update(data);
    hasher.finalize().into()
}

fn pending_checksum(data: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(PENDING_DOMAIN);
    hasher.update(data);
    hasher.finalize().into()
}

pub(crate) fn validate_owner_file_metadata(file: &File) -> Result<(), StorageError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(StorageError::InvalidIdentityFile);
    }
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(StorageError::WrongOwner);
    }
    if metadata.mode() & 0o777 != 0o600 {
        return Err(StorageError::InsecureIdentityPermissions);
    }
    Ok(())
}

pub(crate) fn no_follow_flag() -> Result<i32, StorageError> {
    i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).map_err(|_| StorageError::InvalidIdentityFile)
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), StorageError> {
    File::open(path)?.sync_all().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::{
        StorageError, create_pending_identity, initialize, load_identity, load_pending_identity, open_journal,
    };

    #[test]
    fn initialize_and_load_preserves_public_identity() -> Result<(), Box<dyn std::error::Error>> {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("state");
        let initialized = initialize(&path)?;
        let expected_node = initialized.identity.device.node_id();
        let expected_hive = initialized.identity.hive_id;
        drop(initialized);

        let loaded = load_identity(&path)?;
        assert_eq!(loaded.device.node_id(), expected_node);
        assert_eq!(loaded.hive_id, expected_hive);
        let (_, frames) = open_journal(&path)?;
        assert!(frames.is_empty());
        Ok(())
    }

    #[test]
    fn reinitialization_and_insecure_directory_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("state");
        drop(initialize(&path)?);
        assert!(matches!(initialize(&path), Err(StorageError::AlreadyInitialized)));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        assert!(matches!(
            load_identity(&path),
            Err(StorageError::InsecureDirectoryPermissions)
        ));
        Ok(())
    }

    #[test]
    fn identity_corruption_is_detected() -> Result<(), Box<dyn std::error::Error>> {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("state");
        drop(initialize(&path)?);
        let identity_path = path.join("identity.key");
        let mut bytes = fs::read(&identity_path)?;
        let byte = bytes.get_mut(9).ok_or("test identity file was unexpectedly short")?;
        *byte ^= 1;
        fs::write(identity_path, bytes)?;
        assert!(matches!(load_identity(&path), Err(StorageError::InvalidIdentityFile)));
        Ok(())
    }

    #[test]
    fn pending_identity_is_local_and_durable() -> Result<(), Box<dyn std::error::Error>> {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("state");
        let pending = create_pending_identity(&path)?;
        let loaded = load_pending_identity(&path)?;
        assert_eq!(loaded.device.node_id(), pending.device.node_id());
        assert_eq!(loaded.request_nonce, pending.request_nonce);
        assert!(matches!(
            create_pending_identity(&path),
            Err(StorageError::PendingAlreadyExists)
        ));
        Ok(())
    }
}
