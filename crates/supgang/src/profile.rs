//! Bounded local display-name policy and protected profile persistence.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ids::NodeId,
    storage::{self, no_follow_flag, sync_directory, validate_directory, validate_owner_file_metadata},
};

/// Name of the owner-only local profile.
pub const PROFILE_FILE_NAME: &str = "profile.json";
/// Maximum UTF-8 bytes accepted in a peer display name.
pub const MAX_PEER_NAME_BYTES: usize = 63;

const PROFILE_VERSION: u16 = 1;
const MAX_PROFILE_BYTES: usize = 256;

/// A portable, human-readable label that never replaces a stable node ID.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PeerName(String);

impl PeerName {
    /// Validates a user- or platform-supplied display name.
    ///
    /// Names are deliberately limited to a portable ASCII subset. This keeps
    /// terminal rendering deterministic and excludes control characters and
    /// Unicode confusables from identity-adjacent output.
    ///
    /// # Errors
    ///
    /// Rejects empty, overlong, padded, or non-portable names.
    pub fn new(value: impl Into<String>) -> Result<Self, ProfileError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PEER_NAME_BYTES
            || value.trim() != value
            || !value.bytes().all(is_name_byte)
        {
            return Err(ProfileError::InvalidName);
        }
        Ok(Self(value))
    }

    /// Returns the canonical display text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for PeerName {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileDocument {
    version: u16,
    name: PeerName,
}

/// A profile validation or persistence failure.
#[derive(Debug, Error)]
pub enum ProfileError {
    /// The name is not a safe portable display label.
    #[error("computer name must be 1 through 63 ASCII letters, digits, spaces, dots, underscores, or hyphens")]
    InvalidName,
    /// The protected state directory failed validation.
    #[error("computer profile state directory failed validation")]
    Storage(#[from] storage::StorageError),
    /// A filesystem operation failed.
    #[error("computer profile filesystem operation failed")]
    Io(#[from] io::Error),
    /// Existing profile bytes are malformed, oversized, or unsupported.
    #[error("computer profile is invalid or corrupt")]
    InvalidProfile,
}

/// Loads the protected name, or derives and persists one from the operating
/// system hostname on first use.
///
/// # Errors
///
/// Rejects unsafe state paths and malformed existing profiles. A hostname that
/// is absent or outside the portable name policy falls back to a stable label
/// derived from the non-secret node fingerprint.
pub fn load_or_create(state_directory: &Path, node_id: NodeId) -> Result<PeerName, ProfileError> {
    let directory = validate_directory(state_directory)?;
    let path = directory.join(PROFILE_FILE_NAME);
    match load_path(&path) {
        Ok(name) => Ok(name),
        Err(ProfileError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            let name = automatic_name(node_id);
            replace_path(&directory, &path, &name)?;
            Ok(name)
        }
        Err(error) => Err(error),
    }
}

/// Replaces the local display name atomically.
///
/// # Errors
///
/// Rejects unsafe paths, invalid names, and any write, synchronization, or
/// atomic-replacement failure.
pub fn set(state_directory: &Path, name: &PeerName) -> Result<(), ProfileError> {
    let directory = validate_directory(state_directory)?;
    let path = directory.join(PROFILE_FILE_NAME);
    if path.exists() {
        let _existing = load_path(&path)?;
    }
    replace_path(&directory, &path, name)
}

fn automatic_name(node_id: NodeId) -> PeerName {
    if let Some(hostname) = gethostname::gethostname().to_str() {
        let without_local = hostname.strip_suffix(".local").unwrap_or(hostname);
        if let Ok(name) = PeerName::new(without_local.to_owned()) {
            return name;
        }
    }
    let fingerprint = node_id.to_string();
    let suffix = fingerprint.get(..8).unwrap_or("unknown");
    PeerName(format!("computer-{suffix}"))
}

fn load_path(path: &Path) -> Result<PeerName, ProfileError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(no_follow_flag()?)
        .open(path)?;
    validate_owner_file_metadata(&file)?;
    let length = usize::try_from(file.metadata()?.len()).map_err(|_| ProfileError::InvalidProfile)?;
    if length == 0 || length > MAX_PROFILE_BYTES {
        return Err(ProfileError::InvalidProfile);
    }
    let mut bytes = Vec::with_capacity(length);
    std::io::Read::read_to_end(&mut file, &mut bytes)?;
    let document: ProfileDocument = serde_json::from_slice(&bytes).map_err(|_| ProfileError::InvalidProfile)?;
    if document.version != PROFILE_VERSION {
        return Err(ProfileError::InvalidProfile);
    }
    PeerName::new(document.name.0).map_err(|_| ProfileError::InvalidProfile)
}

fn replace_path(directory: &Path, path: &Path, name: &PeerName) -> Result<(), ProfileError> {
    let document = ProfileDocument {
        version: PROFILE_VERSION,
        name: name.clone(),
    };
    let bytes = serde_json::to_vec(&document).map_err(|_| ProfileError::InvalidProfile)?;
    if bytes.is_empty() || bytes.len() > MAX_PROFILE_BYTES {
        return Err(ProfileError::InvalidProfile);
    }
    let temporary = temporary_path(directory)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(no_follow_flag()?)
            .open(&temporary)?;
        validate_owner_file_metadata(&file)?;
        file.write_all(&bytes)?;
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

fn temporary_path(directory: &Path) -> Result<PathBuf, ProfileError> {
    for _attempt in 0..8 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let candidate = directory.join(format!(".supgang-profile-{}.tmp", hex::encode(random)));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "could not allocate profile replacement").into())
}

const fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'.' | b'_' | b'-')
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::{PeerName, ProfileError, load_or_create, set};
    use crate::{ids::NodeId, state};

    #[test]
    fn validates_portable_human_names() {
        assert!(PeerName::new("Solis").is_ok());
        assert!(PeerName::new("Lael MacBook Pro").is_ok());
        for invalid in ["", " padded", "line\nbreak", "lookalаike", "name/slash"] {
            assert!(matches!(PeerName::new(invalid), Err(ProfileError::InvalidName)));
        }
    }

    #[test]
    fn automatic_profile_is_owner_only_and_user_replaceable() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state_path = temporary.path().join("state");
        let local = state::initialize(&state_path)?;
        let node = local.identity().device.node_id();
        let automatic = load_or_create(&state_path, node)?;
        assert!(!automatic.as_str().is_empty());
        set(&state_path, &PeerName::new("Solis")?)?;
        assert_eq!(load_or_create(&state_path, node)?.as_str(), "Solis");
        assert_eq!(
            fs::metadata(state_path.join(super::PROFILE_FILE_NAME))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        Ok(())
    }

    #[test]
    fn symlinked_or_permissive_profile_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state_path = temporary.path().join("state");
        let local = state::initialize(&state_path)?;
        let node = local.identity().device.node_id();
        let target = temporary.path().join("target");
        fs::write(&target, br#"{"version":1,"name":"fake"}"#)?;
        std::os::unix::fs::symlink(&target, state_path.join(super::PROFILE_FILE_NAME))?;
        assert!(load_or_create(&state_path, node).is_err());
        fs::remove_file(state_path.join(super::PROFILE_FILE_NAME))?;
        let _name = load_or_create(&state_path, node)?;
        fs::set_permissions(
            state_path.join(super::PROFILE_FILE_NAME),
            fs::Permissions::from_mode(0o644),
        )?;
        assert!(load_or_create(&state_path, node).is_err());
        Ok(())
    }

    #[test]
    fn fallback_label_is_stable_for_an_invalid_hostname_policy() {
        let node = NodeId::from_bytes([0xab; 32]);
        let fallback = format!("computer-{}", &node.to_string()[..8]);
        assert!(PeerName::new(fallback).is_ok());
    }
}
