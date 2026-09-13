//! Bounded, owner-only local nicknames for cryptographic peer identities.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ids::NodeId,
    state::MAX_HIVE_MEMBERS,
    storage::{self, no_follow_flag, sync_directory, validate_directory, validate_owner_file_metadata},
};

/// Name of the owner-only local peer-tag document.
pub const PEER_TAG_FILE_NAME: &str = "peer-tags.json";
/// Maximum bytes in one shell-friendly peer tag.
pub const MAX_PEER_TAG_BYTES: usize = 32;
/// Maximum local tags retained for one peer.
pub const MAX_TAGS_PER_PEER: usize = 8;

const PEER_TAG_LOCK_FILE_NAME: &str = "peer-tags.lock";
const PEER_TAG_VERSION: u16 = 1;
const MAX_PEER_TAG_FILE_BYTES: u64 = 128 * 1024;
const TEMPORARY_ATTEMPTS: usize = 8;
const RESERVED_TAGS: &[&str] = &[
    "anchor",
    "doctor",
    "config",
    "help",
    "import",
    "init",
    "invite",
    "join",
    "join-request",
    "mcp",
    "name",
    "peers",
    "publish",
    "resolve",
    "revoke",
    "run",
    "service",
    "status",
    "tag",
    "untag",
];

/// A shell-friendly local nickname that never replaces a stable node ID.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PeerTag(String);

impl PeerTag {
    /// Validates a local nickname and rejects top-level command collisions.
    ///
    /// # Errors
    ///
    /// Rejects padded, overlong, non-ASCII, punctuation-only, or reserved tags.
    pub fn new(value: impl Into<String>) -> Result<Self, PeerTagError> {
        let value = value.into();
        let valid_boundary = value
            .as_bytes()
            .first()
            .zip(value.as_bytes().last())
            .is_some_and(|(first, last)| first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric());
        if value.is_empty()
            || value.len() > MAX_PEER_TAG_BYTES
            || value.trim() != value
            || !valid_boundary
            || !value.bytes().all(is_tag_byte)
        {
            return Err(PeerTagError::InvalidTag);
        }
        if RESERVED_TAGS
            .iter()
            .any(|reserved| value.eq_ignore_ascii_case(reserved))
        {
            return Err(PeerTagError::ReservedTag);
        }
        Ok(Self(value))
    }

    /// Returns the user-provided display spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PeerTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl core::fmt::Display for PeerTag {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl core::str::FromStr for PeerTag {
    type Err = PeerTagError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value.to_owned())
    }
}

/// Validated local peer-tag state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PeerTags {
    tags: BTreeMap<NodeId, Vec<PeerTag>>,
}

impl PeerTags {
    /// Returns a peer's tags in deterministic case-insensitive order.
    #[must_use]
    pub fn for_peer(&self, node_id: &NodeId) -> Vec<String> {
        self.tags
            .get(node_id)
            .into_iter()
            .flatten()
            .map(ToString::to_string)
            .collect()
    }

    /// Finds the stable identity assigned an exact local tag.
    #[must_use]
    pub fn find(&self, tag: &str) -> Option<NodeId> {
        self.tags.iter().find_map(|(node_id, tags)| {
            tags.iter()
                .any(|candidate| candidate.as_str().eq_ignore_ascii_case(tag))
                .then_some(*node_id)
        })
    }

    /// Reports whether a selector is one of a peer's local tags.
    #[must_use]
    pub fn matches(&self, node_id: &NodeId, selector: &str) -> bool {
        self.tags.get(node_id).is_some_and(|tags| {
            tags.iter()
                .any(|candidate| candidate.as_str().eq_ignore_ascii_case(selector))
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PeerTagDocument {
    version: u16,
    tags: BTreeMap<NodeId, Vec<PeerTag>>,
}

/// Result of adding or removing one local peer tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerTagMutation {
    /// Stable cryptographic identity whose local annotation changed.
    pub node_id: NodeId,
    /// Exact user-provided tag involved in the mutation.
    pub tag: PeerTag,
    /// Complete remaining tag set for the peer.
    pub tags: Vec<String>,
    /// Whether durable state changed.
    pub changed: bool,
}

/// A peer-tag validation, concurrency, or persistence failure.
#[derive(Debug, Error)]
pub enum PeerTagError {
    /// The tag is not safe and convenient at the command line.
    #[error(
        "peer tag must be 1 through 32 ASCII letters, digits, dots, underscores, or hyphens and start and end with a letter or digit"
    )]
    InvalidTag,
    /// The tag would hide an existing top-level Supgang command.
    #[error("peer tag conflicts with a Supgang command; choose another tag")]
    ReservedTag,
    /// One tag must identify at most one cryptographic peer identity.
    #[error("peer tag is already assigned to another computer")]
    TagConflict,
    /// The requested exact tag is not retained.
    #[error("no peer has that tag; run `supgang` to list computers and their tags")]
    UnknownTag,
    /// The bounded local annotation budget was exhausted.
    #[error("peer tag limit reached; remove an existing tag before adding another")]
    TagLimit,
    /// Another tag command currently owns the local annotation file.
    #[error("another peer tag change is in progress; retry the command")]
    Busy,
    /// The protected state directory failed validation.
    #[error("peer tag state directory failed validation")]
    Storage(#[from] storage::StorageError),
    /// The operating system rejected a tag-file operation.
    #[error("peer tag filesystem operation failed")]
    Io(#[from] io::Error),
    /// Existing bytes are malformed, oversized, unsupported, or ambiguous.
    #[error("peer tag file is invalid or corrupt")]
    InvalidFile,
}

/// Loads tags without creating a missing document or lock file.
///
/// # Errors
///
/// Rejects unsafe state paths, symlinks, permissive files, malformed content,
/// duplicate case-insensitive tags, and every configured size limit violation.
pub fn load(state_directory: &Path) -> Result<PeerTags, PeerTagError> {
    let directory = validate_directory(state_directory)?;
    load_path(&directory.join(PEER_TAG_FILE_NAME))
}

/// Adds a local tag under an exclusive, non-blocking annotation lock.
///
/// # Errors
///
/// Rejects invalid or conflicting tags, unsafe storage, concurrent mutation,
/// configured limits, and persistence failures.
pub fn add(state_directory: &Path, node_id: NodeId, tag: PeerTag) -> Result<PeerTagMutation, PeerTagError> {
    let (directory, _lock) = PeerTagLock::acquire(state_directory)?;
    let path = directory.join(PEER_TAG_FILE_NAME);
    let mut document = load_document(&path)?;
    if let Some(existing_node) = find_tag(&document.tags, tag.as_str()) {
        if existing_node != node_id {
            return Err(PeerTagError::TagConflict);
        }
        return Ok(PeerTagMutation {
            node_id,
            tag,
            tags: strings_for_peer(&document.tags, &node_id),
            changed: false,
        });
    }
    if !document.tags.contains_key(&node_id) && document.tags.len() >= MAX_HIVE_MEMBERS.saturating_sub(1) {
        return Err(PeerTagError::TagLimit);
    }
    let tags = document.tags.entry(node_id).or_default();
    if tags.len() >= MAX_TAGS_PER_PEER {
        return Err(PeerTagError::TagLimit);
    }
    tags.push(tag.clone());
    tags.sort_by_key(|value| value.as_str().to_ascii_lowercase());
    replace_path(&directory, &path, &document)?;
    Ok(PeerTagMutation {
        node_id,
        tag,
        tags: strings_for_peer(&document.tags, &node_id),
        changed: true,
    })
}

/// Removes one exact local tag wherever it is assigned.
///
/// # Errors
///
/// Rejects an unknown or invalid tag, unsafe storage, concurrent mutation, and
/// persistence failures.
pub fn remove(state_directory: &Path, tag: PeerTag) -> Result<PeerTagMutation, PeerTagError> {
    let (directory, _lock) = PeerTagLock::acquire(state_directory)?;
    let path = directory.join(PEER_TAG_FILE_NAME);
    let mut document = load_document(&path)?;
    let node_id = find_tag(&document.tags, tag.as_str()).ok_or(PeerTagError::UnknownTag)?;
    let tags = document.tags.get_mut(&node_id).ok_or(PeerTagError::UnknownTag)?;
    let before = tags.len();
    tags.retain(|candidate| !candidate.as_str().eq_ignore_ascii_case(tag.as_str()));
    if tags.len() == before {
        return Err(PeerTagError::UnknownTag);
    }
    if tags.is_empty() {
        document.tags.remove(&node_id);
    }
    replace_path(&directory, &path, &document)?;
    Ok(PeerTagMutation {
        node_id,
        tag,
        tags: strings_for_peer(&document.tags, &node_id),
        changed: true,
    })
}

fn load_path(path: &Path) -> Result<PeerTags, PeerTagError> {
    let document = load_document(path)?;
    validate_document(&document)?;
    Ok(PeerTags { tags: document.tags })
}

fn load_document(path: &Path) -> Result<PeerTagDocument, PeerTagError> {
    let mut file = match OpenOptions::new().read(true).custom_flags(no_follow_flag()?).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(PeerTagDocument {
                version: PEER_TAG_VERSION,
                tags: BTreeMap::new(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    validate_owner_file_metadata(&file)?;
    let length = file.metadata()?.len();
    if length == 0 || length > MAX_PEER_TAG_FILE_BYTES {
        return Err(PeerTagError::InvalidFile);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(length).map_err(|_| PeerTagError::InvalidFile)?);
    Read::by_ref(&mut file)
        .take(MAX_PEER_TAG_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()) != Ok(length) {
        return Err(PeerTagError::InvalidFile);
    }
    let document = serde_json::from_slice(&bytes).map_err(|_| PeerTagError::InvalidFile)?;
    validate_document(&document)?;
    Ok(document)
}

fn validate_document(document: &PeerTagDocument) -> Result<(), PeerTagError> {
    if document.version != PEER_TAG_VERSION || document.tags.len() >= MAX_HIVE_MEMBERS {
        return Err(PeerTagError::InvalidFile);
    }
    let mut normalized = BTreeSet::new();
    for tags in document.tags.values() {
        if tags.is_empty() || tags.len() > MAX_TAGS_PER_PEER {
            return Err(PeerTagError::InvalidFile);
        }
        for tag in tags {
            if !normalized.insert(tag.as_str().to_ascii_lowercase()) {
                return Err(PeerTagError::InvalidFile);
            }
        }
    }
    Ok(())
}

fn replace_path(directory: &Path, path: &Path, document: &PeerTagDocument) -> Result<(), PeerTagError> {
    validate_document(document)?;
    if path.exists() {
        let _existing = load_document(path)?;
    }
    let bytes = serde_json::to_vec(document).map_err(|_| PeerTagError::InvalidFile)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).map_or(true, |length| length > MAX_PEER_TAG_FILE_BYTES) {
        return Err(PeerTagError::InvalidFile);
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

fn temporary_path(directory: &Path) -> Result<PathBuf, PeerTagError> {
    for _attempt in 0..TEMPORARY_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let candidate = directory.join(format!(".supgang-peer-tags-{}.tmp", hex::encode(random)));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "could not allocate peer tag replacement").into())
}

fn find_tag(tags: &BTreeMap<NodeId, Vec<PeerTag>>, selector: &str) -> Option<NodeId> {
    tags.iter().find_map(|(node_id, values)| {
        values
            .iter()
            .any(|value| value.as_str().eq_ignore_ascii_case(selector))
            .then_some(*node_id)
    })
}

fn strings_for_peer(tags: &BTreeMap<NodeId, Vec<PeerTag>>, node_id: &NodeId) -> Vec<String> {
    tags.get(node_id)
        .into_iter()
        .flatten()
        .map(ToString::to_string)
        .collect()
}

const fn is_tag_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

struct PeerTagLock {
    file: File,
}

impl PeerTagLock {
    fn acquire(state_directory: &Path) -> Result<(PathBuf, Self), PeerTagError> {
        let directory = validate_directory(state_directory)?;
        let path = directory.join(PEER_TAG_LOCK_FILE_NAME);
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
            Err(error) if error == rustix::io::Errno::WOULDBLOCK => return Err(PeerTagError::Busy),
            Err(error) => return Err(io::Error::from_raw_os_error(error.raw_os_error()).into()),
        }
        if !existed {
            file.sync_all()?;
            sync_directory(&directory)?;
        }
        Ok((directory, Self { file }))
    }
}

impl Drop for PeerTagLock {
    fn drop(&mut self) {
        let _result = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::{PEER_TAG_FILE_NAME, PeerTag, PeerTagError, PeerTagLock, add, load, remove};
    use crate::{ids::NodeId, state};

    #[test]
    fn validates_shell_friendly_non_command_tags() {
        for valid in ["home", "office-mac", "lab_2", "node.example"] {
            assert!(PeerTag::new(valid).is_ok(), "rejected {valid}");
        }
        for invalid in ["", "two words", "-flag", "end-", "lookalаike", "status"] {
            assert!(PeerTag::new(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn tags_are_owner_only_unique_and_removable() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state_path = temporary.path().join("state");
        let initialized = state::initialize(&state_path)?;
        drop(initialized);
        let first = NodeId::from_bytes([1; 32]);
        let second = NodeId::from_bytes([2; 32]);

        let added = add(&state_path, first, PeerTag::new("home")?)?;
        assert!(added.changed);
        assert_eq!(added.tags, ["home"]);
        assert!(!add(&state_path, first, PeerTag::new("HOME")?)?.changed);
        assert!(matches!(
            add(&state_path, second, PeerTag::new("Home")?),
            Err(PeerTagError::TagConflict)
        ));
        assert_eq!(load(&state_path)?.find("HOME"), Some(first));
        assert_eq!(
            fs::metadata(state_path.join(PEER_TAG_FILE_NAME))?.permissions().mode() & 0o777,
            0o600
        );

        let removed = remove(&state_path, PeerTag::new("hOmE")?)?;
        assert_eq!(removed.node_id, first);
        assert!(removed.tags.is_empty());
        assert!(load(&state_path)?.find("home").is_none());
        Ok(())
    }

    #[test]
    fn corrupt_permissive_and_symlinked_documents_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state_path = temporary.path().join("state");
        let initialized = state::initialize(&state_path)?;
        drop(initialized);
        let path = state_path.join(PEER_TAG_FILE_NAME);
        fs::write(&path, br#"{"version":1,"tags":{}}"#)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert!(load(&state_path).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(load(&state_path).is_err());
        fs::remove_file(&path)?;
        let target = temporary.path().join("target");
        fs::write(&target, br#"{"version":1,"tags":{}}"#)?;
        std::os::unix::fs::symlink(&target, &path)?;
        assert!(load(&state_path).is_err());
        Ok(())
    }

    #[test]
    fn concurrent_tag_mutation_fails_instead_of_losing_an_update() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state_path = temporary.path().join("state");
        let initialized = state::initialize(&state_path)?;
        drop(initialized);
        let (_directory, lock) = PeerTagLock::acquire(&state_path)?;
        assert!(matches!(
            add(&state_path, NodeId::from_bytes([1; 32]), PeerTag::new("home")?),
            Err(PeerTagError::Busy)
        ));
        drop(lock);
        assert!(add(&state_path, NodeId::from_bytes([1; 32]), PeerTag::new("home")?)?.changed);
        Ok(())
    }
}
