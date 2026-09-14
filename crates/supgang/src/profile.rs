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
    record::{MAX_SERVICE_ADVERTS, ServiceAdvert, ServiceName, validate_services},
    storage::{self, no_follow_flag, sync_directory, validate_directory, validate_owner_file_metadata},
};

/// Name of the owner-only local profile.
pub const PROFILE_FILE_NAME: &str = "profile.json";
/// Maximum UTF-8 bytes accepted in a peer display name.
pub const MAX_PEER_NAME_BYTES: usize = 63;

const PROFILE_VERSION: u16 = 1;
/// Room for the name and four service advertisements written as hex.
const MAX_PROFILE_BYTES: usize = 1_024;

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
    /// Services this computer advertises in its signed record; absent in
    /// profiles written before advertisements existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    services: Vec<ServiceAdvert>,
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
    /// A service advertisement is invalid or would exceed the record bound.
    #[error("service advertisement is invalid")]
    Service(#[from] crate::record::RecordError),
    /// The record already carries the maximum number of advertisements.
    #[error("a computer advertises at most {MAX_SERVICE_ADVERTS} services; unadvertise one first")]
    TooManyServices,
    /// No advertisement has the given name.
    #[error("this computer does not advertise a service by that name")]
    UnknownService,
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
        Ok(document) => Ok(document.name),
        Err(ProfileError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            let name = automatic_name(node_id);
            replace_path(&directory, &path, &ProfileDocument::new(name.clone(), Vec::new()))?;
            Ok(name)
        }
        Err(error) => Err(error),
    }
}

/// Loads the existing protected display name without creating one.
///
/// # Errors
///
/// Rejects missing, unsafe, malformed, oversized, or unsupported profiles.
pub fn load(state_directory: &Path) -> Result<PeerName, ProfileError> {
    let directory = validate_directory(state_directory)?;
    Ok(load_path(&directory.join(PROFILE_FILE_NAME))?.name)
}

/// Loads the services this computer advertises: empty when there is no
/// profile yet or it names none.
///
/// # Errors
///
/// Rejects unsafe, malformed, oversized, or unsupported profiles.
pub fn services(state_directory: &Path) -> Result<Vec<ServiceAdvert>, ProfileError> {
    let directory = validate_directory(state_directory)?;
    match load_path(&directory.join(PROFILE_FILE_NAME)) {
        Ok(document) => Ok(document.services),
        Err(ProfileError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

/// Adds or replaces one service advertisement, creating the profile with an
/// automatic name when there is none yet. Returns the advertised set.
///
/// # Errors
///
/// Rejects unsafe paths, a fifth distinct service, and any persistence failure.
pub fn advertise(
    state_directory: &Path,
    node_id: NodeId,
    advert: ServiceAdvert,
) -> Result<Vec<ServiceAdvert>, ProfileError> {
    let directory = validate_directory(state_directory)?;
    let path = directory.join(PROFILE_FILE_NAME);
    // Validated before it is stored, not only when it is read back: a
    // profile that persists an advertisement the record refuses would report
    // success here and then refuse to load, which stops the service and
    // every ordinary profile edit after it.
    advert.validate()?;
    let mut document = load_or_automatic(&path, node_id)?;
    document.services.retain(|existing| existing.name != advert.name);
    if document.services.len() >= MAX_SERVICE_ADVERTS {
        return Err(ProfileError::TooManyServices);
    }
    document.services.push(advert);
    document.services.sort_unstable();
    validate_services(&document.services)?;
    replace_path(&directory, &path, &document)?;
    Ok(document.services)
}

/// Removes one service advertisement by name. Returns the advertised set.
///
/// # Errors
///
/// Rejects unsafe paths, a name this computer does not advertise, and any
/// persistence failure.
pub fn unadvertise(
    state_directory: &Path,
    node_id: NodeId,
    name: &ServiceName,
) -> Result<Vec<ServiceAdvert>, ProfileError> {
    let directory = validate_directory(state_directory)?;
    let path = directory.join(PROFILE_FILE_NAME);
    let mut document = load_or_automatic(&path, node_id)?;
    let before = document.services.len();
    document.services.retain(|existing| existing.name != *name);
    if document.services.len() == before {
        return Err(ProfileError::UnknownService);
    }
    replace_path(&directory, &path, &document)?;
    Ok(document.services)
}

fn load_or_automatic(path: &Path, node_id: NodeId) -> Result<ProfileDocument, ProfileError> {
    match load_path(path) {
        Ok(document) => Ok(document),
        Err(ProfileError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            Ok(ProfileDocument::new(automatic_name(node_id), Vec::new()))
        }
        Err(error) => Err(error),
    }
}

impl ProfileDocument {
    const fn new(name: PeerName, services: Vec<ServiceAdvert>) -> Self {
        Self {
            version: PROFILE_VERSION,
            name,
            services,
        }
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
    let services = if path.exists() {
        load_path(&path)?.services
    } else {
        Vec::new()
    };
    replace_path(&directory, &path, &ProfileDocument::new(name.clone(), services))
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

fn load_path(path: &Path) -> Result<ProfileDocument, ProfileError> {
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
    std::io::Read::read_to_end(
        &mut std::io::Read::take(
            std::io::Read::by_ref(&mut file),
            u64::try_from(MAX_PROFILE_BYTES.saturating_add(1)).map_err(|_| ProfileError::InvalidProfile)?,
        ),
        &mut bytes,
    )?;
    if bytes.len() != length {
        return Err(ProfileError::InvalidProfile);
    }
    let document: ProfileDocument = serde_json::from_slice(&bytes).map_err(|_| ProfileError::InvalidProfile)?;
    if document.version != PROFILE_VERSION {
        return Err(ProfileError::InvalidProfile);
    }
    let name = PeerName::new(document.name.0).map_err(|_| ProfileError::InvalidProfile)?;
    let services = document.services;
    // The record's own rules, so a profile edited by hand cannot make this
    // computer sign a record every other member rejects.
    validate_services(&services).map_err(|_| ProfileError::InvalidProfile)?;
    Ok(ProfileDocument::new(name, services))
}

fn replace_path(directory: &Path, path: &Path, document: &ProfileDocument) -> Result<(), ProfileError> {
    let bytes = serde_json::to_vec(document).map_err(|_| ProfileError::InvalidProfile)?;
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

    use super::{PeerName, ProfileError, advertise, load_or_create, services, set, unadvertise};
    use crate::{
        ids::NodeId,
        record::{MAX_SERVICE_ADVERTS, ServiceAdvert, ServiceName},
        state,
    };

    #[test]
    fn validates_portable_human_names() {
        assert!(PeerName::new("HomeServer").is_ok());
        assert!(PeerName::new("Alice MacBook Pro").is_ok());
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
        set(&state_path, &PeerName::new("HomeServer")?)?;
        assert_eq!(load_or_create(&state_path, node)?.as_str(), "HomeServer");
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

    // Advertising a service is a change to the profile beside the name: it
    // survives a rename, is bounded, replaces by name, and comes back sorted
    // so the signed record is canonical without further work.
    #[test]
    fn service_advertisements_live_beside_the_name() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state_path = temporary.path().join("state");
        let local = state::initialize(&state_path)?;
        let node = local.identity().device.node_id();
        assert!(services(&state_path)?.is_empty(), "no profile yet means no services");
        let pin = "ab".repeat(32);
        advertise(&state_path, node, ServiceAdvert::new("remap", 8_080, &pin)?)?;
        advertise(&state_path, node, ServiceAdvert::new("dibs", 4_777, &pin)?)?;
        set(&state_path, &PeerName::new("HomeServer")?)?;
        let advertised = services(&state_path)?;
        assert_eq!(
            advertised.iter().map(|advert| advert.name.as_str()).collect::<Vec<_>>(),
            ["dibs", "remap"],
            "sorted by name, kept across a rename"
        );
        assert_eq!(load_or_create(&state_path, node)?.as_str(), "HomeServer");
        let replaced = advertise(&state_path, node, ServiceAdvert::new("dibs", 4_790, &pin)?)?;
        assert_eq!(replaced.len(), 2);
        assert_eq!(
            replaced
                .iter()
                .find(|advert| advert.name.as_str() == "dibs")
                .map(|advert| advert.port),
            Some(4_790)
        );
        for extra in 0..MAX_SERVICE_ADVERTS {
            let outcome = advertise(&state_path, node, ServiceAdvert::new(format!("svc{extra}"), 1, &pin)?);
            assert_eq!(
                outcome.is_ok(),
                extra < MAX_SERVICE_ADVERTS - 2,
                "bounded at {MAX_SERVICE_ADVERTS}"
            );
        }
        assert!(matches!(
            unadvertise(&state_path, node, &ServiceName::new("nothing")?),
            Err(ProfileError::UnknownService)
        ));
        // An advertisement built around the constructor is refused before it
        // is stored, so the profile never holds what it would refuse to load.
        let mut zero = ServiceAdvert::new("zero", 1, &pin)?;
        zero.port = 0;
        assert!(matches!(
            advertise(&state_path, node, zero),
            Err(ProfileError::Service(_))
        ));
        assert!(services(&state_path).is_ok(), "the profile was left loadable");
        let remaining = unadvertise(&state_path, node, &ServiceName::new("dibs")?)?;
        assert!(remaining.iter().all(|advert| advert.name.as_str() != "dibs"));
        assert_eq!(services(&state_path)?, remaining);
        // A profile edited by hand into an advertisement the record refuses
        // (a name with a capital, port zero) is refused here, before it can
        // be signed into a record every other member rejects.
        for bad in [
            r#"{"name":"Dibs","port":1,"key_pin":""#,
            r#"{"name":"dibs","port":0,"key_pin":""#,
        ] {
            let body = format!(
                r#"{{"version":1,"name":"HomeServer","services":[{bad}{}"}}]}}"#,
                "ab".repeat(32)
            );
            fs::write(state_path.join(super::PROFILE_FILE_NAME), body)?;
            assert!(
                matches!(services(&state_path), Err(ProfileError::InvalidProfile)),
                "{bad}"
            );
        }
        Ok(())
    }

    #[test]
    fn fallback_label_is_stable_for_an_invalid_hostname_policy() {
        let node = NodeId::from_bytes([0xab; 32]);
        let fallback = format!("computer-{}", &node.to_string()[..8]);
        assert!(PeerName::new(fallback).is_ok());
    }
}
