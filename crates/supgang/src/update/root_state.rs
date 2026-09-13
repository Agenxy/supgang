//! Durable TUF root continuity independent from the dependency datastore.

use std::{
    fs::{self, File},
    io::{self, Write},
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tough::schema::{Role, Root, Signed};

use super::{MAX_METADATA_BYTES, TRUSTED_ROOT_FILE, UpdateError, artifact, create_new_owner_file};

const ROOT_STATE_FILE: &str = "root-state.json";
const ROOT_STATE_SCHEMA: &str = "supgang.tuf-root-state/v1";
const MAX_ROOT_STATE_BYTES: u64 = MAX_METADATA_BYTES * 2 + 4 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RootState {
    schema: String,
    bootstrap_sha256: String,
    current: Signed<Root>,
    previous: Option<Signed<Root>>,
}

impl RootState {
    pub(super) fn current_bytes(&self) -> Result<Vec<u8>, UpdateError> {
        serialize_root(&self.current)
    }
}

pub(super) fn pin(updates: &Path, bootstrap: &[u8], root: &Signed<Root>) -> Result<(), UpdateError> {
    let trusted_path = updates.join(TRUSTED_ROOT_FILE);
    match fs::symlink_metadata(&trusted_path) {
        Ok(_) => return Err(UpdateError::TrustAlreadyPinned),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let expected = RootState {
        schema: ROOT_STATE_SCHEMA.to_owned(),
        bootstrap_sha256: digest(bootstrap),
        current: root.clone(),
        previous: None,
    };
    let state_path = updates.join(ROOT_STATE_FILE);
    match fs::symlink_metadata(&state_path) {
        Ok(_) => {
            let existing = read_state(&state_path)?;
            if existing.schema != expected.schema
                || existing.bootstrap_sha256 != expected.bootstrap_sha256
                || existing.previous.is_some()
                || !same_root(&existing.current, &expected.current)?
            {
                return Err(UpdateError::InvalidTrustRoot);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            write_new_state(&state_path, &expected)?;
        }
        Err(error) => return Err(error.into()),
    }
    super::write_new_file(&trusted_path, bootstrap, 0o600)
}

pub(super) fn valid(updates: &Path) -> Result<bool, UpdateError> {
    let trusted_path = updates.join(TRUSTED_ROOT_FILE);
    match fs::symlink_metadata(&trusted_path) {
        Ok(_) => load(updates).map(|_state| true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn load(updates: &Path) -> Result<RootState, UpdateError> {
    let bootstrap = read_bootstrap(updates)?;
    let bootstrap_root = parse_root(&bootstrap)?;
    let state = read_state(&updates.join(ROOT_STATE_FILE))?;
    validate_state(&state, &bootstrap, &bootstrap_root)?;
    Ok(state)
}

pub(super) fn promote(updates: &Path, state: RootState, current: &Signed<Root>) -> Result<(), UpdateError> {
    validate_root(current)?;
    let old_version = state.current.signed.version.get();
    let new_version = current.signed.version.get();
    if new_version < old_version {
        return Err(UpdateError::InvalidTrustRoot);
    }
    if new_version == old_version {
        if !same_root(&state.current, current)? {
            return Err(UpdateError::InvalidTrustRoot);
        }
        return Ok(());
    }
    let promoted = RootState {
        schema: ROOT_STATE_SCHEMA.to_owned(),
        bootstrap_sha256: state.bootstrap_sha256,
        current: current.clone(),
        previous: Some(state.current),
    };
    let bootstrap = read_bootstrap(updates)?;
    let bootstrap_root = parse_root(&bootstrap)?;
    validate_state(&promoted, &bootstrap, &bootstrap_root)?;
    replace_state(&updates.join(ROOT_STATE_FILE), &promoted)
}

fn read_bootstrap(updates: &Path) -> Result<Vec<u8>, UpdateError> {
    let path = updates.join(TRUSTED_ROOT_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => artifact::read(
            path,
            usize::try_from(MAX_METADATA_BYTES).map_err(|_| UpdateError::InvalidTrustRoot)?,
        )
        .map_err(Into::into),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(UpdateError::MissingTrustRoot),
        Err(error) => Err(error.into()),
    }
}

fn read_state(path: &Path) -> Result<RootState, UpdateError> {
    let bytes = match fs::symlink_metadata(path) {
        Ok(_) => artifact::read(
            path,
            usize::try_from(MAX_ROOT_STATE_BYTES).map_err(|_| UpdateError::InvalidTrustRoot)?,
        )?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(UpdateError::InvalidTrustRoot),
        Err(error) => return Err(error.into()),
    };
    serde_json::from_slice(&bytes).map_err(|_| UpdateError::InvalidTrustRoot)
}

fn validate_state(state: &RootState, bootstrap: &[u8], bootstrap_root: &Signed<Root>) -> Result<(), UpdateError> {
    if state.schema != ROOT_STATE_SCHEMA || state.bootstrap_sha256 != digest(bootstrap) {
        return Err(UpdateError::InvalidTrustRoot);
    }
    validate_root(&state.current)?;
    let bootstrap_version = bootstrap_root.signed.version.get();
    let current_version = state.current.signed.version.get();
    if current_version < bootstrap_version {
        return Err(UpdateError::InvalidTrustRoot);
    }
    if current_version == bootstrap_version && !same_root(&state.current, bootstrap_root)? {
        return Err(UpdateError::InvalidTrustRoot);
    }
    match &state.previous {
        Some(previous) => {
            validate_root(previous)?;
            if previous.signed.version >= state.current.signed.version {
                return Err(UpdateError::InvalidTrustRoot);
            }
        }
        None if current_version != bootstrap_version => return Err(UpdateError::InvalidTrustRoot),
        None => {}
    }
    Ok(())
}

fn parse_root(bytes: &[u8]) -> Result<Signed<Root>, UpdateError> {
    let root = serde_json::from_slice(bytes).map_err(|_| UpdateError::InvalidTrustRoot)?;
    validate_root(&root)?;
    Ok(root)
}

fn validate_root(root: &Signed<Root>) -> Result<(), UpdateError> {
    root.signed.verify_role(root).map_err(|_| UpdateError::InvalidTrustRoot)
}

fn serialize_root(root: &Signed<Root>) -> Result<Vec<u8>, UpdateError> {
    serde_json::to_vec(root).map_err(|_| UpdateError::InvalidTrustRoot)
}

fn same_root(left: &Signed<Root>, right: &Signed<Root>) -> Result<bool, UpdateError> {
    let left = left
        .signed
        .canonical_form()
        .map_err(|_| UpdateError::InvalidTrustRoot)?;
    let right = right
        .signed
        .canonical_form()
        .map_err(|_| UpdateError::InvalidTrustRoot)?;
    Ok(left == right)
}

fn canonical_state(state: &RootState) -> Result<Vec<u8>, UpdateError> {
    serde_json::to_vec(state).map_err(|_| UpdateError::InvalidTrustRoot)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_new_state(path: &Path, state: &RootState) -> Result<(), UpdateError> {
    let bytes = canonical_state(state)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_ROOT_STATE_BYTES) {
        return Err(UpdateError::InvalidTrustRoot);
    }
    super::write_new_file(path, &bytes, 0o600)
}

fn replace_state(path: &Path, state: &RootState) -> Result<(), UpdateError> {
    let _validated = read_state(path)?;
    let bytes = canonical_state(state)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_ROOT_STATE_BYTES) {
        return Err(UpdateError::InvalidTrustRoot);
    }
    let parent = path.parent().ok_or(UpdateError::InvalidTrustRoot)?;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| UpdateError::InvalidTrustRoot)?;
    let temporary = parent.join(format!(".root-state-{}.tmp", hex::encode(random)));
    let mut file = create_new_owner_file(&temporary, 0o600)?;
    let result = (|| -> Result<(), UpdateError> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _cleanup = fs::remove_file(&temporary);
    }
    result
}
