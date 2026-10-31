//! Crash-atomic, symlink-free persistence for TUF client rollback metadata.

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tough::schema::{Root, Signed, Snapshot, Targets, Timestamp};

use super::{
    MAX_BUNDLE_ENTRIES, MAX_METADATA_BYTES, UpdateError, artifact_like_read, lifecycle, valid_entry_name,
    write_new_file,
};

const STATE_FILE: &str = "tuf-state.json";
const STATE_SCHEMA: &str = "supgang.tuf-state/v2";
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;
#[cfg(test)]
const REQUIRED_FILES: [&str; 4] = ["root.json", "timestamp.json", "snapshot.json", "targets.json"];

#[derive(Debug, Deserialize, Serialize)]
struct State {
    schema: String,
    files: Vec<StateFile>,
}

#[derive(Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct StateFile {
    name: String,
    sha256: String,
    bytes: String,
}

pub(super) fn seed(updates: &Path, empty_datastore: &Path) -> Result<(), UpdateError> {
    let path = updates.join(STATE_FILE);
    let bytes = match path.symlink_metadata() {
        Ok(_) => artifact_like_read(&path, MAX_STATE_BYTES, 0o600)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let state: State = serde_json::from_slice(&bytes).map_err(|_| UpdateError::Tuf)?;
    validate(&state, Some(&bytes))?;
    for file in state.files {
        let decoded = hex::decode(file.bytes).map_err(|_| UpdateError::Tuf)?;
        write_new_file(&empty_datastore.join(file.name), &decoded, 0o600)?;
    }
    Ok(())
}

pub(super) fn seed_current(
    updates: &Path,
    datastore: &Path,
    trust: &super::root_state::RootState,
) -> Result<(), UpdateError> {
    let current = trust.root();
    seed(updates, datastore)?;
    let root_path = datastore.join("root.json");
    if root_path.exists() {
        let bytes = artifact_like_read(&root_path, MAX_METADATA_BYTES, 0o600)?;
        let old: Signed<Root> = serde_json::from_slice(&bytes).map_err(|_| UpdateError::Tuf)?;
        if old.signed.version > current.signed.version {
            return Err(UpdateError::InvalidTrustRoot);
        }
        // Mirror tough's fast-forward recovery even across a crash between
        // independent root advancement and publishing the role-state snapshot.
        if old.signed.version.get() < trust.role_reset_version()
            || super::root_state::role_keys_changed(&old.signed, &current.signed)
        {
            for name in ["timestamp.json", "snapshot.json"] {
                match fs::remove_file(datastore.join(name)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        fs::remove_file(&root_path)?;
    }
    write_new_file(
        &root_path,
        &serde_json::to_vec(current).map_err(|_| UpdateError::Tuf)?,
        0o600,
    )?;
    commit(updates, datastore)
}

pub(super) fn commit(updates: &Path, datastore: &Path) -> Result<(), UpdateError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(datastore)? {
        if files.len() >= MAX_BUNDLE_ENTRIES {
            return Err(UpdateError::Capacity);
        }
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|_| UpdateError::Tuf)?;
        if !valid_entry_name(&name) {
            return Err(UpdateError::Tuf);
        }
        let path = entry.path();
        let metadata = path.symlink_metadata()?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(UpdateError::Tuf);
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let bytes = artifact_like_read(&path, MAX_METADATA_BYTES, 0o600)?;
        validate_metadata(&name, &bytes)?;
        files.push(StateFile {
            name,
            sha256: hex::encode(Sha256::digest(&bytes)),
            bytes: hex::encode(bytes),
        });
    }
    files.sort_unstable();
    let state = State {
        schema: STATE_SCHEMA.to_owned(),
        files,
    };
    validate(&state, None)?;
    let bytes = serde_json::to_vec(&state).map_err(|_| UpdateError::Tuf)?;
    lifecycle::write_atomic_bounded(
        updates,
        STATE_FILE,
        &bytes,
        0o600,
        usize::try_from(MAX_STATE_BYTES).map_err(|_| UpdateError::Capacity)?,
    )
}

fn validate(state: &State, encoded: Option<&[u8]>) -> Result<(), UpdateError> {
    if !matches!(state.schema.as_str(), STATE_SCHEMA | "supgang.tuf-state/v1")
        || state.files.is_empty()
        || state.files.len() > MAX_BUNDLE_ENTRIES
        || encoded.is_some_and(|bytes| serde_json::to_vec(state).map_or(true, |canonical| canonical != bytes))
    {
        return Err(UpdateError::Tuf);
    }
    let mut previous = None;
    for file in &state.files {
        if !valid_entry_name(&file.name)
            || previous.as_ref().is_some_and(|name| name >= &file.name)
            || file.sha256.len() != 64
        {
            return Err(UpdateError::Tuf);
        }
        let bytes = hex::decode(&file.bytes).map_err(|_| UpdateError::Tuf)?;
        if bytes.is_empty()
            || u64::try_from(bytes.len()).map_or(true, |length| length > MAX_METADATA_BYTES)
            || hex::encode(Sha256::digest(&bytes)) != file.sha256
        {
            return Err(UpdateError::Tuf);
        }
        previous = Some(file.name.clone());
    }
    // A valid root followed by a failed timestamp/snapshot/targets load is
    // legitimate trusted progress, not a reason to discard that progress.
    if !state.files.iter().any(|file| file.name == "root.json") {
        return Err(UpdateError::Tuf);
    }
    Ok(())
}

fn validate_metadata(name: &str, bytes: &[u8]) -> Result<(), UpdateError> {
    let valid = match name {
        "root.json" => serde_json::from_slice::<Signed<Root>>(bytes).is_ok(),
        "timestamp.json" => serde_json::from_slice::<Signed<Timestamp>>(bytes).is_ok(),
        "snapshot.json" => serde_json::from_slice::<Signed<Snapshot>>(bytes).is_ok(),
        "latest_known_time.json" => serde_json::from_slice::<jiff::Timestamp>(bytes).is_ok(),
        _ => serde_json::from_slice::<Signed<Targets>>(bytes).is_ok(),
    };
    if valid { Ok(()) } else { Err(UpdateError::Tuf) }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::{REQUIRED_FILES, STATE_FILE, commit, seed};
    use crate::update::UpdateError;

    fn protected_directory(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn write_required(datastore: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let repository = crate::update::tests::signed_repository()?;
        for name in REQUIRED_FILES {
            let path = datastore.join(name);
            fs::copy(repository.metadata.path().join(name), &path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    #[test]
    fn committed_state_round_trips_through_a_fresh_datastore() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let updates = temporary.path().join("updates");
        let source = temporary.path().join("source");
        let restored = temporary.path().join("restored");
        protected_directory(&updates)?;
        protected_directory(&source)?;
        protected_directory(&restored)?;
        write_required(&source)?;

        commit(&updates, &source)?;
        seed(&updates, &restored)?;
        for name in REQUIRED_FILES {
            assert_eq!(fs::read(source.join(name))?, fs::read(restored.join(name))?);
        }
        Ok(())
    }

    #[test]
    fn corruption_and_datastore_symlinks_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let updates = temporary.path().join("updates");
        let source = temporary.path().join("source");
        let restored = temporary.path().join("restored");
        protected_directory(&updates)?;
        protected_directory(&source)?;
        protected_directory(&restored)?;
        write_required(&source)?;
        commit(&updates, &source)?;

        let state_path = updates.join(STATE_FILE);
        let mut corrupt = fs::read(&state_path)?;
        let first = corrupt.first_mut().ok_or("empty TUF state")?;
        *first ^= 1;
        fs::write(&state_path, corrupt)?;
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600))?;
        assert!(matches!(seed(&updates, &restored), Err(UpdateError::Tuf)));

        let first_name = REQUIRED_FILES.first().ok_or("missing required TUF role")?;
        fs::remove_file(source.join(first_name))?;
        std::os::unix::fs::symlink(temporary.path().join("outside"), source.join(first_name))?;
        assert!(matches!(commit(&updates, &source), Err(UpdateError::Tuf)));
        Ok(())
    }
}
