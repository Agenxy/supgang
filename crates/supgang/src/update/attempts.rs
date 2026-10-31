//! Durable bound on candidate launches across interrupted supervisor probations.

use std::{fs, io, path::Path};

use serde::{Deserialize, Serialize};

use crate::update::{UpdateError, artifact_like_read, lifecycle::SlotRecord, updates_directory};

const FILE: &str = "activation-attempts.json";
const MAX_ATTEMPTS: u8 = 3;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Attempts {
    digest: String,
    version: String,
    count: u8,
}

/// Called under the update lock before launching any pending candidate.
pub(super) fn reserve(state: &Path, candidate: &SlotRecord) -> Result<bool, UpdateError> {
    let updates = updates_directory(state, false)?;
    let previous = match artifact_like_read(&updates.join(FILE), 1024, 0o600) {
        Ok(bytes) => Some(serde_json::from_slice::<Attempts>(&bytes).map_err(|_| UpdateError::InvalidBundle)?),
        Err(UpdateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let count = previous
        .filter(|previous| previous.digest == candidate.digest && previous.version == candidate.version)
        .map_or(0, |previous| previous.count);
    if count >= MAX_ATTEMPTS {
        return Ok(false);
    }
    let next = Attempts {
        digest: candidate.digest.clone(),
        version: candidate.version.clone(),
        count: count.saturating_add(1),
    };
    crate::update::lifecycle::write_atomic(
        &updates,
        FILE,
        &serde_json::to_vec(&next).map_err(|_| UpdateError::InvalidBundle)?,
        0o600,
    )?;
    Ok(true)
}

/// Only a new explicit activation resets the crash budget.
pub(super) fn reset(updates: &Path) -> Result<(), UpdateError> {
    match fs::remove_file(updates.join(FILE)) {
        Ok(()) => fs::File::open(updates)?.sync_all().map_err(Into::into),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{reserve, reset};

    #[test]
    fn interrupted_probations_cannot_retry_forever() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state = temporary.path().join("state");
        drop(crate::state::initialize(&state)?);
        let updates = crate::update::updates_directory(&state, true)?;
        let candidate = crate::update::lifecycle::SlotRecord {
            schema: "supgang.update-slot/v1".to_owned(),
            version: "2.0.0".to_owned(),
            digest: "a".repeat(64),
            executable: state.join("example"),
        };
        for _ in 0..3 {
            assert!(reserve(&state, &candidate)?);
        }
        for _ in 0..4 {
            assert!(!reserve(&state, &candidate)?);
        }
        reset(&updates)?;
        assert!(reserve(&state, &candidate)?);
        Ok(())
    }
}
