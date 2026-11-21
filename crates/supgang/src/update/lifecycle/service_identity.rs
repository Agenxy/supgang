//! A narrowly scoped, durable identity transition for explicit service commands.

use std::path::Path;
#[cfg(target_os = "macos")]
use std::{fs, io};

use semver::Version;
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};

use super::{ACTIVE_FILE, SlotRecord, effective_version_floor, read_record, validate_record};
use crate::{
    VERSION,
    update::{UpdateError, updates_directory},
};

pub(super) fn preflight_local_refresh_unlocked(state_directory: &Path) -> Result<(), UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    if read_record(&updates.join(ACTIVE_FILE))?.is_none() {
        return Err(UpdateError::InvalidBundle);
    }
    preflight_local_install_unlocked(state_directory)
}

pub(super) fn preflight_local_install_unlocked(state_directory: &Path) -> Result<(), UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    let installed_version = Version::parse(VERSION).map_err(|_| UpdateError::InvalidTargetName)?;
    let active = read_record(&updates.join(ACTIVE_FILE))?;
    if let Some(active) = &active {
        validate_record(&updates, active)?;
        if installed_version < Version::parse(&active.version).map_err(|_| UpdateError::InvalidTargetName)? {
            return Err(UpdateError::Rollback);
        }
    }
    if installed_version < effective_version_floor(&updates)? {
        return Err(UpdateError::Rollback);
    }
    if let Some(active) = active {
        crate::update::executable::validate_compatible_identity(&active.executable, &std::env::current_exe()?)?;
    }
    Ok(())
}

pub fn preflight_service_refresh_unlocked(state_directory: &Path) -> Result<bool, UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    if read_record(&updates.join(ACTIVE_FILE))?.is_none() {
        return Err(UpdateError::InvalidBundle);
    }
    let transition = preflight_service_install_unlocked(state_directory)?;
    if !transition {
        preflight_local_refresh_unlocked(state_directory)?;
    }
    Ok(transition)
}

pub fn preflight_service_install_unlocked(state_directory: &Path) -> Result<bool, UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    let installed_version = Version::parse(VERSION).map_err(|_| UpdateError::InvalidTargetName)?;
    let active = read_record(&updates.join(ACTIVE_FILE))?;
    let transition = if let Some(active) = &active {
        validate_record(&updates, active)?;
        if installed_version < Version::parse(&active.version).map_err(|_| UpdateError::InvalidTargetName)? {
            return Err(UpdateError::Rollback);
        }
        crate::update::executable::validate_service_identity(&active.executable, &std::env::current_exe()?)?
    } else {
        false
    };
    if !transition {
        preflight_local_install_unlocked(state_directory)?;
        return Ok(false);
    }
    if installed_version < effective_version_floor(&updates)? {
        return Err(UpdateError::Rollback);
    }
    Ok(transition)
}

#[cfg(target_os = "macos")]
pub(super) fn record_transition_audit(
    updates: &Path,
    active: &SlotRecord,
    executable: &Path,
    new_digest: &str,
) -> Result<(), UpdateError> {
    let old_requirement = crate::update::executable::designated_requirement(&active.executable)?;
    let new_requirement = crate::update::executable::designated_requirement(executable)?;
    if !crate::update::executable::validate_service_identity(&active.executable, executable)? {
        return Err(UpdateError::IncompatibleCodeIdentity);
    }
    let line = format!(
        "v1 old_requirement={} new_requirement={} old_executable={} new_executable={}\n",
        hex::encode(Sha256::digest(old_requirement.as_bytes())),
        hex::encode(Sha256::digest(new_requirement.as_bytes())),
        active.digest,
        new_digest,
    );
    append_transition_audit(updates, &line)
}

#[cfg(target_os = "macos")]
fn append_transition_audit(updates: &Path, line: &str) -> Result<(), UpdateError> {
    const AUDIT_FILE: &str = "identity-transition.log";
    const MAX_AUDIT_BYTES: usize = 4096;
    const MAX_AUDIT_LINES: usize = 8;

    let path = updates.join(AUDIT_FILE);
    let mut bytes = match fs::symlink_metadata(&path) {
        Ok(_) => crate::artifact::read(&path, MAX_AUDIT_BYTES).map_err(|_| UpdateError::InvalidBundle)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    if bytes.len() > MAX_AUDIT_BYTES || !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(UpdateError::InvalidBundle);
    }
    if bytes
        .split(|byte| *byte == b'\n')
        .any(|part| part == line.trim_end().as_bytes())
    {
        return Ok(());
    }
    if bytes
        .split(|byte| *byte == b'\n')
        .filter(|part| !part.is_empty())
        .count()
        >= MAX_AUDIT_LINES
    {
        return Err(UpdateError::InvalidBundle);
    }
    bytes.extend_from_slice(line.as_bytes());
    super::write_atomic_bounded(updates, AUDIT_FILE, &bytes, 0o600, MAX_AUDIT_BYTES)
}

#[cfg(not(target_os = "macos"))]
pub(super) const fn record_transition_audit(
    _updates: &Path,
    _active: &SlotRecord,
    _executable: &Path,
    _new_digest: &str,
) -> Result<(), UpdateError> {
    Err(UpdateError::IncompatibleCodeIdentity)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::append_transition_audit;

    #[test]
    fn transition_audit_is_durable_idempotent_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let updates = temporary.path();
        append_transition_audit(updates, "v1 old=a new=b\n")?;
        append_transition_audit(updates, "v1 old=a new=b\n")?;
        let audit = updates.join("identity-transition.log");
        assert_eq!(fs::read_to_string(&audit)?, "v1 old=a new=b\n");
        assert_eq!(fs::metadata(&audit)?.permissions().mode() & 0o777, 0o600);
        for index in 1..8 {
            append_transition_audit(updates, &format!("v1 old={index} new=b\n"))?;
        }
        assert!(append_transition_audit(updates, "v1 old=9 new=b\n").is_err());
        append_transition_audit(updates, "v1 old=a new=b\n")?;
        assert_eq!(fs::read_to_string(&audit)?.lines().count(), 8);
        Ok(())
    }
}
