use std::{
    collections::BTreeSet,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{MAX_UPDATE_TARGET_BYTES, StagedUpdate, UpdateError, artifact_like_read, ensure_child, updates_directory};
use crate::{VERSION, artifact};

const STAGED_FILE: &str = "staged.json";
const PENDING_FILE: &str = "pending.json";
const ACTIVE_FILE: &str = "active.json";
const PREVIOUS_FILE: &str = "previous.json";
const RECORD_BYTES: usize = 1024;
const MAX_SLOT_ENTRIES_PER_PASS: usize = 16;

mod filesystem;
use filesystem::remove_file;
pub(super) use filesystem::{write_atomic, write_atomic_bounded};

/// Non-secret local update readiness and activation state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UpdateStatus {
    /// Whether a TUF root has been explicitly pinned on this computer.
    pub trusted: bool,
    /// Running or initially installed release version.
    pub active_version: String,
    /// Newer verified release waiting for activation, if any.
    pub staged_version: Option<String>,
    /// Whether a verified release will be tried on the next supervisor handoff.
    pub activation_pending: bool,
    /// Root-authorized peer deliveries retained across reconnects and restarts.
    pub queued_peer_deliveries: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct SlotRecord {
    pub(super) schema: String,
    pub(super) version: String,
    pub(super) digest: String,
    pub(super) executable: PathBuf,
}

impl From<&StagedUpdate> for SlotRecord {
    fn from(value: &StagedUpdate) -> Self {
        Self {
            schema: "supgang.update-slot/v1".to_owned(),
            version: value.version.clone(),
            digest: value.digest.clone(),
            executable: value.executable.clone(),
        }
    }
}

pub(super) fn persist_staged(updates: &Path, staged: &StagedUpdate) -> Result<(), UpdateError> {
    Version::parse(&staged.version).map_err(|_| UpdateError::InvalidTargetName)?;
    let bytes = serde_json::to_vec(&SlotRecord::from(staged)).map_err(|_| UpdateError::InvalidBundle)?;
    write_atomic(updates, STAGED_FILE, &bytes, 0o600)
}

/// Marks the latest verified release for a supervisor handoff.
///
/// The stable supervisor revalidates and health-checks it before promotion.
/// # Errors
/// Rejects unsafe state, an invalid staged slot, or concurrent update work.
pub fn activate_staged(state_directory: &Path) -> Result<StagedUpdate, UpdateError> {
    let _lock = super::lock::UpdateLock::acquire(state_directory)?;
    activate_staged_unlocked(state_directory)
}

/// Disarms a pending activation while preserving the verified staged release.
///
/// # Errors
/// Rejects unsafe state or concurrent update work.
pub fn cancel_activation(state_directory: &Path) -> Result<(), UpdateError> {
    let _lock = super::lock::UpdateLock::acquire(state_directory)?;
    let updates = updates_directory(state_directory, false)?;
    remove_file(&updates.join(PENDING_FILE))?;
    prune_slots(&updates)
}

pub(super) fn activate_staged_unlocked(state_directory: &Path) -> Result<StagedUpdate, UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    let record = read_record(&updates.join(STAGED_FILE))?.ok_or(UpdateError::InvalidBundle)?;
    validate_record(&updates, &record)?;
    validate_against_active(&updates, &record)?;
    let bytes = serde_json::to_vec(&record).map_err(|_| UpdateError::InvalidBundle)?;
    super::supervisor::reset_attempts(&updates)?;
    write_atomic(&updates, PENDING_FILE, &bytes, 0o600)?;
    Ok(StagedUpdate {
        version: record.version,
        digest: record.digest,
        executable: record.executable,
    })
}

/// Reports local trust, active slot, and pending activation without networking.
///
/// # Errors
/// Rejects unsafe or malformed protected update state.
pub fn status(state_directory: &Path) -> Result<UpdateStatus, UpdateError> {
    let updates = match updates_directory(state_directory, false) {
        Ok(value) => value,
        Err(UpdateError::Storage(crate::storage::StorageError::Io(error)))
            if error.kind() == io::ErrorKind::NotFound =>
        {
            return Ok(UpdateStatus {
                trusted: false,
                active_version: VERSION.to_owned(),
                staged_version: None,
                activation_pending: false,
                queued_peer_deliveries: 0,
            });
        }
        Err(error) => return Err(error),
    };
    let active = read_record(&updates.join(ACTIVE_FILE))?;
    let staged = read_record(&updates.join(STAGED_FILE))?;
    let pending = read_validated_pending(&updates)?;
    if let Some(record) = active.as_ref() {
        validate_record(&updates, record)?;
    }
    if let Some(record) = staged.as_ref() {
        validate_record(&updates, record)?;
        validate_against_active(&updates, record)?;
    }
    Ok(UpdateStatus {
        trusted: super::trusted_root_valid(&updates)?,
        active_version: active.map_or_else(|| VERSION.to_owned(), |value| value.version),
        staged_version: staged.map(|value| value.version),
        activation_pending: pending.is_some(),
        queued_peer_deliveries: super::delivery_queue::queued_delivery_count(&updates)?,
    })
}

pub fn activation_pending(state_directory: &Path) -> Result<bool, UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    read_validated_pending(&updates).map(|record| record.is_some())
}

/// Installs the current binary as the supervisor's first known-good slot.
///
/// # Errors
/// Rejects unsafe state or bytes, capacity failures, and concurrent work.
pub fn initialize_installed(state_directory: &Path, executable: &Path) -> Result<PathBuf, UpdateError> {
    let _lock = super::lock::UpdateLock::acquire(state_directory)?;
    initialize_installed_unlocked(state_directory, executable)
}

pub fn initialize_installed_unlocked(state_directory: &Path, executable: &Path) -> Result<PathBuf, UpdateError> {
    let updates = updates_directory(state_directory, true)?;
    let installed_version = Version::parse(VERSION).map_err(|_| UpdateError::InvalidTargetName)?;
    let existing = read_record(&updates.join(ACTIVE_FILE))?;
    if let Some(active) = existing.as_ref() {
        validate_record(&updates, active)?;
        super::executable::validate_compatible_identity(&active.executable, executable)?;
        let active_version = Version::parse(&active.version).map_err(|_| UpdateError::InvalidTargetName)?;
        if installed_version < active_version {
            return Err(UpdateError::Rollback);
        }
    }
    if installed_version < effective_version_floor(&updates)? {
        return Err(UpdateError::Rollback);
    }
    let bytes = artifact_like_read(executable, MAX_UPDATE_TARGET_BYTES, 0o700)?;
    super::executable::validate(&bytes)?;
    super::executable::validate_staged(executable, &Sha256::digest(&bytes))?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let unchanged = if let Some(active) = existing.as_ref()
        && active.version == VERSION
        && active.digest == digest
    {
        Some(active.executable.clone())
    } else {
        None
    };
    let target = if let Some(target) = unchanged {
        target
    } else {
        let slots = ensure_child(&updates, super::SLOTS_DIRECTORY)?;
        let slot = ensure_child(&slots, &digest)?;
        let target = slot.join("supgang");
        match fs::symlink_metadata(&target) {
            Ok(_) => {
                super::executable::validate_staged(&target, &Sha256::digest(&bytes))?;
                super::executable::validate_compatible_identity(executable, &target)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                super::write_new_file(&target, &bytes, 0o700)?;
                super::executable::validate_staged(&target, &Sha256::digest(&bytes))?;
                super::executable::validate_compatible_identity(executable, &target)?;
            }
            Err(error) => return Err(error.into()),
        }
        target
    };
    remove_file(&updates.join(STAGED_FILE))?;
    remove_file(&updates.join(PENDING_FILE))?;
    if existing
        .as_ref()
        .is_some_and(|active| active.version == VERSION && active.digest == digest)
    {
        prune_slots(&updates)?;
        return Ok(target);
    }
    let record = SlotRecord {
        schema: "supgang.update-slot/v1".to_owned(),
        version: VERSION.to_owned(),
        digest,
        executable: target.clone(),
    };
    if let Some(active) = existing {
        write_atomic(
            &updates,
            PREVIOUS_FILE,
            &serde_json::to_vec(&active).map_err(|_| UpdateError::InvalidBundle)?,
            0o600,
        )?;
    }
    write_atomic(
        &updates,
        ACTIVE_FILE,
        &serde_json::to_vec(&record).map_err(|_| UpdateError::InvalidBundle)?,
        0o600,
    )?;
    prune_slots(&updates)?;
    Ok(target)
}

pub fn preflight_local_refresh_unlocked(state_directory: &Path) -> Result<(), UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    if read_record(&updates.join(ACTIVE_FILE))?.is_none() {
        return Err(UpdateError::InvalidBundle);
    }
    preflight_local_install_unlocked(state_directory)
}

pub fn preflight_local_install_unlocked(state_directory: &Path) -> Result<(), UpdateError> {
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
        super::executable::validate_compatible_identity(&active.executable, &std::env::current_exe()?)?;
    }
    Ok(())
}

pub(super) fn read_pending(state_directory: &Path) -> Result<Option<SlotRecord>, UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    read_validated_pending(&updates)
}

fn read_validated_pending(updates: &Path) -> Result<Option<SlotRecord>, UpdateError> {
    let record = read_record(&updates.join(PENDING_FILE))?;
    if let Some(value) = record.as_ref() {
        validate_record(updates, value)?;
        validate_against_active(updates, value)?;
    }
    Ok(record)
}

pub(super) fn read_active(state_directory: &Path) -> Result<SlotRecord, UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    let record = read_record(&updates.join(ACTIVE_FILE))?.ok_or(UpdateError::InvalidBundle)?;
    validate_record(&updates, &record)?;
    Ok(record)
}

pub(super) fn commit_pending(state_directory: &Path, record: &SlotRecord) -> Result<(), UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    validate_record(&updates, record)?;
    validate_against_active(&updates, record)?;
    let active = read_record(&updates.join(ACTIVE_FILE))?;
    if active
        .as_ref()
        .is_some_and(|active| active.digest != record.digest || active.version != record.version)
        && let Some(active) = active
    {
        write_atomic(
            &updates,
            PREVIOUS_FILE,
            &serde_json::to_vec(&active).map_err(|_| UpdateError::InvalidBundle)?,
            0o600,
        )?;
    }
    if read_record(&updates.join(ACTIVE_FILE))?
        .as_ref()
        .is_none_or(|active| active.digest != record.digest || active.version != record.version)
    {
        write_atomic(
            &updates,
            ACTIVE_FILE,
            &serde_json::to_vec(record).map_err(|_| UpdateError::InvalidBundle)?,
            0o600,
        )?;
    }
    remove_file(&updates.join(PENDING_FILE))?;
    remove_staged_if_matching(&updates, &record.digest)?;
    prune_slots(&updates)
}

pub(super) fn discard_pending(state_directory: &Path) -> Result<(), UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    let pending = read_record(&updates.join(PENDING_FILE))?;
    remove_file(&updates.join(PENDING_FILE))?;
    if let Some(pending) = pending {
        remove_staged_if_matching(&updates, &pending.digest)?;
    }
    prune_slots(&updates)
}

fn remove_staged_if_matching(updates: &Path, digest: &str) -> Result<(), UpdateError> {
    if read_record(&updates.join(STAGED_FILE))?
        .as_ref()
        .is_some_and(|staged| staged.digest == digest)
    {
        remove_file(&updates.join(STAGED_FILE))?;
    }
    Ok(())
}

fn validate_record(updates: &Path, record: &SlotRecord) -> Result<(), UpdateError> {
    if record.schema != "supgang.update-slot/v1"
        || Version::parse(&record.version).is_err()
        || record.digest.len() != 64
    {
        return Err(UpdateError::InvalidBundle);
    }
    let digest = hex::decode(&record.digest).map_err(|_| UpdateError::InvalidBundle)?;
    let expected = updates
        .join(super::SLOTS_DIRECTORY)
        .join(&record.digest)
        .join("supgang");
    if record.executable != expected {
        return Err(UpdateError::InvalidBundle);
    }
    super::executable::validate_staged(&record.executable, &digest)
}

fn validate_against_active(updates: &Path, record: &SlotRecord) -> Result<(), UpdateError> {
    let active = read_record(&updates.join(ACTIVE_FILE))?.ok_or(UpdateError::InvalidBundle)?;
    validate_record(updates, &active)?;
    let active_version = Version::parse(&active.version).map_err(|_| UpdateError::Rollback)?;
    let candidate_version = Version::parse(&record.version).map_err(|_| UpdateError::Rollback)?;
    let same_release = record.version == active.version && record.digest == active.digest;
    if !same_release && candidate_version <= active_version {
        return Err(UpdateError::Rollback);
    }
    super::executable::validate_compatible_identity(&active.executable, &record.executable)
}

pub(super) fn effective_version_floor(updates: &Path) -> Result<Version, UpdateError> {
    let mut floor = Version::parse(VERSION).map_err(|_| UpdateError::InvalidTargetName)?;
    for name in [ACTIVE_FILE, PREVIOUS_FILE, STAGED_FILE, PENDING_FILE] {
        if let Some(record) = read_record(&updates.join(name))? {
            validate_record(updates, &record)?;
            let version = Version::parse(&record.version).map_err(|_| UpdateError::Rollback)?;
            floor = floor.max(version);
        }
    }
    Ok(floor)
}

fn read_record(path: &Path) -> Result<Option<SlotRecord>, UpdateError> {
    let bytes = match fs::symlink_metadata(path) {
        Ok(_) => artifact::read(path, RECORD_BYTES)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let record = serde_json::from_slice(&bytes).map_err(|_| UpdateError::InvalidBundle)?;
    if serde_json::to_vec(&record).map_err(|_| UpdateError::InvalidBundle)? != bytes {
        return Err(UpdateError::InvalidBundle);
    }
    Ok(Some(record))
}

fn prune_slots(updates: &Path) -> Result<(), UpdateError> {
    let slots = ensure_child(updates, super::SLOTS_DIRECTORY)?;
    let mut keep = BTreeSet::new();
    for name in [ACTIVE_FILE, PREVIOUS_FILE, STAGED_FILE, PENDING_FILE] {
        if let Some(record) = read_record(&updates.join(name))? {
            validate_record(updates, &record)?;
            keep.insert(record.digest);
        }
    }
    let mut inspected = 0_usize;
    for entry in fs::read_dir(&slots)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| UpdateError::InvalidBundle)?;
        if name.len() != 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(UpdateError::InvalidBundle);
        }
        crate::storage::validate_trusted_owner_directory(&entry.path())?;
        if !keep.contains(&name) {
            fs::remove_dir_all(entry.path())?;
        }
        inspected = inspected.checked_add(1).ok_or(UpdateError::Capacity)?;
        if inspected > MAX_SLOT_ENTRIES_PER_PASS {
            return Err(UpdateError::Capacity);
        }
    }
    File::open(slots)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    #[cfg(not(target_os = "macos"))]
    use std::io::Write;

    #[cfg(target_os = "macos")]
    use std::process::Command;

    use sha2::{Digest, Sha256};

    use super::{
        ACTIVE_FILE, PENDING_FILE, PREVIOUS_FILE, STAGED_FILE, SlotRecord, commit_pending, discard_pending,
        effective_version_floor, persist_staged, preflight_local_install_unlocked, preflight_local_refresh_unlocked,
        read_pending, read_record, write_atomic,
    };
    use crate::{
        VERSION,
        update::{StagedUpdate, UpdateError, activate_staged, cancel_activation, initialize_installed},
    };

    fn initialized_state() -> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state = temporary.path().join("state");
        drop(crate::state::initialize(&state)?);
        let executable = temporary.path().join("supgang");
        fs::copy(std::env::current_exe()?, &executable)?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
        sign_lifecycle_fixture(&executable, 0)?;
        let _installed = initialize_installed(&state, &executable)?;
        Ok((temporary, state))
    }

    fn candidate(
        state: &std::path::Path,
        version: &str,
        marker: u8,
    ) -> Result<StagedUpdate, Box<dyn std::error::Error>> {
        let updates = crate::update::updates_directory(state, false)?;
        let slots = crate::update::ensure_child(&updates, crate::update::SLOTS_DIRECTORY)?;
        let unsigned = state.join(format!(".lifecycle-candidate-{marker}"));
        let bytes = fs::read(std::env::current_exe()?)?;
        crate::update::write_new_file(&unsigned, &bytes, 0o700)?;
        sign_lifecycle_fixture(&unsigned, marker)?;
        let signed_bytes = fs::read(&unsigned)?;
        let digest = hex::encode(Sha256::digest(&signed_bytes));
        let slot = crate::update::ensure_child(&slots, &digest)?;
        let executable = slot.join("supgang");
        crate::update::write_new_file(&executable, &signed_bytes, 0o700)?;
        fs::remove_file(unsigned)?;
        Ok(StagedUpdate {
            version: version.to_owned(),
            digest,
            executable,
        })
    }

    #[cfg(target_os = "macos")]
    fn sign_lifecycle_fixture(path: &std::path::Path, marker: u8) -> Result<(), Box<dyn std::error::Error>> {
        let entitlements = path.with_extension(format!("entitlements-{marker}.plist"));
        fs::write(
            &entitlements,
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>org.agenxy.supgang.test-marker</key><integer>{marker}</integer></dict></plist>\n"
            ),
        )?;
        let output = Command::new("/usr/bin/codesign")
            .args([
                "--force",
                "--sign",
                "-",
                "--identifier",
                "org.agenxy.supgang.lifecycle-test",
                "--requirements",
                "=designated => identifier \"org.agenxy.supgang.lifecycle-test\"",
                "--entitlements",
            ])
            .arg(&entitlements)
            .args(["--timestamp=none"])
            .arg(path)
            .output()?;
        fs::remove_file(entitlements)?;
        if output.status.success() {
            Ok(())
        } else {
            Err("codesign did not prepare the lifecycle fixture".into())
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn sign_lifecycle_fixture(path: &std::path::Path, marker: u8) -> Result<(), Box<dyn std::error::Error>> {
        fs::OpenOptions::new().append(true).open(path)?.write_all(&[marker])?;
        Ok(())
    }

    #[test]
    fn finishing_one_pending_slot_never_deletes_a_different_staged_slot() -> Result<(), Box<dyn std::error::Error>> {
        let (_temporary, state) = initialized_state()?;
        let updates = crate::update::updates_directory(&state, false)?;
        let first = candidate(&state, "9998.0.0", 1)?;
        let second = candidate(&state, "9999.0.0", 2)?;
        persist_staged(&updates, &first)?;
        let pending_first = activate_staged(&state)?;
        persist_staged(&updates, &second)?;

        commit_pending(&state, &SlotRecord::from(&pending_first))?;
        assert_eq!(
            read_record(&updates.join(STAGED_FILE))?.map(|record| record.digest),
            Some(second.digest.clone())
        );

        let pending_second = activate_staged(&state)?;
        persist_staged(&updates, &first)?;
        assert_eq!(pending_second.digest, second.digest);
        discard_pending(&state)?;
        assert_eq!(
            read_record(&updates.join(STAGED_FILE))?.map(|record| record.digest),
            Some(first.digest)
        );
        Ok(())
    }

    #[test]
    fn recovered_commit_is_idempotent_and_preserves_the_real_previous_slot() -> Result<(), Box<dyn std::error::Error>> {
        let (_temporary, state) = initialized_state()?;
        let updates = crate::update::updates_directory(&state, false)?;
        let old_active = read_record(&updates.join(ACTIVE_FILE))?.ok_or("missing active slot")?;
        let staged = candidate(&state, "9998.0.0", 3)?;
        persist_staged(&updates, &staged)?;
        let pending = SlotRecord::from(&activate_staged(&state)?);
        commit_pending(&state, &pending)?;
        let previous = read_record(&updates.join(PREVIOUS_FILE))?.ok_or("missing previous slot")?;
        assert_eq!(previous.digest, old_active.digest);

        write_atomic(&updates, PENDING_FILE, &serde_json::to_vec(&pending)?, 0o600)?;
        commit_pending(&state, &pending)?;
        let recovered_previous = read_record(&updates.join(PREVIOUS_FILE))?.ok_or("missing recovered previous slot")?;
        assert_eq!(recovered_previous.digest, previous.digest);
        Ok(())
    }

    #[test]
    fn a_discarded_candidate_does_not_leave_a_permanent_semantic_floor() -> Result<(), Box<dyn std::error::Error>> {
        let (_temporary, state) = initialized_state()?;
        let updates = crate::update::updates_directory(&state, false)?;
        let baseline = effective_version_floor(&updates)?;
        let staged = candidate(&state, "9999.0.0", 4)?;
        persist_staged(&updates, &staged)?;
        assert!(effective_version_floor(&updates)? > baseline);
        fs::remove_file(updates.join(STAGED_FILE))?;
        assert_eq!(effective_version_floor(&updates)?, baseline);
        Ok(())
    }

    #[test]
    fn local_reinstall_clears_same_version_staged_and_pending_slots() -> Result<(), Box<dyn std::error::Error>> {
        let (temporary, state) = initialized_state()?;
        let updates = crate::update::updates_directory(&state, false)?;
        let obsolete_candidate = candidate(&state, VERSION, 5)?;
        let obsolete_record = SlotRecord::from(&obsolete_candidate);
        persist_staged(&updates, &obsolete_candidate)?;
        write_atomic(&updates, PENDING_FILE, &serde_json::to_vec(&obsolete_record)?, 0o600)?;

        let replacement = temporary.path().join("replacement-supgang");
        fs::copy(std::env::current_exe()?, &replacement)?;
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700))?;
        sign_lifecycle_fixture(&replacement, 6)?;
        let installed = initialize_installed(&state, &replacement)?;

        assert!(!updates.join(STAGED_FILE).exists());
        assert!(!updates.join(PENDING_FILE).exists());
        let active = read_record(&updates.join(ACTIVE_FILE))?.ok_or("missing active slot")?;
        assert_eq!(active.executable, installed);
        assert_eq!(active.version, VERSION);
        assert_eq!(crate::update::status(&state)?.staged_version, None);
        Ok(())
    }

    #[test]
    fn stale_pending_slot_is_rejected_before_supervisor_handoff() -> Result<(), Box<dyn std::error::Error>> {
        let (_temporary, state) = initialized_state()?;
        let updates = crate::update::updates_directory(&state, false)?;
        let obsolete_record = SlotRecord::from(&candidate(&state, VERSION, 7)?);
        write_atomic(&updates, PENDING_FILE, &serde_json::to_vec(&obsolete_record)?, 0o600)?;

        assert!(matches!(read_pending(&state), Err(UpdateError::Rollback)));
        Ok(())
    }

    #[test]
    fn cancelling_activation_preserves_the_verified_staged_release() -> Result<(), Box<dyn std::error::Error>> {
        let (_temporary, state) = initialized_state()?;
        let updates = crate::update::updates_directory(&state, false)?;
        let staged = candidate(&state, "9999.0.0", 8)?;
        persist_staged(&updates, &staged)?;
        let _pending = activate_staged(&state)?;

        cancel_activation(&state)?;

        assert!(!updates.join(PENDING_FILE).exists());
        assert_eq!(
            read_record(&updates.join(STAGED_FILE))?.map(|record| record.digest),
            Some(staged.digest)
        );
        Ok(())
    }

    #[test]
    fn local_refresh_preflight_rejects_a_newer_durable_version_floor() -> Result<(), Box<dyn std::error::Error>> {
        let (_temporary, state) = initialized_state()?;
        let updates = crate::update::updates_directory(&state, false)?;
        let newer = candidate(&state, "9999.0.0", 9)?;
        persist_staged(&updates, &newer)?;

        assert!(matches!(
            preflight_local_refresh_unlocked(&state),
            Err(UpdateError::Rollback)
        ));
        assert!(matches!(
            preflight_local_install_unlocked(&state),
            Err(UpdateError::Rollback)
        ));
        Ok(())
    }

    #[test]
    fn same_bytes_at_a_higher_version_advance_the_active_record() -> Result<(), Box<dyn std::error::Error>> {
        let (_temporary, state) = initialized_state()?;
        let updates = crate::update::updates_directory(&state, false)?;
        let active = read_record(&updates.join(ACTIVE_FILE))?.ok_or("missing active slot")?;
        let promoted = SlotRecord {
            version: "9999.0.0".to_owned(),
            ..active
        };
        write_atomic(&updates, PENDING_FILE, &serde_json::to_vec(&promoted)?, 0o600)?;

        let validated = read_pending(&state)?.ok_or("missing pending slot")?;
        commit_pending(&state, &validated)?;

        let committed = read_record(&updates.join(ACTIVE_FILE))?.ok_or("missing active slot")?;
        assert_eq!(committed.version, "9999.0.0");
        assert_eq!(committed.digest, promoted.digest);
        assert!(!updates.join(PENDING_FILE).exists());
        Ok(())
    }
}
