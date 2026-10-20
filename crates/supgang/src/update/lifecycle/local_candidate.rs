//! An owner's local refresh to a newer release, tried before it is trusted.
//!
//! A refresh normally replaces the active release at once. On a computer the
//! owner can only reach through Supgang, a release that fails to start, or
//! starts but never reconnects, would leave no way back in. A newer release
//! is therefore staged as the pending candidate, which the installed
//! supervisor runs under its health probation and abandons for the
//! known-good release if it fails. After a candidate commits, the refresh
//! still requires a peer to reconnect, and if none does it returns to the
//! release that ran before, which the owner was running minutes earlier.
//!
//! A revert never points the next revert at a release that failed. Staging
//! keeps a copy of the current previous release, a release this computer ran
//! and replaced, outside the slots the supervisor prunes. A revert makes that
//! copy the previous release again, or records none, so a second revert
//! restores a release known to have worked, never the one that just failed.

use std::path::Path;

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    ACTIVE_FILE, PENDING_FILE, PREVIOUS_FILE, SlotRecord, effective_version_floor, prune_slots, read_record,
    validate_record, write_atomic,
};
use crate::{
    VERSION,
    update::{SLOTS_DIRECTORY, UpdateError, ensure_child, updates_directory},
};

const OUTCOME_FILE: &str = "refresh-outcome.json";
/// The release a revert falls back to, kept outside the pruned slots.
const FALLBACK_DIRECTORY: &str = "fallback";
const FALLBACK_RECORD: &str = "fallback.json";

/// What became of the last owner refresh that used probation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RefreshOutcome {
    /// Record format, `supgang.refresh-outcome/v1`.
    pub schema: String,
    /// The release the refresh tried.
    pub version: String,
    /// That release's SHA-256 digest.
    pub digest: String,
    /// `committed`, `reverted-unhealthy` or `reverted-no-peer`.
    pub result: String,
    /// Unix seconds when the outcome was decided.
    pub recorded_at: u64,
}

/// Stages `bytes`, the running executable, as the supervisor's pending
/// candidate when it is a newer release than the active one. Returns its
/// digest, or `None` when the release is not newer and the caller should
/// refresh directly as before.
///
/// # Errors
///
/// Rejects unsafe state, invalid executables, an incompatible signing
/// identity, and a release below the recorded version floor.
pub fn stage_local_candidate_unlocked(state_directory: &Path, bytes: &[u8]) -> Result<Option<String>, UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    let Some(active) = read_record(&updates.join(ACTIVE_FILE))? else {
        return Ok(None);
    };
    validate_record(&updates, &active)?;
    let candidate = Version::parse(VERSION).map_err(|_| UpdateError::InvalidTargetName)?;
    if candidate <= Version::parse(&active.version).map_err(|_| UpdateError::InvalidTargetName)? {
        return Ok(None);
    }
    if candidate < effective_version_floor(&updates)? {
        return Err(UpdateError::Rollback);
    }
    crate::update::executable::validate(bytes)?;
    let digest_bytes = Sha256::digest(bytes);
    let digest = hex::encode(digest_bytes);
    let slots = ensure_child(&updates, SLOTS_DIRECTORY)?;
    let slot = ensure_child(&slots, &digest)?;
    let target = slot.join("supgang");
    if std::fs::symlink_metadata(&target).is_err() {
        crate::update::write_new_file(&target, bytes, 0o700)?;
    }
    crate::update::executable::validate_staged(&target, &digest_bytes)?;
    crate::update::executable::validate_compatible_identity(&active.executable, &target)?;
    preserve_fallback(&updates, &active)?;
    let record = SlotRecord {
        schema: "supgang.update-slot/v1".to_owned(),
        version: VERSION.to_owned(),
        digest: digest.clone(),
        executable: target,
    };
    write_atomic(
        &updates,
        PENDING_FILE,
        &serde_json::to_vec(&record).map_err(|_| UpdateError::InvalidBundle)?,
        0o600,
    )?;
    Ok(Some(digest))
}

/// The digest of the active release.
///
/// # Errors
///
/// Rejects unsafe or missing update state.
pub fn active_digest(state_directory: &Path) -> Result<String, UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    let active = read_record(&updates.join(ACTIVE_FILE))?.ok_or(UpdateError::InvalidBundle)?;
    validate_record(&updates, &active)?;
    Ok(active.digest)
}

/// Returns to the release that ran before `failed`, if `failed` is still the
/// active release and a previous one is recorded. The release recorded as
/// previous afterwards is the kept fallback, or none: never `failed`.
///
/// # Errors
///
/// Rejects unsafe state, a different active release, or no previous release.
pub fn revert_local_candidate_unlocked(state_directory: &Path, failed: &str) -> Result<(), UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    let active = read_record(&updates.join(ACTIVE_FILE))?.ok_or(UpdateError::InvalidBundle)?;
    let previous = read_record(&updates.join(PREVIOUS_FILE))?.ok_or(UpdateError::InvalidBundle)?;
    validate_record(&updates, &active)?;
    validate_record(&updates, &previous)?;
    if active.digest != failed || previous.digest == failed {
        return Err(UpdateError::InvalidBundle);
    }
    crate::update::executable::validate_compatible_identity(&active.executable, &previous.executable)?;
    write_atomic(
        &updates,
        ACTIVE_FILE,
        &serde_json::to_vec(&previous).map_err(|_| UpdateError::InvalidBundle)?,
        0o600,
    )?;
    match restore_fallback(&updates, &previous, failed)? {
        Some(fallback) => write_atomic(
            &updates,
            PREVIOUS_FILE,
            &serde_json::to_vec(&fallback).map_err(|_| UpdateError::InvalidBundle)?,
            0o600,
        )?,
        None => super::remove_file(&updates.join(PREVIOUS_FILE))?,
    }
    prune_slots(&updates)
}

/// The release `supgang update revert` would restore, as (version, digest).
///
/// # Errors
///
/// Rejects unsafe state or a malformed record.
pub fn revert_target(state_directory: &Path) -> Result<Option<(String, String)>, UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    let Some(previous) = read_record(&updates.join(PREVIOUS_FILE))? else {
        return Ok(None);
    };
    validate_record(&updates, &previous)?;
    Ok(Some((previous.version, previous.digest)))
}

/// Keeps a copy of the current previous release, which this computer ran and
/// replaced, so a revert can make it the previous release again after the
/// supervisor prunes its slot.
fn preserve_fallback(updates: &Path, active: &SlotRecord) -> Result<(), UpdateError> {
    let Some(previous) = read_record(&updates.join(PREVIOUS_FILE))? else {
        return Ok(());
    };
    validate_record(updates, &previous)?;
    if previous.digest == active.digest {
        return Ok(());
    }
    let kept = ensure_child(&ensure_child(updates, FALLBACK_DIRECTORY)?, &previous.digest)?;
    let copy = kept.join("supgang");
    if std::fs::symlink_metadata(&copy).is_err() {
        let bytes =
            crate::update::artifact_like_read(&previous.executable, crate::update::MAX_UPDATE_TARGET_BYTES, 0o700)?;
        crate::update::write_new_file(&copy, &bytes, 0o700)?;
    }
    let digest = hex::decode(&previous.digest).map_err(|_| UpdateError::InvalidBundle)?;
    crate::update::executable::validate_staged(&copy, &digest)?;
    write_atomic(
        updates,
        FALLBACK_RECORD,
        &serde_json::to_vec(&previous).map_err(|_| UpdateError::InvalidBundle)?,
        0o600,
    )
}

/// The kept fallback as a valid slot record, its slot restored if pruned, or
/// `None` when there is none or it is the release being restored or the one
/// that failed.
fn restore_fallback(updates: &Path, restored: &SlotRecord, failed: &str) -> Result<Option<SlotRecord>, UpdateError> {
    let Some(fallback) = read_record(&updates.join(FALLBACK_RECORD))? else {
        return Ok(None);
    };
    if fallback.digest == restored.digest || fallback.digest == failed {
        return Ok(None);
    }
    let digest = hex::decode(&fallback.digest).map_err(|_| UpdateError::InvalidBundle)?;
    let kept = updates.join(FALLBACK_DIRECTORY).join(&fallback.digest).join("supgang");
    crate::update::executable::validate_staged(&kept, &digest)?;
    if std::fs::symlink_metadata(&fallback.executable).is_err() {
        let slot = ensure_child(&ensure_child(updates, SLOTS_DIRECTORY)?, &fallback.digest)?;
        let bytes = crate::update::artifact_like_read(&kept, crate::update::MAX_UPDATE_TARGET_BYTES, 0o700)?;
        crate::update::write_new_file(&slot.join("supgang"), &bytes, 0o700)?;
    }
    validate_record(updates, &fallback)?;
    crate::update::executable::validate_compatible_identity(&restored.executable, &fallback.executable)?;
    Ok(Some(fallback))
}

/// Records a probation outcome where the owner can read it after reconnecting.
///
/// # Errors
///
/// Rejects unsafe state.
pub fn record_refresh_outcome(state_directory: &Path, digest: &str, result: &str, now: u64) -> Result<(), UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    let outcome = RefreshOutcome {
        schema: "supgang.refresh-outcome/v1".to_owned(),
        version: VERSION.to_owned(),
        digest: digest.to_owned(),
        result: result.to_owned(),
        recorded_at: now,
    };
    write_atomic(
        &updates,
        OUTCOME_FILE,
        &serde_json::to_vec(&outcome).map_err(|_| UpdateError::InvalidBundle)?,
        0o600,
    )
}

/// The last recorded probation outcome, if any.
///
/// # Errors
///
/// Rejects unsafe state or a malformed record.
pub fn last_refresh_outcome(state_directory: &Path) -> Result<Option<RefreshOutcome>, UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    let path = updates.join(OUTCOME_FILE);
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(None);
    }
    let bytes = crate::artifact::read(&path, 1024)?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| UpdateError::InvalidBundle)
}
