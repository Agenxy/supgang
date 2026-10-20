//! An owner's local refresh to a newer release is staged as the supervisor's
//! pending candidate, never installed over the known-good release, and a
//! committed candidate that fails to reconnect can return to the previous one.

use std::{fs, os::unix::fs::PermissionsExt};

use super::{fixture_executable, initialize_active_fixture, sign_update_fixture};
use crate::update::{
    lifecycle::{self, SlotRecord},
    updates_directory,
};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

/// Rewrites the active record as an older release, as a computer still
/// running the previous version would have it.
fn age_active(state: &std::path::Path) -> std::result::Result<SlotRecord, Box<dyn std::error::Error>> {
    let updates = updates_directory(state, false)?;
    let mut active = lifecycle::read_active(state)?;
    active.version = "0.0.1".to_owned();
    lifecycle::write_atomic(&updates, "active.json", &serde_json::to_vec(&active)?, 0o600)?;
    Ok(active)
}

fn candidate_bytes(directory: &std::path::Path) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    let candidate = directory.join("candidate-supgang");
    fs::copy(fixture_executable()?, &candidate)?;
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))?;
    sign_update_fixture(&candidate, 2)?;
    Ok(fs::read(candidate)?)
}

#[test]
fn a_same_version_refresh_is_not_staged() -> Result {
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    initialize_active_fixture(&state, temporary.path())?;
    let bytes = candidate_bytes(temporary.path())?;
    assert_eq!(lifecycle::stage_local_candidate_unlocked(&state, &bytes)?, None);
    assert!(lifecycle::read_pending(&state)?.is_none());
    Ok(())
}

#[test]
fn a_newer_release_waits_as_the_candidate_and_the_known_good_one_stays_active() -> Result {
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    initialize_active_fixture(&state, temporary.path())?;
    let known_good = age_active(&state)?;
    let bytes = candidate_bytes(temporary.path())?;

    let digest = lifecycle::stage_local_candidate_unlocked(&state, &bytes)?.ok_or("a newer release was not staged")?;
    // The supervisor reads it exactly as it reads a signed update's candidate.
    let pending = lifecycle::read_pending(&state)?.ok_or("no pending candidate")?;
    assert_eq!(pending.digest, digest);
    assert_eq!(pending.version, crate::VERSION);
    assert_eq!(fs::read(&pending.executable)?, bytes);
    assert_eq!(lifecycle::read_active(&state)?, known_good);
    assert_eq!(lifecycle::active_digest(&state)?, known_good.digest);
    Ok(())
}

#[test]
fn a_committed_candidate_that_never_reconnects_returns_to_the_previous_release() -> Result {
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    initialize_active_fixture(&state, temporary.path())?;
    let known_good = age_active(&state)?;
    let bytes = candidate_bytes(temporary.path())?;
    let digest = lifecycle::stage_local_candidate_unlocked(&state, &bytes)?.ok_or("not staged")?;
    let pending = lifecycle::read_pending(&state)?.ok_or("no pending candidate")?;
    lifecycle::commit_pending(&state, &pending)?;
    assert_eq!(lifecycle::active_digest(&state)?, digest);

    // Only the release that is active, and failed, can be reverted.
    assert!(lifecycle::revert_local_candidate_unlocked(&state, &known_good.digest).is_err());
    lifecycle::revert_local_candidate_unlocked(&state, &digest)?;
    assert_eq!(lifecycle::read_active(&state)?, known_good);
    // A second revert has nothing to return to.
    assert!(lifecycle::revert_local_candidate_unlocked(&state, &digest).is_err());

    lifecycle::record_refresh_outcome(&state, &digest, "reverted-no-peer", 1_792_000_000)?;
    let outcome = lifecycle::last_refresh_outcome(&state)?.ok_or("no outcome recorded")?;
    assert_eq!(outcome.result, "reverted-no-peer");
    assert_eq!(outcome.digest, digest);
    Ok(())
}
