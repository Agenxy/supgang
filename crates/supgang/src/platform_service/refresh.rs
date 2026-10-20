//! Owner refresh of an installed service, with probation for a newer release.
//!
//! A newer release is staged as the supervisor's pending candidate rather than
//! installed over the known-good one, and the installed supervisor is left in
//! place to judge it: it runs the candidate under health probation and returns
//! to the known-good release if the candidate fails. A healthy candidate must
//! then also reconnect a peer, when one was connected before the refresh,
//! because a release that starts but cannot reach the owner's other computers
//! would strand an owner who can only reach this one through Supgang. If none
//! reconnects in time, the refresh returns to the previous release itself.
//!
//! The command detaches into its own session, so the SSH session that started
//! it, which rides the connection being replaced, can end without ending it,
//! and it records the outcome where the owner can read it after reconnecting.

use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};

use super::{Report, ServiceError, executable, service_update_error};
use crate::control::{self, ControlReply, ControlRequest};

/// The supervisor's verdict: start (10 s) plus probation (30 s), with margin.
const VERDICT_TIMEOUT: Duration = Duration::from_secs(90);
/// A committed release must reconnect a peer within this. A peer whose old
/// connection went silent redials within about 20 s; this allows several
/// retry rounds across an ocean.
const RECONNECT_TIMEOUT: Duration = Duration::from_mins(2);
const POLL: Duration = Duration::from_millis(500);

pub(super) enum Refreshed {
    /// The release replaced the active one directly, as before probation.
    Direct,
    /// A newer release waits as the pending candidate.
    Candidate { digest: String, peers_before: u32 },
}

/// Stages a newer release as a candidate, or installs the same release
/// directly. The caller then restarts the service and calls [`settle`].
pub(super) fn install(state_directory: &Path) -> Result<Refreshed, ServiceError> {
    let peers_before = connected_peers(state_directory).unwrap_or(0);
    let lock = crate::update::UpdateLock::acquire(state_directory).map_err(|error| service_update_error(&error))?;
    crate::update::preflight_local_refresh_unlocked(state_directory).map_err(|error| service_update_error(&error))?;
    let bytes = executable::read_current()?;
    if let Some(digest) = crate::update::stage_local_candidate_unlocked(state_directory, &bytes)
        .map_err(|error| service_update_error(&error))?
    {
        drop(lock);
        // Outlive the SSH session that started this; it rides the connection
        // the restart replaces. A process that already leads its session
        // cannot detach and does not need to.
        let _session = rustix::process::setsid();
        return Ok(Refreshed::Candidate { digest, peers_before });
    }
    let installed = executable::install_current()?;
    crate::update::initialize_installed_unlocked(state_directory, &installed)
        .map_err(|error| service_update_error(&error))?;
    drop(lock);
    Ok(Refreshed::Direct)
}

/// Waits for a candidate's verdict and its reconnection, returning to the
/// previous release if it does not reconnect.
pub(super) fn settle(state_directory: &Path, refreshed: Refreshed, report: Report) -> Result<Report, ServiceError> {
    let Refreshed::Candidate { digest, peers_before } = refreshed else {
        return Ok(report);
    };
    let verdict = Instant::now() + VERDICT_TIMEOUT;
    while crate::update::activation_pending(state_directory).map_err(|error| service_update_error(&error))? {
        if Instant::now() >= verdict {
            return Err(ServiceError::NotReady);
        }
        thread::sleep(POLL);
    }
    if crate::update::active_digest(state_directory).map_err(|error| service_update_error(&error))? != digest {
        record(state_directory, &digest, "reverted-unhealthy");
        return Err(ServiceError::CandidateRejected);
    }
    if peers_before == 0 {
        record(state_directory, &digest, "committed");
        return Ok(report);
    }
    let reconnect = Instant::now() + RECONNECT_TIMEOUT;
    while Instant::now() < reconnect {
        if connected_peers(state_directory).is_some_and(|peers| peers > 0) {
            record(state_directory, &digest, "committed");
            return Ok(report);
        }
        thread::sleep(POLL);
    }
    {
        let _lock =
            crate::update::UpdateLock::acquire(state_directory).map_err(|error| service_update_error(&error))?;
        crate::update::revert_local_candidate_unlocked(state_directory, &digest)
            .map_err(|error| service_update_error(&error))?;
    }
    record(state_directory, &digest, "reverted-no-peer");
    // The supervisor exits on a clean restart with nothing pending, and the
    // service manager starts it again on the active, previous release.
    let _restart = control::request(state_directory, ControlRequest::Restart);
    Err(ServiceError::CandidateReverted)
}

fn connected_peers(state_directory: &Path) -> Option<u32> {
    match control::probe(state_directory, ControlRequest::Status) {
        Ok(Some(ControlReply::Status { value })) => u32::try_from(value.active_peers).ok(),
        _ => None,
    }
}

fn record(state_directory: &Path, digest: &str, result: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let _recorded = crate::update::record_refresh_outcome(state_directory, digest, result, now);
}
