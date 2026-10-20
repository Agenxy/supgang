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
///
/// A staged candidate is always judged here, whatever `restarted` says. The
/// restart's own wait can end while the supervisor is still validating and
/// starting the candidate, and returning then would skip the reconnection
/// check that keeps a release that cannot reach its peers from staying.
pub(super) fn settle(
    state_directory: &Path,
    refreshed: Refreshed,
    restarted: Result<Report, ServiceError>,
    report: impl Fn() -> Result<Report, ServiceError>,
) -> Result<Report, ServiceError> {
    settle_with(
        &Local(state_directory),
        refreshed,
        restarted,
        report,
        Timings::INSTALLED,
    )
}

/// How long each stage of a candidate's judgement may take.
#[derive(Clone, Copy)]
struct Timings {
    verdict: Duration,
    reconnect: Duration,
    poll: Duration,
}

impl Timings {
    const INSTALLED: Self = Self {
        verdict: VERDICT_TIMEOUT,
        reconnect: RECONNECT_TIMEOUT,
        poll: POLL,
    };
}

/// The state a candidate's judgement reads and the actions it may take.
trait Probation {
    fn pending(&self) -> Result<bool, ServiceError>;
    fn active_digest(&self) -> Result<String, ServiceError>;
    fn connected_peers(&self) -> Option<u32>;
    fn revert(&self, failed: &str) -> Result<(), ServiceError>;
    fn restart(&self);
    fn record(&self, digest: &str, result: &str);
    /// A progress line for the refresh log; the owner reads it after reconnecting.
    fn note(&self, line: &str);
}

fn settle_with(
    probation: &impl Probation,
    refreshed: Refreshed,
    restarted: Result<Report, ServiceError>,
    report: impl Fn() -> Result<Report, ServiceError>,
    timings: Timings,
) -> Result<Report, ServiceError> {
    let Refreshed::Candidate { digest, peers_before } = refreshed else {
        return restarted;
    };
    if restarted.is_err() {
        probation.note("restart wait ended before the service answered; judging the candidate anyway");
    }
    let verdict = Instant::now() + timings.verdict;
    while probation.pending()? {
        if Instant::now() >= verdict {
            probation.note("no supervisor verdict in time");
            return Err(ServiceError::NotReady);
        }
        thread::sleep(timings.poll);
    }
    if probation.active_digest()? != digest {
        probation.note("supervisor rejected the candidate; the previous release runs");
        probation.record(&digest, "reverted-unhealthy");
        return Err(ServiceError::CandidateRejected);
    }
    probation.note("supervisor committed the candidate");
    if peers_before == 0 {
        probation.record(&digest, "committed");
        return report();
    }
    probation.note("waiting for a peer to reconnect");
    let reconnect = Instant::now() + timings.reconnect;
    while Instant::now() < reconnect {
        if probation.connected_peers().is_some_and(|peers| peers > 0) {
            probation.note("a peer reconnected; keeping the candidate");
            probation.record(&digest, "committed");
            return report();
        }
        thread::sleep(timings.poll);
    }
    probation.note("no peer reconnected; returning to the previous release");
    probation.revert(&digest)?;
    probation.record(&digest, "reverted-no-peer");
    // The supervisor exits on a clean restart with nothing pending, and the
    // service manager starts it again on the active, previous release.
    probation.restart();
    probation.note("restart requested on the previous release");
    Err(ServiceError::CandidateReverted)
}

/// This computer's update state and running service.
struct Local<'a>(&'a Path);

impl Probation for Local<'_> {
    fn pending(&self) -> Result<bool, ServiceError> {
        crate::update::activation_pending(self.0).map_err(|error| service_update_error(&error))
    }

    fn active_digest(&self) -> Result<String, ServiceError> {
        crate::update::active_digest(self.0).map_err(|error| service_update_error(&error))
    }

    fn connected_peers(&self) -> Option<u32> {
        connected_peers(self.0)
    }

    fn revert(&self, failed: &str) -> Result<(), ServiceError> {
        let _lock = crate::update::UpdateLock::acquire(self.0).map_err(|error| service_update_error(&error))?;
        crate::update::revert_local_candidate_unlocked(self.0, failed).map_err(|error| service_update_error(&error))
    }

    fn restart(&self) {
        let _restart = control::request(self.0, ControlRequest::Restart);
    }

    fn record(&self, digest: &str, result: &str) {
        let _recorded = crate::update::record_refresh_outcome(self.0, crate::VERSION, digest, result, unix_now());
    }

    fn note(&self, line: &str) {
        use std::io::Write as _;
        let _written = writeln!(std::io::stderr(), "supgang refresh {}: {line}", unix_now());
    }
}

fn connected_peers(state_directory: &Path) -> Option<u32> {
    match control::probe(state_directory, ControlRequest::Status) {
        Ok(Some(ControlReply::Status { value })) => u32::try_from(value.active_peers).ok(),
        _ => None,
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests;
