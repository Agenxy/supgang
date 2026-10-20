//! The judgement of a staged candidate, against a scripted supervisor and
//! service. The 20 October laptop drill found that a restart wait which timed
//! out, while the supervisor was still starting the candidate, skipped the
//! reconnection check entirely.

use std::{
    cell::{Cell, RefCell},
    time::{Duration, Instant},
};

use super::{Probation, Refreshed, Timings, settle_with};
use crate::platform_service::{Report, ServiceError};

const CANDIDATE: &str = "candidate";
const PREVIOUS: &str = "previous";

/// A supervisor that gives its verdict after `verdict_after`, and a service
/// whose peers appear after `peers_after`, if ever.
struct Scripted {
    started: Instant,
    verdict_after: Duration,
    commits: bool,
    peers_after: Option<Duration>,
    reverted: Cell<bool>,
    restarted: Cell<bool>,
    records: RefCell<Vec<String>>,
}

impl Scripted {
    fn new(verdict_after: Duration, commits: bool, peers_after: Option<Duration>) -> Self {
        Self {
            started: Instant::now(),
            verdict_after,
            commits,
            peers_after,
            reverted: Cell::new(false),
            restarted: Cell::new(false),
            records: RefCell::new(Vec::new()),
        }
    }
}

impl Probation for Scripted {
    fn pending(&self) -> Result<bool, ServiceError> {
        Ok(self.started.elapsed() < self.verdict_after)
    }

    fn active_digest(&self) -> Result<String, ServiceError> {
        Ok(if self.commits && !self.reverted.get() {
            CANDIDATE
        } else {
            PREVIOUS
        }
        .to_owned())
    }

    fn connected_peers(&self) -> Option<u32> {
        Some(u32::from(
            self.peers_after.is_some_and(|after| self.started.elapsed() >= after),
        ))
    }

    fn revert(&self, failed: &str) -> Result<(), ServiceError> {
        assert_eq!(failed, CANDIDATE);
        self.reverted.set(true);
        Ok(())
    }

    fn restart(&self) {
        self.restarted.set(true);
    }

    fn record(&self, digest: &str, result: &str) {
        assert_eq!(digest, CANDIDATE);
        self.records.borrow_mut().push(result.to_owned());
    }

    fn note(&self, _line: &str) {}
}

const FAST: Timings = Timings {
    verdict: Duration::from_secs(2),
    reconnect: Duration::from_millis(600),
    poll: Duration::from_millis(20),
};

fn candidate() -> Refreshed {
    Refreshed::Candidate {
        digest: CANDIDATE.to_owned(),
        peers_before: 1,
    }
}

fn report() -> Report {
    crate::platform_service::report("test", true, true, true)
}

#[test]
fn a_restart_wait_that_times_out_still_reverts_a_candidate_that_never_reconnects() {
    // The supervisor is slow to give its verdict, as on 20 October, and the
    // restart's own wait has already given up.
    let probation = Scripted::new(Duration::from_millis(300), true, None);
    let result = settle_with(
        &probation,
        candidate(),
        Err(ServiceError::NotReady),
        || Ok(report()),
        FAST,
    );
    assert!(matches!(result, Err(ServiceError::CandidateReverted)), "{result:?}");
    assert!(probation.reverted.get(), "the candidate was not reverted");
    assert!(probation.restarted.get(), "the previous release was not restarted");
    assert_eq!(*probation.records.borrow(), ["reverted-no-peer"]);
}

#[test]
fn a_restart_wait_that_times_out_still_keeps_a_candidate_that_reconnects() {
    let probation = Scripted::new(Duration::from_millis(300), true, Some(Duration::from_millis(400)));
    let result = settle_with(
        &probation,
        candidate(),
        Err(ServiceError::NotReady),
        || Ok(report()),
        FAST,
    );
    assert!(result.is_ok(), "{result:?}");
    assert!(!probation.reverted.get());
    assert_eq!(*probation.records.borrow(), ["committed"]);
}

#[test]
fn a_candidate_the_supervisor_rejects_is_reported_without_a_second_revert() {
    let probation = Scripted::new(Duration::from_millis(100), false, Some(Duration::ZERO));
    let result = settle_with(
        &probation,
        candidate(),
        Err(ServiceError::NotReady),
        || Ok(report()),
        FAST,
    );
    assert!(matches!(result, Err(ServiceError::CandidateRejected)), "{result:?}");
    assert!(!probation.reverted.get());
    assert_eq!(*probation.records.borrow(), ["reverted-unhealthy"]);
}

#[test]
fn a_direct_refresh_returns_the_restart_result_unchanged() {
    let probation = Scripted::new(Duration::ZERO, true, None);
    let result = settle_with(
        &probation,
        Refreshed::Direct,
        Err(ServiceError::NotReady),
        || Ok(report()),
        FAST,
    );
    assert!(matches!(result, Err(ServiceError::NotReady)));
    assert!(probation.records.borrow().is_empty());
}
