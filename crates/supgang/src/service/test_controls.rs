//! Deterministic simulator knobs for asymmetric local path observations.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use crate::ids::NodeId;

#[derive(Clone, Copy, Debug, Default)]
pub(super) enum OnLinkPreference {
    #[default]
    NotNeeded,
    Desired,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct RecoverySnapshot {
    pub(super) cooldown_ms: Option<u64>,
    pub(super) on_link_preference: OnLinkPreference,
    pub(super) pending_replacement: bool,
    pub(super) recent_admission: bool,
    pub(super) outbound_in_flight: bool,
}

impl std::fmt::Display for RecoverySnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "cooldown_ms={:?} on_link_preference={:?} pending_replacement={} recent_admission={} outbound_in_flight={}",
            self.cooldown_ms,
            self.on_link_preference,
            self.pending_replacement,
            self.recent_admission,
            self.outbound_in_flight
        )
    }
}

#[derive(Default)]
pub(super) struct SimControls {
    pub(super) suppress_rtt_replacement: AtomicBool,
    pub(super) suppress_quality_dial: AtomicBool,
    pub(super) reject_duplicate: AtomicBool,
    pub(super) replacement_attempts: AtomicU64,
    pub(super) quality_dials: AtomicU64,
    pub(super) drain_limit_seconds: AtomicU64,
    pub(super) interface_changes: AtomicU64,
    pub(super) recovery: Mutex<BTreeMap<NodeId, RecoverySnapshot>>,
    pub(super) recovery_events: [AtomicU64; RecoveryEvent::COUNT],
}

#[derive(Clone, Copy)]
#[repr(usize)]
pub(super) enum RecoveryEvent {
    EmptyCandidates,
    OnLinkDial,
    Authenticated,
    AuthenticationFailed,
    AdmissionRejected,
    ProofStarted,
    ProofSucceeded,
    ProofFailed,
}

impl RecoveryEvent {
    pub(super) const COUNT: usize = 8;
}

thread_local! {
    static ACTIVE: RefCell<Option<Arc<SimControls>>> = const { RefCell::new(None) };
}

pub(super) struct Guard(Option<Arc<SimControls>>);

pub(super) fn install(controls: Arc<SimControls>) -> Guard {
    Guard(ACTIVE.with(|active| active.replace(Some(controls))))
}

impl Drop for Guard {
    fn drop(&mut self) {
        ACTIVE.with(|active| {
            active.replace(self.0.take());
        });
    }
}

pub(super) fn suppress_rtt_replacement() -> bool {
    ACTIVE.with(|active| {
        active.borrow().as_ref().is_some_and(|controls| {
            controls.replacement_attempts.fetch_add(1, Ordering::Relaxed);
            controls.suppress_rtt_replacement.load(Ordering::Relaxed)
        })
    })
}

pub(super) fn suppress_quality_dial() -> bool {
    ACTIVE.with(|active| {
        active
            .borrow()
            .as_ref()
            .is_some_and(|controls| controls.suppress_quality_dial.load(Ordering::Relaxed))
    })
}

pub(super) fn note_quality_dial() {
    ACTIVE.with(|active| {
        if let Some(controls) = active.borrow().as_ref() {
            controls.quality_dials.fetch_add(1, Ordering::Relaxed);
        }
    });
}

pub(super) fn note_interface_change() {
    ACTIVE.with(|active| {
        if let Some(controls) = active.borrow().as_ref() {
            controls.interface_changes.fetch_add(1, Ordering::Relaxed);
        }
    });
}

pub(super) fn note_recovery_event(event: RecoveryEvent) {
    ACTIVE.with(|active| {
        if let Some(controls) = active.borrow().as_ref()
            && let Some(counter) = controls.recovery_events.get(event as usize)
        {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });
}

pub(super) fn record_recovery(
    active: &std::collections::BTreeMap<NodeId, super::active::ActiveConnection>,
    replacements: &std::collections::BTreeMap<NodeId, super::live_session::PendingReplacement>,
    quality: &super::path_quality::PathQualityWatch,
    outbound_in_flight: bool,
    now: tokio::time::Instant,
) {
    ACTIVE.with(|slot| {
        if let Some(controls) = slot.borrow().as_ref()
            && let Ok(mut snapshots) = controls.recovery.lock()
        {
            let networks = crate::network::interface_networks().unwrap_or_default();
            snapshots.clear();
            for peer in active.keys() {
                let (cooldown_ms, recent_admission) = quality.diagnostic(*peer, now);
                snapshots.insert(
                    *peer,
                    RecoverySnapshot {
                        cooldown_ms,
                        on_link_preference: if super::retry_schedule::wants_on_link_path(active, *peer, &networks) {
                            OnLinkPreference::Desired
                        } else {
                            OnLinkPreference::NotNeeded
                        },
                        pending_replacement: replacements.contains_key(peer),
                        recent_admission,
                        outbound_in_flight,
                    },
                );
            }
        }
    });
}

pub(super) fn reject_duplicate() -> bool {
    ACTIVE.with(|active| {
        active
            .borrow()
            .as_ref()
            .is_some_and(|controls| controls.reject_duplicate.load(Ordering::Relaxed))
    })
}

pub(super) fn drain_limit(default: Duration) -> Duration {
    ACTIVE.with(|active| {
        active.borrow().as_ref().map_or(default, |controls| {
            let seconds = controls.drain_limit_seconds.load(Ordering::Relaxed);
            if seconds == 0 {
                default
            } else {
                Duration::from_secs(seconds)
            }
        })
    })
}
