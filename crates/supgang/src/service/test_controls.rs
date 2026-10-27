//! Deterministic simulator knobs for asymmetric local path observations.

use std::{
    cell::RefCell,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

#[derive(Default)]
pub(super) struct SimControls {
    pub(super) suppress_rtt_replacement: AtomicBool,
    pub(super) suppress_quality_dial: AtomicBool,
    pub(super) reject_duplicate: AtomicBool,
    pub(super) replacement_attempts: AtomicU64,
    pub(super) quality_dials: AtomicU64,
    pub(super) drain_limit_seconds: AtomicU64,
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
