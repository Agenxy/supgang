//! Bounded observation of live paths before trying another signed candidate.

use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

use tokio::time::Instant;

use super::active::ActiveConnection;
use crate::ids::NodeId;

const BAD_RTT_FACTOR: u32 = 3;
const BAD_RTT_FLOOR: Duration = Duration::from_millis(150);
const BAD_RTT_SUSTAIN: Duration = Duration::from_secs(8);
const MIN_RESIDENCE: Duration = Duration::from_secs(5);
const ATTEMPT_COOLDOWN: Duration = Duration::from_secs(30);
const REPLACEMENT_COOLDOWN: Duration = Duration::from_mins(1);
const RECENT_ADMISSION_WINDOW: Duration = Duration::from_mins(2);
pub(super) const BLACK_HOLES_BEFORE_MTU_CAP: u64 = 3;

struct Observation {
    connection_id: usize,
    joined: Instant,
    best_rtt: Option<Duration>,
    bad_since: Option<Instant>,
    next_allowed: Instant,
    on_link_bypass_record: Option<(u64, u64)>,
}

impl Observation {
    fn new(connection_id: usize, now: Instant, replaced: bool) -> Self {
        Self {
            connection_id,
            joined: now,
            best_rtt: None,
            bad_since: None,
            next_allowed: now + if replaced { REPLACEMENT_COOLDOWN } else { MIN_RESIDENCE },
            on_link_bypass_record: None,
        }
    }

    fn sample(&mut self, rtt: Duration, black_holes: u64, now: Instant) -> bool {
        if !rtt.is_zero() {
            let best = self.best_rtt.get_or_insert(rtt);
            if rtt < *best {
                *best = rtt;
            }
            let bad = rtt >= BAD_RTT_FLOOR && rtt >= best.saturating_mul(BAD_RTT_FACTOR);
            if bad {
                self.bad_since.get_or_insert(now);
            } else {
                self.bad_since = None;
            }
        }
        black_holes >= BLACK_HOLES_BEFORE_MTU_CAP
    }

    fn due(&self, now: Instant) -> bool {
        now >= self.next_allowed
            && now.saturating_duration_since(self.joined) >= MIN_RESIDENCE
            && self
                .bad_since
                .is_some_and(|since| now.saturating_duration_since(since) >= BAD_RTT_SUSTAIN)
    }

    fn attempted(&mut self, now: Instant) {
        self.next_allowed = now + ATTEMPT_COOLDOWN;
    }
}

/// One fixed-size entry per admitted peer; no work is spawned during sampling.
#[derive(Default)]
pub(super) struct PathQualityWatch {
    paths: BTreeMap<NodeId, Observation>,
    recent_admissions: BTreeMap<NodeId, (usize, Instant)>,
    /// Recently observed peers whose black-holed address needs a safe redial.
    capped: BTreeMap<NodeId, (SocketAddr, Instant)>,
}

impl PathQualityWatch {
    /// A different local network may expose a directly attached path to a
    /// peer. Previous-path residence and rejection backoff must not delay the
    /// first attempt on that new network; a failed attempt gets fresh backoff.
    pub(super) fn network_changed(&mut self, now: Instant) {
        for entry in self.paths.values_mut() {
            entry.next_allowed = now;
            entry.on_link_bypass_record = None;
        }
    }

    pub(super) fn observe(&mut self, active: &BTreeMap<NodeId, ActiveConnection>, now: Instant) {
        self.recent_admissions
            .retain(|_, (_, at)| now.saturating_duration_since(*at) <= RECENT_ADMISSION_WINDOW);
        for (peer, connection) in active {
            self.note_admitted(*peer, connection.stable_id(), now);
        }
        self.paths.retain(|peer, _| active.contains_key(peer));
        for (peer, connection) in active {
            let id = connection.stable_id();
            let previous = self.paths.get(peer);
            if previous.is_none_or(|entry| entry.connection_id != id) {
                self.paths.insert(*peer, Observation::new(id, now, previous.is_some()));
            }
            if let Some(entry) = self.paths.get_mut(peer) {
                let stats = connection.stats().path;
                if entry.sample(stats.rtt, stats.black_holes_detected, now) {
                    if self.capped.len() >= super::MAX_ANCHOR_PEERS && !self.capped.contains_key(peer) {
                        let oldest = self.capped.iter().min_by_key(|(_, (_, at))| at).map(|(peer, _)| *peer);
                        if let Some(oldest) = oldest {
                            self.capped.remove(&oldest);
                        }
                    }
                    self.capped.insert(*peer, (connection.remote_address(), now));
                }
            }
        }
    }

    pub(super) fn wants_replacement(&self, peer: NodeId, now: Instant) -> bool {
        #[cfg(test)]
        if super::test_controls::suppress_quality_dial() {
            return false;
        }
        self.paths.get(&peer).is_some_and(|entry| entry.due(now))
    }

    pub(super) fn allows_replacement(&self, peer: NodeId, now: Instant) -> bool {
        self.paths.get(&peer).is_none_or(|entry| now >= entry.next_allowed)
    }

    /// A fresh signed record or local interface change permits one authenticated
    /// on-link route attempt despite the prior path's quality cooldown.
    pub(super) fn allows_on_link_bypass(&self, peer: NodeId, record: (u64, u64)) -> bool {
        self.paths
            .get(&peer)
            .is_some_and(|entry| entry.on_link_bypass_record != Some(record))
    }

    pub(super) fn mark_on_link_bypass(&mut self, peer: NodeId, record: (u64, u64), now: Instant) {
        if let Some(entry) = self.paths.get_mut(&peer) {
            entry.on_link_bypass_record = Some(record);
            entry.next_allowed = entry.next_allowed.max(now + ATTEMPT_COOLDOWN);
        }
    }

    #[cfg(test)]
    pub(super) fn diagnostic(&self, peer: NodeId, now: Instant) -> (Option<u64>, bool) {
        let cooldown_ms = self.paths.get(&peer).map(|entry| {
            u64::try_from(entry.next_allowed.saturating_duration_since(now).as_millis()).unwrap_or(u64::MAX)
        });
        (cooldown_ms, self.recent_admissions.contains_key(&peer))
    }

    pub(super) fn recent_admissions(&self, now: Instant) -> BTreeMap<NodeId, usize> {
        self.recent_admissions
            .iter()
            .filter(|(_, (_, at))| now.saturating_duration_since(*at) <= RECENT_ADMISSION_WINDOW)
            .map(|(peer, (id, _))| (*peer, *id))
            .collect()
    }

    pub(super) fn note_admitted(&mut self, peer: NodeId, id: usize, now: Instant) {
        if self.recent_admissions.len() >= super::MAX_ANCHOR_PEERS && !self.recent_admissions.contains_key(&peer) {
            let oldest = self
                .recent_admissions
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(peer, _)| *peer);
            if let Some(oldest) = oldest {
                self.recent_admissions.remove(&oldest);
            }
        }
        self.recent_admissions.insert(peer, (id, now));
    }

    pub(super) fn capped_address(&self, peer: NodeId) -> Option<SocketAddr> {
        self.capped.get(&peer).map(|(address, _)| *address)
    }

    /// Pre-handshake source matching can only reduce PMTU probing. The
    /// address enters this map from an authenticated connection's statistics.
    pub(super) fn capped_source(&self, source: SocketAddr) -> bool {
        let source_ip = source.ip().to_canonical();
        self.capped
            .values()
            .any(|(address, _)| address.ip().to_canonical() == source_ip)
    }

    pub(super) fn mark_attempt(&mut self, peer: NodeId, now: Instant) {
        #[cfg(test)]
        super::test_controls::note_quality_dial();
        if let Some(entry) = self.paths.get_mut(&peer) {
            entry.attempted(now);
        }
    }

    /// A peer that rejected a candidate must not be redialled each round.
    pub(super) fn backoff(&mut self, peer: NodeId, now: Instant) {
        if let Some(entry) = self.paths.get_mut(&peer) {
            entry.next_allowed = now + REPLACEMENT_COOLDOWN;
        }
    }
}

/// A fresh authenticated path must be much faster, not merely win by jitter.
pub(super) fn materially_better(old: Duration, new: Duration) -> bool {
    !old.is_zero()
        && !new.is_zero()
        && old.saturating_sub(new) >= Duration::from_millis(100)
        && new.saturating_mul(2) <= old
}

#[cfg(test)]
mod tests {
    use super::{
        BLACK_HOLES_BEFORE_MTU_CAP, MIN_RESIDENCE, Observation, PathQualityWatch, REPLACEMENT_COOLDOWN,
        materially_better,
    };
    use crate::ids::NodeId;
    use std::time::Duration;
    use tokio::time::Instant;

    #[test]
    fn sustained_bad_rtt_is_bounded_and_a_replacement_gets_hysteresis() {
        let now = Instant::now();
        let mut path = Observation::new(1, now, false);
        path.sample(Duration::from_millis(200), 0, now);
        path.sample(Duration::from_millis(800), 0, now + Duration::from_secs(5));
        assert!(!path.due(now + Duration::from_secs(12)));
        assert!(path.due(now + Duration::from_secs(13)));
        path.attempted(now + Duration::from_secs(13));
        assert!(!path.due(now + Duration::from_secs(14)));
        let mut replacement = Observation::new(2, now + Duration::from_secs(20), true);
        replacement.sample(Duration::from_millis(200), 0, now + Duration::from_secs(20));
        replacement.sample(Duration::from_millis(800), 0, now + Duration::from_secs(25));
        assert!(!replacement.due(now + Duration::from_secs(79)));
        assert!(replacement.due(now + Duration::from_secs(80)));
    }

    #[test]
    fn only_a_material_rtt_improvement_qualifies() {
        assert!(materially_better(
            Duration::from_millis(1_500),
            Duration::from_millis(200)
        ));
        assert!(!materially_better(
            Duration::from_millis(200),
            Duration::from_millis(130)
        ));
        assert!(!materially_better(Duration::ZERO, Duration::from_millis(100)));
    }

    #[test]
    fn repeated_black_holes_alone_never_request_a_replacement() {
        let now = Instant::now();
        let mut path = Observation::new(1, now, false);
        for count in 1..=BLACK_HOLES_BEFORE_MTU_CAP + 2 {
            let at = now + Duration::from_secs(count);
            assert_eq!(
                path.sample(Duration::from_millis(200), count, at),
                count >= BLACK_HOLES_BEFORE_MTU_CAP
            );
            assert!(!path.due(at + MIN_RESIDENCE));
        }
    }

    #[test]
    fn rejected_candidate_backs_off_on_link_retries_too() {
        let now = Instant::now();
        let peer = NodeId::from_bytes([7; 32]);
        let mut quality = PathQualityWatch::default();
        quality
            .paths
            .insert(peer, Observation::new(1, now - MIN_RESIDENCE, false));
        assert!(quality.allows_replacement(peer, now));
        quality.backoff(peer, now);
        assert!(!quality.allows_replacement(peer, now + Duration::from_secs(30)));
        assert!(quality.allows_replacement(peer, now + REPLACEMENT_COOLDOWN));
    }

    #[test]
    fn network_change_releases_prior_path_cooldown_then_rejection_backs_off_again() {
        let now = Instant::now();
        let peer = NodeId::from_bytes([8; 32]);
        let mut quality = PathQualityWatch::default();
        quality.paths.insert(peer, Observation::new(1, now, true));
        assert!(!quality.allows_replacement(peer, now));
        quality.network_changed(now);
        assert!(quality.allows_replacement(peer, now));
        quality.backoff(peer, now);
        assert!(!quality.allows_replacement(peer, now + Duration::from_secs(30)));
    }

    #[test]
    fn on_link_bypass_is_once_per_signed_record_or_interface_change() {
        let now = Instant::now();
        let peer = NodeId::from_bytes([9; 32]);
        let mut quality = PathQualityWatch::default();
        quality.paths.insert(peer, Observation::new(1, now, true));
        assert!(!quality.allows_replacement(peer, now));
        assert!(quality.allows_on_link_bypass(peer, (0, 1)));
        quality.mark_on_link_bypass(peer, (0, 1), now);
        assert!(!quality.allows_on_link_bypass(peer, (0, 1)));
        quality.backoff(peer, now);
        assert!(!quality.allows_on_link_bypass(peer, (0, 1)));
        assert!(quality.allows_on_link_bypass(peer, (0, 2)));
        quality.mark_on_link_bypass(peer, (0, 2), now);
        assert!(!quality.allows_on_link_bypass(peer, (0, 2)));
        quality.network_changed(now);
        assert!(quality.allows_on_link_bypass(peer, (0, 2)));
    }
}
