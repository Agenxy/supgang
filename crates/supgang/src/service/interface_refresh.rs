//! Bounded automatic interface and authenticated public-address refresh policy.

use std::{net::SocketAddr, time::Duration};

use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate, MAX_CANDIDATES},
    endpoint_config::EndpointConfig,
    router_mapping::{RouterMapping, RouterMappingStatus},
};

use super::ServiceConfig;

const ROUTER_MAPPING_UPDATE_WINDOW: Duration = Duration::from_mins(5);
const MAX_ROUTER_MAPPING_UPDATES_PER_WINDOW: u8 = 4;
const INTERFACE_FAILURES_BEFORE_CLEAR: u8 = 2;

pub(super) struct InterfaceRefreshHealth {
    failures: u8,
}

impl InterfaceRefreshHealth {
    pub(super) const fn new() -> Self {
        Self { failures: 0 }
    }

    const fn available(&mut self) {
        self.failures = 0;
    }

    const fn unavailable(&mut self) -> bool {
        self.failures = self.failures.saturating_add(1);
        self.failures >= INTERFACE_FAILURES_BEFORE_CLEAR
    }
}

enum AutomaticRefresh {
    Changed,
    Unchanged,
    Unavailable,
}

pub(super) struct RouterMappingUpdateBudget {
    window_started: tokio::time::Instant,
    updates: u8,
    published: Option<RouterMappingStatus>,
    renew_at: tokio::time::Instant,
}

impl RouterMappingUpdateBudget {
    pub(super) const fn new(now: tokio::time::Instant) -> Self {
        Self {
            window_started: now,
            updates: 0,
            published: None,
            renew_at: now,
        }
    }

    pub(super) fn allow(&mut self, now: tokio::time::Instant) -> bool {
        if now.saturating_duration_since(self.window_started) >= ROUTER_MAPPING_UPDATE_WINDOW {
            self.window_started = now;
            self.updates = 0;
        }
        if self.updates >= MAX_ROUTER_MAPPING_UPDATES_PER_WINDOW {
            return false;
        }
        self.updates = self.updates.saturating_add(1);
        true
    }

    pub(super) fn take_change(
        &mut self,
        mapping: &mut RouterMapping,
        now: tokio::time::Instant,
    ) -> Option<RouterMappingStatus> {
        // Observe the watch to clear network-refresh state, but retain the
        // latest mapping in the mapper when publication is rate limited.
        let _change = mapping.take_change();
        self.observe(mapping.status(), now)
    }

    fn observe(&mut self, latest: RouterMappingStatus, now: tokio::time::Instant) -> Option<RouterMappingStatus> {
        let mapped = matches!(latest, RouterMappingStatus::Mapped(_));
        if self.published == Some(latest) && (!mapped || now < self.renew_at) {
            return None;
        }
        // Withdrawal is never delayed. Stable valid leases need fresh signed
        // claims too, even when their external address has not changed.
        if mapped && !self.allow(now) {
            return None;
        }
        self.published = Some(latest);
        self.renew_at = now + ROUTER_MAPPING_UPDATE_WINDOW;
        Some(latest)
    }
}

pub(super) struct CandidateRefresh {
    pub(super) interfaces_changed: bool,
    pub(super) mapping_changed: Option<RouterMappingStatus>,
}

pub(super) fn refresh_service_candidates(
    router_mapping: &mut Option<RouterMapping>,
    mapping_budget: &mut RouterMappingUpdateBudget,
    now: tokio::time::Instant,
    next_interface_refresh: &mut tokio::time::Instant,
    interface_refresh: Duration,
    config: &mut ServiceConfig,
    interface_health: &mut InterfaceRefreshHealth,
) -> CandidateRefresh {
    let mut mapping_changed = router_mapping
        .as_mut()
        .and_then(|mapping| mapping_budget.take_change(mapping, now));
    let mut interfaces_changed = false;
    if config.automatic_interface_refresh && now >= *next_interface_refresh {
        match refresh_automatic_candidates(config) {
            AutomaticRefresh::Changed => {
                interface_health.available();
                if let Some(mapping) = router_mapping.as_mut() {
                    mapping.network_changed();
                    mapping_changed = Some(RouterMappingStatus::Checking);
                }
                interfaces_changed = true;
            }
            AutomaticRefresh::Unchanged => interface_health.available(),
            AutomaticRefresh::Unavailable if interface_health.unavailable() => {
                if let Some(mapping) = router_mapping.as_mut() {
                    mapping.network_unavailable();
                    mapping_changed = Some(RouterMappingStatus::Unavailable);
                }
                interfaces_changed |= replace_interface_candidates(config, &[], &[]);
            }
            AutomaticRefresh::Unavailable => {}
        }
        *next_interface_refresh = now + interface_refresh;
    }
    CandidateRefresh {
        interfaces_changed,
        mapping_changed,
    }
}

fn refresh_automatic_candidates(config: &mut ServiceConfig) -> AutomaticRefresh {
    let Ok(discovered) = EndpointConfig::automatic(config.listen.port()) else {
        return AutomaticRefresh::Unavailable;
    };
    if replace_interface_candidates(config, discovered.local(), discovered.direct()) {
        AutomaticRefresh::Changed
    } else {
        AutomaticRefresh::Unchanged
    }
}

pub(super) fn replace_interface_candidates(
    config: &mut ServiceConfig,
    local: &[SocketAddr],
    direct: &[SocketAddr],
) -> bool {
    let current_interfaces = config
        .candidates
        .iter()
        .filter(|candidate| matches!(candidate.kind(), CandidateKind::Local | CandidateKind::Direct))
        .cloned()
        .collect::<Vec<_>>();
    let owner_declared = owner_declared_candidates(&config.candidates);
    let interface_limit = MAX_CANDIDATES.saturating_sub(owner_declared.len());
    let candidates = bounded_automatic_interfaces_with_limit(local, direct, interface_limit);
    if candidates == current_interfaces {
        return false;
    }
    config.candidates = owner_declared.into_iter().chain(candidates).collect();
    config.candidates.sort_unstable();
    config.candidates.dedup();
    true
}

pub(super) fn bounded_automatic_interfaces(
    local: &[SocketAddr],
    direct: &[SocketAddr],
    owner_declared: &[EndpointCandidate],
) -> Vec<EndpointCandidate> {
    let owner_declared = owner_declared_candidates(owner_declared);
    let interface_limit = MAX_CANDIDATES.saturating_sub(owner_declared.len());
    let interfaces = bounded_automatic_interfaces_with_limit(local, direct, interface_limit);
    let mut candidates = owner_declared.into_iter().chain(interfaces).collect::<Vec<_>>();
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

fn owner_declared_candidates(candidates: &[EndpointCandidate]) -> Vec<EndpointCandidate> {
    candidates
        .iter()
        .filter(|candidate| match candidate.kind() {
            CandidateKind::Mapped | CandidateKind::OwnedRelay => true,
            CandidateKind::Local | CandidateKind::Direct | CandidateKind::Reflexive => false,
        })
        .cloned()
        .collect()
}

fn bounded_automatic_interfaces_with_limit(
    local: &[SocketAddr],
    direct: &[SocketAddr],
    interface_limit: usize,
) -> Vec<EndpointCandidate> {
    let mut local = local
        .iter()
        .filter_map(|address| EndpointCandidate::new(CandidateKind::Local, CandidateTransport::QuicV1, *address).ok())
        .collect::<Vec<_>>();
    let mut direct = direct
        .iter()
        .filter_map(|address| EndpointCandidate::new(CandidateKind::Direct, CandidateTransport::QuicV1, *address).ok())
        .collect::<Vec<_>>();
    bound_interface_candidates(&mut local, &mut direct, interface_limit);
    let mut candidates = local.into_iter().chain(direct).collect::<Vec<_>>();
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

pub(super) fn interface_addresses(candidates: &[EndpointCandidate], kind: CandidateKind) -> Vec<SocketAddr> {
    candidates
        .iter()
        .filter(|candidate| candidate.kind() == kind)
        .map(EndpointCandidate::address)
        .collect()
}

fn bound_interface_candidates(local: &mut Vec<EndpointCandidate>, direct: &mut Vec<EndpointCandidate>, limit: usize) {
    local.sort_unstable();
    local.dedup();
    direct.sort_unstable();
    direct.dedup();
    if local.len().saturating_add(direct.len()) <= limit {
        return;
    }
    if local.is_empty() {
        direct.truncate(limit);
        return;
    }
    if direct.is_empty() {
        local.truncate(limit);
        return;
    }
    let direct_reserve = direct.len().min(limit / 2);
    local.truncate(limit.saturating_sub(direct_reserve));
    direct.truncate(limit.saturating_sub(local.len()));
}

#[cfg(test)]
mod tests {
    use super::{MAX_ROUTER_MAPPING_UPDATES_PER_WINDOW, ROUTER_MAPPING_UPDATE_WINDOW, RouterMappingUpdateBudget};
    use crate::router_mapping::RouterMappingStatus;

    #[test]
    fn unchanged_mapping_renews_before_its_claim_expires() {
        let now = tokio::time::Instant::now();
        let mut budget = RouterMappingUpdateBudget::new(now);
        let mapped =
            RouterMappingStatus::Mapped(std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(8, 8, 8, 8), 4433));
        assert_eq!(budget.observe(mapped, now), Some(mapped));
        assert_eq!(budget.observe(mapped, now), None);
        assert_eq!(budget.observe(mapped, now + ROUTER_MAPPING_UPDATE_WINDOW), Some(mapped));
        assert_eq!(
            budget.observe(mapped, now + ROUTER_MAPPING_UPDATE_WINDOW * 2),
            Some(mapped)
        );
    }

    #[test]
    fn rate_limit_coalesces_latest_mapping_and_never_delays_withdrawal() {
        let now = tokio::time::Instant::now();
        let mut budget = RouterMappingUpdateBudget::new(now);
        let mapping =
            |port| RouterMappingStatus::Mapped(std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(8, 8, 8, 8), port));
        for port in 1..=4 {
            assert_eq!(budget.observe(mapping(port), now), Some(mapping(port)));
        }
        assert_eq!(budget.observe(mapping(5), now), None);
        assert_eq!(
            budget.observe(mapping(6), now + ROUTER_MAPPING_UPDATE_WINDOW),
            Some(mapping(6))
        );
        assert_eq!(
            budget.observe(RouterMappingStatus::Unavailable, now),
            Some(RouterMappingStatus::Unavailable)
        );
    }

    #[test]
    fn gateway_mapping_signature_churn_has_a_fixed_rate() {
        let now = tokio::time::Instant::now();
        let mut budget = RouterMappingUpdateBudget::new(now);
        for _ in 0..MAX_ROUTER_MAPPING_UPDATES_PER_WINDOW {
            assert!(budget.allow(now));
        }
        assert!(!budget.allow(now));
        assert!(budget.allow(now + ROUTER_MAPPING_UPDATE_WINDOW));
    }
}
