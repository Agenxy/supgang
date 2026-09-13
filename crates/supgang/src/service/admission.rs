//! Fixed-memory source admission for authenticated-session handshakes.

use std::{collections::BTreeMap, net::IpAddr, time::Duration};

const MAX_SESSIONS_PER_SOURCE_WINDOW: u8 = 1;
const MAX_TRACKED_SOURCES: usize = 64;
const SOURCE_WINDOW: Duration = Duration::from_secs(30);

const _: () = assert!(SOURCE_WINDOW.as_secs() > super::CONNECT_TIMEOUT_SECONDS + super::SESSION_TIMEOUT_SECONDS);

#[derive(Clone, Copy)]
struct SourceWindow {
    started: tokio::time::Instant,
    admitted: u8,
}

/// Limits work started after QUIC address validation but before peer authentication.
///
/// The outer inbound task pool remains the hard global ceiling. This second,
/// fixed-memory bound prevents one validated address from occupying that pool.
pub(super) struct InboundAdmission {
    sources: BTreeMap<IpAddr, SourceWindow>,
}

impl InboundAdmission {
    pub(super) const fn new() -> Self {
        Self {
            sources: BTreeMap::new(),
        }
    }

    pub(super) fn allow(&mut self, address: std::net::SocketAddr, now: tokio::time::Instant) -> bool {
        self.sources
            .retain(|_, window| now.saturating_duration_since(window.started) < SOURCE_WINDOW);
        let source = canonical_source(address.ip());
        if let Some(window) = self.sources.get_mut(&source) {
            if window.admitted >= MAX_SESSIONS_PER_SOURCE_WINDOW {
                return false;
            }
            window.admitted = window.admitted.saturating_add(1);
            return true;
        }
        if self.sources.len() >= MAX_TRACKED_SOURCES {
            let Some(oldest) = self
                .sources
                .iter()
                .min_by_key(|(_, window)| window.started)
                .map(|(source, _)| *source)
            else {
                return false;
            };
            self.sources.remove(&oldest);
        }
        self.sources.insert(
            source,
            SourceWindow {
                started: now,
                admitted: 1,
            },
        );
        true
    }
}

pub(super) fn schedule_admitted_incoming(
    incoming: quinn::Incoming,
    admission: &mut InboundAdmission,
    device: &std::sync::Arc<crate::identity::DeviceIdentity>,
    tasks: &mut tokio::task::JoinSet<super::SessionTaskResult>,
    priority_tasks: &mut tokio::task::JoinSet<super::SessionTaskResult>,
    live: &super::LiveSessionState<'_>,
) {
    if !incoming.remote_address_validated() {
        let _retry_result = incoming.retry();
        return;
    }
    let remote = incoming.remote_address();
    let priority = remembered_source(live.directory, remote.ip(), super::unix_time().unwrap_or(0));
    let use_priority = priority && priority_tasks.len() < super::MAX_PENDING_PRIORITY_INBOUND_SESSIONS;
    if (!use_priority && tasks.len() >= super::MAX_PENDING_INBOUND_SESSIONS)
        || !admission.allow(remote, tokio::time::Instant::now())
    {
        incoming.refuse();
        return;
    }
    let selected = if use_priority { priority_tasks } else { tasks };
    super::live_session::schedule_incoming_peer(incoming, device, selected, live);
}

fn remembered_source(directory: &crate::peer_directory::PeerDirectory, remote: IpAddr, now: u64) -> bool {
    let remote = canonical_source(remote);
    directory
        .dial_hints(now)
        .iter()
        .flat_map(crate::peer_directory::PeerDialHint::addresses)
        .any(|address| canonical_source(address.ip()) == remote)
}

fn canonical_source(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address.to_ipv4_mapped().map_or_else(
            || IpAddr::V6(std::net::Ipv6Addr::from(u128::from(address) & (u128::MAX << 64))),
            IpAddr::V4,
        ),
        IpAddr::V4(address) => IpAddr::V4(address),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::Duration;

    use super::{InboundAdmission, MAX_SESSIONS_PER_SOURCE_WINDOW, MAX_TRACKED_SOURCES, SOURCE_WINDOW};

    #[test]
    fn one_validated_source_cannot_occupy_the_inbound_pool() {
        let now = tokio::time::Instant::now();
        let source = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), 40_000));
        let mut admission = InboundAdmission::new();
        for offset in 0..MAX_SESSIONS_PER_SOURCE_WINDOW {
            assert!(admission.allow(SocketAddr::new(source.ip(), source.port() + u16::from(offset)), now));
        }
        assert!(!admission.allow(source, now));
        assert!(admission.allow(source, now + SOURCE_WINDOW));
    }

    #[test]
    fn ipv4_aliases_and_native_ipv6_prefixes_share_their_respective_budgets() {
        let now = tokio::time::Instant::now();
        let mut admission = InboundAdmission::new();
        let v4 = Ipv4Addr::new(192, 0, 2, 9);
        assert!(admission.allow(SocketAddr::from((v4, 40_000)), now));
        let mapped = v4.to_ipv6_mapped();
        assert!(!admission.allow(SocketAddr::from((mapped, 40_001)), now));
        assert!(!admission.allow(SocketAddr::from((v4, 50_000)), now));

        let mut ipv6_admission = InboundAdmission::new();
        let first = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1);
        let second = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 2);
        for offset in 0..MAX_SESSIONS_PER_SOURCE_WINDOW {
            let address = if offset % 2 == 0 { first } else { second };
            assert!(ipv6_admission.allow(SocketAddr::from((address, 40_000 + u16::from(offset))), now));
        }
        assert!(!ipv6_admission.allow(SocketAddr::from((second, 50_000)), now));
    }

    #[test]
    fn a_full_source_table_evicts_the_oldest_window_without_growing() {
        let now = tokio::time::Instant::now();
        let mut saturated = InboundAdmission::new();
        let mut admitted_at = now;
        for suffix in (1_u128..).take(MAX_TRACKED_SOURCES) {
            let address = Ipv6Addr::from(suffix << 64);
            assert!(saturated.allow(SocketAddr::from((address, 40_000)), admitted_at));
            admitted_at += Duration::from_nanos(1);
        }
        assert!(saturated.allow(SocketAddr::from((Ipv6Addr::from(65_u128 << 64), 40_000)), admitted_at));
        assert_eq!(saturated.sources.len(), MAX_TRACKED_SOURCES);
        assert!(
            !saturated
                .sources
                .contains_key(&std::net::IpAddr::V6(Ipv6Addr::from(1_u128 << 64)))
        );
    }
}
