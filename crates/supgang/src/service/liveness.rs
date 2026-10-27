//! Whether an established connection still reaches its peer.
//!
//! When a peer authenticates a new connection over a different path while an
//! older one is registered, the older one may have gone silent or become far
//! slower. Admission would otherwise refuse the new connection as a duplicate.
//! A one-byte
//! datagram elicits a transport acknowledgement from any live peer without
//! involving its application (Supgang ignores datagrams that are not
//! rendezvous frames, as every earlier release did), so the absence of any
//! received datagram within a short, RTT-scaled window is evidence that the
//! old path is gone. A peer that cannot be probed is treated as live, which
//! keeps the earlier admission behaviour.

use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

use quinn::Connection;

use crate::ids::NodeId;

/// The probe datagram: not a valid rendezvous frame, so receivers ignore it.
const PROBE: u8 = 0;
/// Probes sent before a silent connection is judged gone; one may be lost.
const ATTEMPTS: u32 = 2;
const MIN_WINDOW: Duration = Duration::from_millis(500);
const MAX_WINDOW: Duration = Duration::from_millis(2_500);
const POLL: Duration = Duration::from_millis(20);

/// Why a registered connection may yield to an authenticated candidate.
/// A usable old path needs the peer's application-level replacement proof.
#[derive(Clone, Copy)]
pub(super) struct Superseded {
    pub(super) id: usize,
    pub(super) old_live: bool,
}

/// Returns whether `connection` still exchanges packets with its peer.
pub async fn is_live(connection: &Connection) -> bool {
    let before = connection.stats().udp_rx.datagrams;
    let window = connection.rtt().saturating_mul(4).clamp(MIN_WINDOW, MAX_WINDOW);
    for _ in 0..ATTEMPTS {
        if connection.close_reason().is_some() {
            return false;
        }
        if connection.send_datagram(vec![PROBE].into()).is_err() {
            return connection.close_reason().is_none();
        }
        let deadline = tokio::time::Instant::now() + window;
        while tokio::time::Instant::now() < deadline {
            if connection.stats().udp_rx.datagrams > before {
                return true;
            }
            if connection.close_reason().is_some() {
                return false;
            }
            tokio::time::sleep(POLL).await;
        }
    }
    false
}

/// The registered connection a newly authenticated one supersedes, if the
/// peer has one over a different path that went silent or is much slower.
pub(super) async fn superseded(
    registered: &BTreeMap<NodeId, Connection>,
    peer: NodeId,
    offered: &Connection,
) -> Option<Superseded> {
    let existing = registered.get(&peer)?;
    let canonical = |address: SocketAddr| crate::candidate::canonical_socket_address(address);
    if canonical(existing.remote_address()) == canonical(offered.remote_address()) {
        // A simultaneous dial on the same path keeps the live registered
        // connection. A closed connection may be replaced even when its
        // successor has the same remote address (for example after a local
        // endpoint refresh).
        return (!is_live(existing).await).then(|| Superseded {
            id: existing.stable_id(),
            // A missing probe reply is not proof that a still-open remote
            // session accepted this candidate. Require the Sync proof.
            old_live: existing.close_reason().is_none(),
        });
    }
    // A directly attached path supersedes one that is not, even while the
    // indirect one works. Both computers see the shared LAN as attached, so
    // they agree on which connection survives.
    let networks = crate::network::interface_networks().unwrap_or_default();
    let on_link = |address: SocketAddr| {
        let ip = address.ip().to_canonical();
        networks.iter().any(|network| network.contains(ip))
    };
    if on_link(offered.remote_address()) && !on_link(existing.remote_address()) {
        return Some(Superseded {
            id: existing.stable_id(),
            old_live: true,
        });
    }
    // A newly authenticated path that is substantially faster may replace a
    // still-live one. A small RTT fluctuation cannot move the connection.
    #[cfg(test)]
    let suppress_rtt_replacement = super::test_controls::suppress_rtt_replacement();
    #[cfg(not(test))]
    let suppress_rtt_replacement = false;
    if !suppress_rtt_replacement && super::path_quality::materially_better(existing.rtt(), offered.rtt()) {
        return Some(Superseded {
            id: existing.stable_id(),
            old_live: true,
        });
    }
    (!is_live(existing).await).then(|| Superseded {
        id: existing.stable_id(),
        old_live: existing.close_reason().is_none(),
    })
}
