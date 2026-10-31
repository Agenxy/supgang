//! A bounded record of connections made and ended, so an outage reported
//! after the fact has a timeline. It keeps the kind of path and the reason a
//! connection ended, never an address, and only the most recent events.

use std::collections::{BTreeMap, VecDeque};

use quinn::ConnectionError;

use super::active::ActiveConnection;
use crate::{control::ConnectionEvent, ids::NodeId};

/// Events kept; older ones are dropped first.
pub(super) const MAX_EVENTS: usize = 32;
/// Longest peer-supplied close reason kept, in bytes.
const MAX_REASON_BYTES: usize = 48;

#[derive(Default)]
pub(super) struct ConnectionHistory {
    seen: BTreeMap<NodeId, ActiveConnection>,
    events: VecDeque<ConnectionEvent>,
}

impl ConnectionHistory {
    /// Records the difference between the connections seen last time and now.
    pub(super) fn observe(&mut self, active: &BTreeMap<NodeId, ActiveConnection>, now: u64) {
        let ended = self
            .seen
            .iter()
            .filter(|(peer, seen)| {
                active
                    .get(peer)
                    .is_none_or(|current| current.stable_id() != seen.stable_id())
            })
            .map(|(peer, seen)| (*peer, seen.clone()))
            .collect::<Vec<_>>();
        for (peer, connection) in ended {
            self.seen.remove(&peer);
            self.push(event(now, peer, "ended", &connection, ended_reason(&connection)));
        }
        for (peer, connection) in active {
            if self.seen.contains_key(peer) {
                continue;
            }
            self.seen.insert(*peer, connection.clone());
            self.push(event(now, *peer, "connected", connection, String::new()));
        }
    }

    pub(super) fn events(&self) -> Vec<ConnectionEvent> {
        self.events.iter().cloned().collect()
    }

    fn push(&mut self, event: ConnectionEvent) {
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }
}

fn event(now: u64, peer: NodeId, kind: &str, connection: &ActiveConnection, reason: String) -> ConnectionEvent {
    ConnectionEvent {
        at: now,
        peer: peer.to_string().chars().take(8).collect(),
        event: kind.to_owned(),
        path: path_kind(connection).to_owned(),
        reason,
    }
}

fn path_kind(connection: &ActiveConnection) -> &'static str {
    let ip = connection.remote_address().ip().to_canonical();
    let private = match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        std::net::IpAddr::V6(v6) => v6.is_unique_local() || v6.is_unicast_link_local() || v6.is_loopback(),
    };
    match (private, ip.is_ipv4()) {
        (true, true) => "private-ipv4",
        (true, false) => "private-ipv6",
        (false, true) => "internet-ipv4",
        (false, false) => "internet-ipv6",
    }
}

fn ended_reason(connection: &ActiveConnection) -> String {
    if let Some(reason) = connection.retired_reason() {
        return printable(reason);
    }
    match connection.close_reason() {
        None => "replaced".to_owned(),
        Some(ConnectionError::TimedOut) => "idle timeout".to_owned(),
        Some(ConnectionError::ApplicationClosed(close)) => {
            let reason = printable(&close.reason);
            if reason.is_empty() {
                "closed by peer".to_owned()
            } else {
                format!("closed by peer: {reason}")
            }
        }
        Some(ConnectionError::ConnectionClosed(_)) => "closed by peer transport".to_owned(),
        Some(ConnectionError::Reset) => "reset by peer".to_owned(),
        Some(ConnectionError::LocallyClosed) => "closed here".to_owned(),
        Some(ConnectionError::VersionMismatch | ConnectionError::TransportError(_)) => "transport error".to_owned(),
        Some(ConnectionError::CidsExhausted) => "connection identifiers exhausted".to_owned(),
    }
}

/// Keeps a reason only as bounded printable ASCII; a peer chose these bytes.
fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(MAX_REASON_BYTES)
        .filter(|byte| byte.is_ascii_graphic() || **byte == b' ')
        .map(|byte| char::from(*byte))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::printable;

    #[test]
    fn peer_supplied_reasons_are_bounded_printable_ascii() {
        assert_eq!(printable(b"service handoff"), "service handoff");
        assert_eq!(printable(b"a\x1b[2Jb\n\xff"), "a[2Jb");
        assert_eq!(printable(&[b'x'; 200]).len(), super::MAX_REASON_BYTES);
    }
}
