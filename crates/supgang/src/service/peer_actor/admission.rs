//! Deterministic connection admission and preferred direction.

use super::super::ConnectionOrigin;
use crate::ids::NodeId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ConnectionAdmission {
    Accept,
    ReplaceFallback,
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OfferedConnection {
    Preferred,
    Fallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CurrentConnection {
    None,
    Preferred,
    Fallback,
}

pub(super) const fn connection_admission(
    offered: OfferedConnection,
    current: CurrentConnection,
    at_capacity: bool,
) -> ConnectionAdmission {
    match current {
        CurrentConnection::Fallback if matches!(offered, OfferedConnection::Preferred) => {
            ConnectionAdmission::ReplaceFallback
        }
        CurrentConnection::Preferred | CurrentConnection::Fallback => ConnectionAdmission::Reject,
        CurrentConnection::None if at_capacity => ConnectionAdmission::Reject,
        CurrentConnection::None => ConnectionAdmission::Accept,
    }
}

pub(super) fn offered_connection(local: NodeId, peer: NodeId, origin: ConnectionOrigin) -> OfferedConnection {
    // Both ends must rank the same connection identically. A role-local
    // preference for inbound connections makes an anchor replace a connection
    // its peer considers preferred; that peer then rejects the replacement.
    // Anchor capacity is configured separately and cannot affect this ordering.
    let preferred = matches!(origin, ConnectionOrigin::Outbound) == (local < peer);
    if preferred {
        OfferedConnection::Preferred
    } else {
        OfferedConnection::Fallback
    }
}

pub fn preferred_over_pending(
    local: NodeId,
    peer: NodeId,
    pending: ConnectionOrigin,
    offered: ConnectionOrigin,
) -> bool {
    offered_connection(local, peer, pending) == OfferedConnection::Fallback
        && offered_connection(local, peer, offered) == OfferedConnection::Preferred
}
