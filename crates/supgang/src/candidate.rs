//! Bounded and classified network endpoint candidates.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The maximum number of candidates accepted in one endpoint record.
pub const MAX_CANDIDATES: usize = 16;

/// The provenance and expected reachability scope of a candidate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum CandidateKind {
    /// An address learned from a local interface or authenticated local discovery.
    Local = 0,
    /// A globally routed address owned directly by the node.
    Direct = 1,
    /// A reflexive address reported by an authenticated peer.
    Reflexive = 2,
    /// An address opened through an explicit router mapping.
    Mapped = 3,
    /// A user-owned introducer or constrained relay address.
    OwnedRelay = 4,
}

impl TryFrom<u8> for CandidateKind {
    type Error = CandidateError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Local),
            1 => Ok(Self::Direct),
            2 => Ok(Self::Reflexive),
            3 => Ok(Self::Mapped),
            4 => Ok(Self::OwnedRelay),
            _ => Err(CandidateError::UnknownKind),
        }
    }
}

/// The on-wire transport for a candidate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum CandidateTransport {
    /// QUIC version 1 over UDP.
    QuicV1 = 0,
}

impl TryFrom<u8> for CandidateTransport {
    type Error = CandidateError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::QuicV1),
            _ => Err(CandidateError::UnknownTransport),
        }
    }
}

/// A possible socket at which a node may currently be reached.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EndpointCandidate {
    kind: CandidateKind,
    transport: CandidateTransport,
    address: SocketAddr,
}

impl EndpointCandidate {
    /// Validates and constructs a candidate.
    ///
    /// # Errors
    ///
    /// Rejects unspecified, multicast, broadcast, port-zero, and scope-mismatched addresses.
    pub fn new(
        kind: CandidateKind,
        transport: CandidateTransport,
        address: SocketAddr,
    ) -> Result<Self, CandidateError> {
        validate_address(kind, address)?;
        Ok(Self {
            kind,
            transport,
            address,
        })
    }

    /// Returns the candidate's provenance kind.
    #[must_use]
    pub const fn kind(&self) -> CandidateKind {
        self.kind
    }

    /// Returns the candidate's transport.
    #[must_use]
    pub const fn transport(&self) -> CandidateTransport {
        self.transport
    }

    /// Returns the candidate socket address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }
}

/// A reason an endpoint candidate was rejected.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CandidateError {
    /// The encoded kind is not supported by this protocol version.
    #[error("candidate kind is not supported")]
    UnknownKind,
    /// The encoded transport is not supported by this protocol version.
    #[error("candidate transport is not supported")]
    UnknownTransport,
    /// Port zero cannot be dialed.
    #[error("candidate port must not be zero")]
    ZeroPort,
    /// An unspecified address does not identify an endpoint.
    #[error("candidate address must not be unspecified")]
    Unspecified,
    /// Multicast and IPv4 broadcast addresses are never peer endpoints.
    #[error("candidate address must not be multicast or broadcast")]
    MulticastOrBroadcast,
    /// Loopback and link-local addresses are restricted to local candidates.
    #[error("loopback and link-local addresses require local candidate provenance")]
    LocalScopeMismatch,
    /// Non-local candidates must be globally routable unicast addresses.
    #[error("non-local candidate address must be globally routable")]
    NonGlobalScope,
}

fn validate_address(kind: CandidateKind, address: SocketAddr) -> Result<(), CandidateError> {
    if address.port() == 0 {
        return Err(CandidateError::ZeroPort);
    }

    let ip = address.ip();
    if ip.is_unspecified() {
        return Err(CandidateError::Unspecified);
    }
    if is_multicast_or_broadcast(ip) {
        return Err(CandidateError::MulticastOrBroadcast);
    }
    if is_local_scope(ip) && kind != CandidateKind::Local {
        return Err(CandidateError::LocalScopeMismatch);
    }
    if kind != CandidateKind::Local && !is_globally_routable(ip) {
        return Err(CandidateError::NonGlobalScope);
    }
    Ok(())
}

const fn is_multicast_or_broadcast(ip: IpAddr) -> bool {
    ip.is_multicast() || matches!(ip, IpAddr::V4(value) if value.is_broadcast())
}

const fn is_local_scope(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => value.is_loopback() || value.is_link_local(),
        IpAddr::V6(value) => value.is_loopback() || value.is_unicast_link_local(),
    }
}

const fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => {
            let [first, second, third, _] = value.octets();
            let shared = first == 100 && second >= 64 && second <= 127;
            let protocol_assignment = first == 192 && second == 0 && third == 0;
            let deprecated_relay = first == 192 && second == 88 && third == 99;
            let benchmarking = first == 198 && (second == 18 || second == 19);
            first != 0
                && first < 224
                && !value.is_private()
                && !value.is_loopback()
                && !value.is_link_local()
                && !value.is_documentation()
                && !shared
                && !protocol_assignment
                && !deprecated_relay
                && !benchmarking
        }
        IpAddr::V6(value) => {
            let [first, second, third, fourth, ..] = value.octets();
            let global_unicast = first & 0xe0 == 0x20;
            let documentation = first == 0x20 && second == 0x01 && third == 0x0d && fourth == 0xb8;
            global_unicast && !documentation
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::{CandidateError, CandidateKind, CandidateTransport, EndpointCandidate};

    #[test]
    fn rejects_unsafe_or_misclassified_addresses() {
        let transport = CandidateTransport::QuicV1;
        assert_eq!(
            EndpointCandidate::new(CandidateKind::Direct, transport, SocketAddr::from(([0, 0, 0, 0], 1))),
            Err(CandidateError::Unspecified)
        );
        assert_eq!(
            EndpointCandidate::new(CandidateKind::Direct, transport, SocketAddr::from(([127, 0, 0, 1], 1))),
            Err(CandidateError::LocalScopeMismatch)
        );
        assert_eq!(
            EndpointCandidate::new(
                CandidateKind::Local,
                transport,
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
            ),
            Err(CandidateError::ZeroPort)
        );
        assert_eq!(
            EndpointCandidate::new(
                CandidateKind::Direct,
                transport,
                SocketAddr::from(([203, 0, 113, 8], 443))
            ),
            Err(CandidateError::NonGlobalScope)
        );
    }

    #[test]
    fn accepts_local_loopback_and_public_direct_candidates() {
        let transport = CandidateTransport::QuicV1;
        assert!(
            EndpointCandidate::new(CandidateKind::Local, transport, SocketAddr::from(([127, 0, 0, 1], 443))).is_ok()
        );
        assert!(
            EndpointCandidate::new(CandidateKind::Direct, transport, SocketAddr::from(([8, 8, 8, 8], 443))).is_ok()
        );
    }
}
