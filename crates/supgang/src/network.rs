//! Side-effect-free local interface discovery for macOS and Linux.

use std::{collections::BTreeSet, net::IpAddr};

use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags, sys::socket::SockaddrStorage};
use thiserror::Error;

use crate::candidate::{CandidateKind, EndpointCandidate};

pub(crate) const MAX_DIAL_CANDIDATES_PER_ROUND: usize = 4;

/// One local interface address and its operating-system netmask.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceNetwork {
    address: IpAddr,
    netmask: IpAddr,
}

impl InterfaceNetwork {
    pub(crate) const fn new(address: IpAddr, netmask: IpAddr) -> Self {
        Self { address, netmask }
    }

    /// Returns this interface address.
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    /// Returns whether `remote` is in the same directly attached IP prefix.
    #[must_use]
    pub const fn contains(self, remote: IpAddr) -> bool {
        match (self.address, self.netmask, remote) {
            (IpAddr::V4(local), IpAddr::V4(mask), IpAddr::V4(peer)) => {
                u32::from_be_bytes(local.octets()) & u32::from_be_bytes(mask.octets())
                    == u32::from_be_bytes(peer.octets()) & u32::from_be_bytes(mask.octets())
            }
            (IpAddr::V6(local), IpAddr::V6(mask), IpAddr::V6(peer)) => {
                u128::from_be_bytes(local.octets()) & u128::from_be_bytes(mask.octets())
                    == u128::from_be_bytes(peer.octets()) & u128::from_be_bytes(mask.octets())
            }
            _ => false,
        }
    }
}

/// A local interface enumeration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NetworkError {
    /// The operating system did not return its interface table.
    #[error("local network interface enumeration failed")]
    Enumeration,
}

/// Returns active physical-network IP interfaces and their matching netmasks.
///
/// Automatic discovery excludes known tunnel, container, peer-to-peer, and
/// virtual bridge interfaces. Their addresses commonly look globally routed
/// while accepting traffic only inside another product's overlay. A user who
/// deliberately wants such an address can select it through `--endpoints`.
///
/// # Errors
///
/// Returns an error when the operating system cannot enumerate interfaces.
pub fn interface_networks() -> Result<Vec<InterfaceNetwork>, NetworkError> {
    let mut networks = BTreeSet::new();
    for interface in getifaddrs().map_err(|_| NetworkError::Enumeration)? {
        if !interface.flags.contains(InterfaceFlags::IFF_UP) || interface.flags.contains(InterfaceFlags::IFF_LOOPBACK) {
            continue;
        }
        if !is_automatic_interface(&interface.interface_name) {
            continue;
        }
        let Some(address) = interface.address.as_ref().and_then(ip_from_storage) else {
            continue;
        };
        let Some(netmask) = interface.netmask.as_ref().and_then(ip_from_storage) else {
            continue;
        };
        if address.is_unspecified() || address.is_multicast() || !same_family(address, netmask) {
            continue;
        }
        networks.insert((address, netmask));
    }
    Ok(networks
        .into_iter()
        .map(|(address, netmask)| InterfaceNetwork::new(address, netmask))
        .collect())
}

fn is_automatic_interface(name: &str) -> bool {
    const VIRTUAL_PREFIXES: &[&str] = &[
        "anpi",
        "awdl",
        "br-",
        "bridge",
        "cni",
        "docker",
        "dummy",
        "flannel",
        "gif",
        "ifb",
        "ipsec",
        "kube",
        "llw",
        "nan",
        "p2p",
        "podman",
        "stf",
        "tailscale",
        "tap",
        "tun",
        "utun",
        "veth",
        "virbr",
        "wg",
        "zt",
    ];
    !VIRTUAL_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

/// Returns whether an address shares a directly attached prefix with this host.
///
/// Enumeration failure deliberately returns false so callers fall back to a
/// public candidate instead of presenting a LAN address as preferred.
#[must_use]
pub fn is_on_link(remote: IpAddr) -> bool {
    interface_networks().is_ok_and(|networks| networks.into_iter().any(|network| network.contains(remote)))
}

pub(crate) fn candidate_dial_order(
    candidates: &[EndpointCandidate],
    local_networks: &[InterfaceNetwork],
) -> Vec<usize> {
    let preferred_local = candidates.iter().position(|candidate| {
        candidate.kind() == CandidateKind::Local
            && local_networks
                .iter()
                .any(|network| network.contains(candidate.address().ip()))
    });
    let mut indices = (0..candidates.len()).collect::<Vec<_>>();
    indices.sort_unstable_by_key(|index| {
        let rank = candidates.get(*index).map_or(6, |candidate| {
            if Some(*index) == preferred_local {
                0
            } else {
                match candidate.kind() {
                    CandidateKind::OwnedRelay => 1,
                    CandidateKind::Mapped => 2,
                    CandidateKind::Reflexive => 3,
                    CandidateKind::Direct => 4,
                    CandidateKind::Local => 5,
                }
            }
        });
        let route_incompatible = candidates
            .get(*index)
            .is_none_or(|candidate| !candidate_is_route_compatible(candidate, local_networks));
        (route_incompatible, rank, *index)
    });
    indices
}

/// Returns whether this host currently has a physical-network route family
/// suitable for trying `candidate`.
///
/// This is deliberately weaker than reachability: a compatible public route
/// can still be blocked by NAT or a firewall. It prevents an off-link LAN
/// address or an IPv6-only address on an IPv4-only network from being presented
/// and retried as though the operating system could route it.
#[must_use]
pub(crate) fn candidate_is_route_compatible(
    candidate: &EndpointCandidate,
    local_networks: &[InterfaceNetwork],
) -> bool {
    let remote = candidate.address().ip();
    if candidate.kind() == CandidateKind::Local {
        return local_networks.iter().any(|network| network.contains(remote));
    }
    local_networks.iter().any(|network| match (network.address(), remote) {
        (IpAddr::V4(local), IpAddr::V4(_)) => !local.is_unspecified() && !local.is_loopback() && !local.is_link_local(),
        (IpAddr::V6(local), IpAddr::V6(_)) => globally_routed_ipv6(local),
        _ => false,
    })
}

const fn globally_routed_ipv6(address: std::net::Ipv6Addr) -> bool {
    address.octets()[0] & 0xe0 == 0x20
}

fn ip_from_storage(storage: &SockaddrStorage) -> Option<IpAddr> {
    storage
        .as_sockaddr_in()
        .map(|address| IpAddr::V4(address.ip()))
        .or_else(|| storage.as_sockaddr_in6().map(|address| IpAddr::V6(address.ip())))
}

const fn same_family(first: IpAddr, second: IpAddr) -> bool {
    matches!(
        (first, second),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{
        InterfaceNetwork, MAX_DIAL_CANDIDATES_PER_ROUND, candidate_dial_order, candidate_is_route_compatible,
        is_automatic_interface,
    };
    use crate::candidate::{CandidateKind, CandidateTransport, EndpointCandidate};

    #[test]
    fn prefix_matching_is_family_safe() {
        let v4 = InterfaceNetwork::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
        );
        assert!(v4.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 191))));
        assert!(!v4.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 191))));
        assert!(!v4.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn automatic_discovery_excludes_overlay_and_virtual_interfaces() {
        for physical in ["en0", "en1", "eth0", "wlan0", "wlp2s0", "wwan0", "bond0"] {
            assert!(is_automatic_interface(physical), "{physical}");
        }
        for virtual_name in [
            "awdl0",
            "bridge100",
            "docker0",
            "ipsec0",
            "tailscale0",
            "utun4",
            "veth1234",
            "wg0",
        ] {
            assert!(!is_automatic_interface(virtual_name), "{virtual_name}");
        }
    }

    #[test]
    fn dial_order_keeps_public_candidates_inside_the_attempt_bound() -> Result<(), Box<dyn std::error::Error>> {
        let local_networks = [InterfaceNetwork::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
        )];
        let mut candidates = Vec::new();
        for final_octet in 1..=5 {
            candidates.push(EndpointCandidate::new(
                CandidateKind::Local,
                CandidateTransport::QuicV1,
                SocketAddr::from(([192, 168, 1, final_octet], 4_433)),
            )?);
        }
        candidates.push(EndpointCandidate::new(
            CandidateKind::Direct,
            CandidateTransport::QuicV1,
            SocketAddr::from(([8, 8, 8, 8], 4_433)),
        )?);

        let order = candidate_dial_order(&candidates, &local_networks);
        assert_eq!(order.first().copied(), Some(0));
        assert_eq!(order.get(1).copied(), Some(5));
        assert!(
            order
                .iter()
                .take(MAX_DIAL_CANDIDATES_PER_ROUND)
                .any(|index| *index == 5)
        );
        Ok(())
    }

    #[test]
    fn mapped_candidate_outranks_incidental_direct_interfaces() -> Result<(), Box<dyn std::error::Error>> {
        let mut candidates = (1_u8..=4)
            .map(|host| {
                EndpointCandidate::new(
                    CandidateKind::Direct,
                    CandidateTransport::QuicV1,
                    SocketAddr::from(([8, 8, 8, host], 4_433)),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        candidates.push(EndpointCandidate::new(
            CandidateKind::Mapped,
            CandidateTransport::QuicV1,
            SocketAddr::from(([9, 9, 9, 9], 4_433)),
        )?);

        let order = candidate_dial_order(&candidates, &[]);
        assert_eq!(order.first().copied(), Some(4));
        assert!(
            order
                .iter()
                .take(MAX_DIAL_CANDIDATES_PER_ROUND)
                .any(|index| *index == 4)
        );
        Ok(())
    }

    #[test]
    fn route_compatibility_rejects_off_link_lan_and_missing_address_families() -> Result<(), Box<dyn std::error::Error>>
    {
        let ipv4_only = [InterfaceNetwork::new(
            IpAddr::V4(Ipv4Addr::new(172, 16, 110, 141)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 0, 0)),
        )];
        let off_link = EndpointCandidate::new(
            CandidateKind::Local,
            CandidateTransport::QuicV1,
            SocketAddr::from(([192, 168, 1, 191], 44_330)),
        )?;
        let public_ipv4 = EndpointCandidate::new(
            CandidateKind::Mapped,
            CandidateTransport::QuicV1,
            SocketAddr::from(([8, 8, 8, 8], 44_330)),
        )?;
        let public_ipv6 = EndpointCandidate::new(
            CandidateKind::Direct,
            CandidateTransport::QuicV1,
            SocketAddr::from((Ipv6Addr::new(0x2600, 0x1700, 0, 0, 0, 0, 0, 1), 44_330)),
        )?;

        assert!(!candidate_is_route_compatible(&off_link, &ipv4_only));
        assert!(candidate_is_route_compatible(&public_ipv4, &ipv4_only));
        assert!(!candidate_is_route_compatible(&public_ipv6, &ipv4_only));
        assert_eq!(candidate_dial_order(&[public_ipv6, public_ipv4], &ipv4_only), [1, 0]);
        Ok(())
    }
}
