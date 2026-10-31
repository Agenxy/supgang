//! Destination route regression cases independent of the test host's routes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{InterfaceNetwork, candidate_has_route};
use crate::candidate::{CandidateKind, CandidateTransport, EndpointCandidate};

#[test]
fn a_ula_family_without_a_route_does_not_authorize_global_ipv6() -> Result<(), Box<dyn std::error::Error>> {
    let local = InterfaceNetwork::new("fd00::1".parse()?, "ffff:ffff:ffff:ffff::".parse()?);
    let remote = EndpointCandidate::new(
        CandidateKind::Direct,
        CandidateTransport::QuicV1,
        SocketAddr::from(("2600:1700::c".parse::<Ipv6Addr>()?, 44_330)),
    )?;
    assert!(!candidate_has_route(&remote, &[local], |_| false));
    assert!(candidate_has_route(&remote, &[local], |_| true));
    Ok(())
}

#[test]
fn destination_lookup_retains_explicit_on_link_and_default_routes() -> Result<(), Box<dyn std::error::Error>> {
    let local = InterfaceNetwork::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
    );
    for remote in [[192, 168, 1, 191], [10, 20, 30, 40], [9, 9, 9, 9]] {
        let candidate = EndpointCandidate::new(
            CandidateKind::Local,
            CandidateTransport::QuicV1,
            SocketAddr::from((remote, 44_330)),
        )
        .or_else(|_| {
            EndpointCandidate::new(
                CandidateKind::Direct,
                CandidateTransport::QuicV1,
                SocketAddr::from((remote, 44_330)),
            )
        })?;
        assert!(candidate_has_route(&candidate, &[local], |destination| destination == candidate.address()));
        assert!(!candidate_has_route(&candidate, &[local], |_| false));
    }
    Ok(())
}

#[test]
fn missing_family_stays_ineligible_and_route_loss_is_not_cached() -> Result<(), Box<dyn std::error::Error>> {
    let local = InterfaceNetwork::new("fd00::1".parse()?, "ffff:ffff:ffff:ffff::".parse()?);
    let remote = EndpointCandidate::new(
        CandidateKind::Direct,
        CandidateTransport::QuicV1,
        SocketAddr::from(([9, 9, 9, 9], 44_330)),
    )?;
    assert!(!candidate_has_route(&remote, &[local], |_| true));
    let ipv4 = InterfaceNetwork::new("10.0.0.1".parse()?, "255.255.255.0".parse()?);
    assert!(candidate_has_route(&remote, &[ipv4], |_| true));
    assert!(!candidate_has_route(&remote, &[ipv4], |_| false));
    Ok(())
}
