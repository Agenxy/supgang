//! Bounded, route-compatible candidates from authenticated contact history.

use std::net::SocketAddr;

use crate::{contact::PeerContact, network, peer_directory::PeerDialHint};

use super::super::retry_schedule::candidate_batch;

pub(super) fn recovery_candidates(
    hints: &[PeerDialHint<'_>],
    networks: &[network::InterfaceNetwork],
    cycle: usize,
) -> Vec<(PeerContact, SocketAddr)> {
    let eligible = eligible_hints(hints, networks);
    let mut addresses = eligible
        .iter()
        .flat_map(|(_, addresses)| addresses.iter().copied())
        .collect::<Vec<_>>();
    addresses.sort_by_key(|address| {
        if networks.iter().any(|network| network.contains(address.ip())) {
            0
        } else if crate::candidate::EndpointCandidate::new(
            crate::candidate::CandidateKind::Local,
            crate::candidate::CandidateTransport::QuicV1,
            *address,
        )
        .is_ok()
        {
            2
        } else {
            1
        }
    });
    // Race families across record boundaries, retaining the signed authority
    // associated with each address. History cannot replace the latest preferred
    // path, but neither can IPv6-heavy records starve the only IPv4 alternative.
    candidate_batch(&addresses, cycle)
        .into_iter()
        .filter_map(|address| {
            eligible
                .iter()
                .find(|(_, addresses)| addresses.contains(&address))
                .map(|(hint, _)| (hint.contact().clone(), address))
        })
        .collect()
}

pub(super) fn eligible_hints<'a>(
    hints: &'a [PeerDialHint<'a>],
    networks: &[network::InterfaceNetwork],
) -> Vec<(&'a PeerDialHint<'a>, Vec<SocketAddr>)> {
    // Do not spend retry windows on records with no possible route. In
    // particular, IPv6-only history must not delay older IPv4 recovery hints.
    hints
        .iter()
        .filter_map(|hint| {
            let addresses = hint
                .addresses()
                .iter()
                .copied()
                .filter(|address| network::address_is_route_compatible(*address, networks))
                .collect::<Vec<_>>();
            (!addresses.is_empty()).then_some((hint, addresses))
        })
        .collect()
}
