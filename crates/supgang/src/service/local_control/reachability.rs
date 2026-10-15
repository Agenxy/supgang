//! Distinguish owner claims from gateway and peer reports.

use crate::{
    candidate::CandidateKind, ids::NodeId, peer_directory::PeerDirectory, router_mapping::RouterMappingStatus,
};

pub(super) fn internet_reachability(
    local_contact: &crate::contact::PeerContact,
    router_mapping: RouterMappingStatus,
    directory: &PeerDirectory,
    local_node: NodeId,
    now: u64,
) -> &'static str {
    let peer_reported = directory.reachability_claims(now).iter().any(|claim| {
        claim.subject == local_node && claim.source == crate::reachability::ReachabilitySource::PeerObserved
    });
    internet_reachability_from_candidates(&local_contact.endpoint.record.candidates, router_mapping, peer_reported)
}

pub(super) fn internet_reachability_from_candidates(
    candidates: &[crate::candidate::EndpointCandidate],
    router_mapping: RouterMappingStatus,
    peer_reported: bool,
) -> &'static str {
    if peer_reported {
        return "peer-reported-address";
    }
    if candidates
        .iter()
        .any(|candidate| candidate.kind() == CandidateKind::Reflexive)
    {
        return "device-claimed-address";
    }
    if matches!(router_mapping, RouterMappingStatus::Mapped(_)) {
        return "gateway-reported-address";
    }
    if candidates
        .iter()
        .any(|candidate| candidate.kind() == CandidateKind::Mapped)
    {
        return "owner-mapped-address-unverified";
    }
    if candidates
        .iter()
        .any(|candidate| candidate.kind() == CandidateKind::Direct)
    {
        "direct-address-unverified"
    } else {
        "local-only"
    }
}
