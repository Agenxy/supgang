//! Address provenance and preference rendering for peer rows.

use crate::{
    candidate::EndpointCandidate, cli_peer_types::ResolvedCandidate, ids::NodeId, network::InterfaceNetwork,
    peer_directory::PeerDirectory, reachability::ReachabilitySource,
};

use super::{candidate_kind_name, candidate_scope};

pub(super) fn resolved_candidates(
    candidates: &[EndpointCandidate],
    local_networks: &[InterfaceNetwork],
    choose_preferred: bool,
) -> Vec<ResolvedCandidate> {
    let preferred_index = choose_preferred
        .then(|| {
            crate::network::candidate_dial_order(candidates, local_networks)
                .into_iter()
                .find(|index| {
                    candidates.get(*index).is_some_and(|candidate| {
                        crate::network::candidate_is_route_compatible(candidate, local_networks)
                    })
                })
        })
        .flatten();
    resolved_with_preference(candidates, preferred_index, "device-signed", local_networks)
}

pub(super) fn resolved_peer_candidates(
    directory: &PeerDirectory,
    node_id: NodeId,
    candidates: &[EndpointCandidate],
    local_networks: &[InterfaceNetwork],
    now: u64,
    choose_preferred: bool,
) -> Vec<ResolvedCandidate> {
    let mut addresses = directory
        .reachability_claims(now)
        .into_iter()
        .filter(|claim| claim.subject == node_id)
        .filter_map(|claim| {
            let candidate = claim.candidate().ok()?;
            let provenance = match claim.source {
                ReachabilitySource::Gateway => "gateway-reported",
                ReachabilitySource::PeerObserved => "peer-reported",
            };
            Some(ResolvedCandidate {
                scope: candidate_scope(candidate.kind()).to_owned(),
                kind: provenance.to_owned(),
                transport: "quic-v1".to_owned(),
                address: claim.address.to_string(),
                provenance: provenance.to_owned(),
                reporter: Some(claim.reporter.to_string()),
                report_expires_at: Some(claim.expires_at),
                route_compatible: crate::network::candidate_is_route_compatible(&candidate, local_networks),
                preferred: false,
            })
        })
        .collect::<Vec<_>>();
    let preferred_report = choose_preferred
        .then(|| addresses.iter().position(|candidate| candidate.route_compatible))
        .flatten();
    if let Some(index) = preferred_report
        && let Some(candidate) = addresses.get_mut(index)
    {
        candidate.preferred = true;
    }
    let mut signed = resolved_candidates(
        candidates,
        local_networks,
        choose_preferred && preferred_report.is_none(),
    );
    signed.retain(|candidate| !addresses.iter().any(|existing| existing.address == candidate.address));
    addresses.extend(signed);
    addresses
}

pub(super) fn resolved_with_preference(
    candidates: &[EndpointCandidate],
    preferred_index: Option<usize>,
    provenance: &str,
    local_networks: &[InterfaceNetwork],
) -> Vec<ResolvedCandidate> {
    candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| ResolvedCandidate {
            scope: candidate_scope(candidate.kind()).to_owned(),
            kind: candidate_kind_name(candidate.kind()).to_owned(),
            transport: "quic-v1".to_owned(),
            address: candidate.address().to_string(),
            provenance: provenance.to_owned(),
            reporter: None,
            report_expires_at: None,
            route_compatible: crate::network::candidate_is_route_compatible(candidate, local_networks),
            preferred: Some(index) == preferred_index,
        })
        .collect()
}
