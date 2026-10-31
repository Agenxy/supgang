//! Address provenance and preference rendering for peer rows.

use crate::{
    candidate::{CandidateKind, EndpointCandidate},
    cli_peer_types::ResolvedCandidate,
    ids::NodeId,
    network::InterfaceNetwork,
    peer_directory::PeerDirectory,
    reachability::ReachabilitySource,
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
                address: candidate.address().to_string(),
                provenance: provenance.to_owned(),
                reporter: Some(claim.reporter.to_string()),
                report_expires_at: Some(claim.expires_at),
                route_compatible: crate::network::candidate_is_route_compatible(&candidate, local_networks),
                preferred: false,
            })
        })
        .collect::<Vec<_>>();
    let signed_local = candidates.iter().any(|candidate| {
        candidate.kind() == CandidateKind::Local
            && local_networks
                .iter()
                .any(|network| network.contains(candidate.address().ip()))
    });
    // A public observation is provenance, not a reason to bypass a usable LAN
    // address. Prefer an on-link report or signed local address before WAN hints.
    let preferred_report = choose_preferred
        .then(|| {
            addresses
                .iter()
                .position(|candidate| {
                    candidate.scope == "local"
                        && candidate
                            .address
                            .parse::<std::net::SocketAddr>()
                            .is_ok_and(|address| local_networks.iter().any(|network| network.contains(address.ip())))
                })
                .or_else(|| {
                    addresses
                        .iter()
                        .position(|candidate| !signed_local && candidate.route_compatible)
                })
        })
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::resolved_peer_candidates;
    use crate::{
        candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
        identity::DeviceIdentity,
        membership::MembershipRoles,
        network::InterfaceNetwork,
        peer_directory::PeerDirectory,
        reachability::{ReachabilityClaim, ReachabilitySource},
        state,
    };

    #[test]
    fn local_preference_survives_public_reports_and_changes_after_roaming() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("state");
        let mut founder = state::initialize(&path)?;
        let reporter = DeviceIdentity::generate()?;
        let subject = DeviceIdentity::generate()?.node_id();
        let membership =
            founder.issue_membership(&reporter.verifying_key(), MembershipRoles::DEVICE, [19; 32], 10, 1_000)?;
        let mut directory = PeerDirectory::open(
            &path,
            founder.identity().root_verifying_key,
            founder.identity().device.node_id(),
            founder.revocations(),
        )?;
        let public = SocketAddr::from(([9, 9, 9, 9], 44_330));
        let local = SocketAddr::from(([192, 168, 1, 191], 44_330));
        let claim = ReachabilityClaim::sign(
            membership.clone(),
            &reporter,
            subject,
            "[::ffff:9.9.9.9]:44330".parse()?,
            ReachabilitySource::PeerObserved,
            40,
        )?;
        assert!(directory.import_reachability(claim, 50)?);
        let candidates = [EndpointCandidate::new(
            CandidateKind::Local,
            CandidateTransport::QuicV1,
            local,
        )?];
        let home = [InterfaceNetwork::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
        )];
        let away = [InterfaceNetwork::new(
            IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
        )];
        let preferred = |networks: &[InterfaceNetwork]| {
            resolved_peer_candidates(&directory, subject, &candidates, networks, 50, true)
                .into_iter()
                .filter(|address| address.preferred)
                .map(|address| address.address)
                .collect::<Vec<_>>()
        };
        assert_eq!(preferred(&home), vec![local.to_string()]);
        assert_eq!(preferred(&away), vec![public.to_string()]);
        assert!(
            resolved_peer_candidates(&directory, subject, &candidates, &home, 50, false)
                .iter()
                .all(|address| !address.preferred)
        );
        let local_claim = ReachabilityClaim::sign(
            membership,
            &reporter,
            subject,
            local,
            ReachabilitySource::PeerObserved,
            41,
        )?;
        assert!(directory.import_reachability(local_claim, 50)?);
        let addresses = resolved_peer_candidates(&directory, subject, &candidates, &home, 50, true);
        assert_eq!(addresses.iter().filter(|address| address.preferred).count(), 1);
        assert!(
            addresses
                .iter()
                .any(|address| address.preferred && address.address == local.to_string())
        );
        assert_eq!(
            addresses
                .iter()
                .filter(|address| address.address == local.to_string())
                .count(),
            1
        );
        Ok(())
    }
}
