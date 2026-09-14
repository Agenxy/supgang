use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};

use super::{
    PeerRow, resolve_selector_from_rows, resolved_candidates, selector_matches_from_rows, self_preferred_index,
};
use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
    ids::NodeId,
    network::InterfaceNetwork,
};

fn row(name: &str, byte: u8) -> PeerRow {
    let node_id = NodeId::from_bytes([byte; 32]);
    PeerRow {
        name: name.to_owned(),
        name_source: "device-signed".to_owned(),
        tags: Vec::new(),
        fingerprint: node_id.to_string().chars().take(8).collect(),
        node_id: node_id.to_string(),
        connected: None,
        status: "fresh".to_owned(),
        generation: 0,
        sequence: 1,
        expires_at: 100,
        candidate_count: 0,
        addresses: Vec::new(),
        services: Vec::new(),
    }
}

#[test]
fn names_are_convenient_but_ambiguity_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let first = row("HomeServer", 1);
    let second = row("HomeServer", 2);
    assert_eq!(
        resolve_selector_from_rows(std::slice::from_ref(&first), "home")?,
        NodeId::from_str(&first.node_id)?
    );
    assert!(resolve_selector_from_rows(&[first.clone(), second], "HomeServer").is_err());
    assert_eq!(
        resolve_selector_from_rows(std::slice::from_ref(&first), &first.fingerprint)?,
        NodeId::from_str(&first.node_id)?
    );
    Ok(())
}

#[test]
fn tags_partial_names_and_small_typos_return_significant_ranked_matches() -> Result<(), Box<dyn std::error::Error>> {
    let mut alpha_server = row("AlphaServer", 1);
    alpha_server.tags.push("alpha".to_owned());
    let alpine = row("Alpine", 2);
    let studio = row("Studio", 3);
    let rows = [alpha_server.clone(), alpine, studio];

    assert_eq!(
        resolve_selector_from_rows(&rows, "alpha")?,
        NodeId::from_str(&alpha_server.node_id)?
    );
    let partial = selector_matches_from_rows(&rows, "alp")?;
    assert_eq!(partial.len(), 2);
    assert_eq!(
        partial.first().map(|matched| matched.node_id),
        Some(NodeId::from_str(&alpha_server.node_id)?)
    );
    assert!(partial.iter().all(|matched| !matched.exact));
    let typo = selector_matches_from_rows(&rows, "alphaserer")?;
    assert_eq!(typo.len(), 1);
    assert_eq!(
        typo.first().map(|matched| matched.node_id),
        Some(NodeId::from_str(&alpha_server.node_id)?)
    );
    assert!(selector_matches_from_rows(&rows, "x").is_err());
    assert!(selector_matches_from_rows(&rows, "unrelated").is_ok_and(|matches| matches.is_empty()));
    Ok(())
}

#[test]
fn exact_owner_tag_outranks_another_peers_signed_name() -> Result<(), Box<dyn std::error::Error>> {
    let mut tagged = row("Workstation", 1);
    tagged.tags.push("home".to_owned());
    let remote_name = row("HomeServer", 2);
    assert_eq!(
        resolve_selector_from_rows(&[tagged.clone(), remote_name], "home")?,
        NodeId::from_str(&tagged.node_id)?
    );
    Ok(())
}

#[test]
fn historical_addresses_are_never_recommended() -> Result<(), Box<dyn std::error::Error>> {
    let candidates = [EndpointCandidate::new(
        CandidateKind::Local,
        CandidateTransport::QuicV1,
        SocketAddr::from(([192, 168, 1, 191], 4_433)),
    )?];
    let networks = [InterfaceNetwork::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
    )];

    let addresses = resolved_candidates(&candidates, &networks, false);
    assert!(addresses.iter().all(|address| !address.preferred));
    Ok(())
}

#[test]
fn mapped_address_is_preferred_when_peer_is_off_link() -> Result<(), Box<dyn std::error::Error>> {
    let candidates = [
        EndpointCandidate::new(
            CandidateKind::Direct,
            CandidateTransport::QuicV1,
            SocketAddr::from(([8, 8, 8, 8], 4_433)),
        )?,
        EndpointCandidate::new(
            CandidateKind::Mapped,
            CandidateTransport::QuicV1,
            SocketAddr::from(([9, 9, 9, 9], 4_433)),
        )?,
    ];
    let networks = [InterfaceNetwork::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
    )];
    let addresses = resolved_candidates(&candidates, &networks, true);
    assert!(
        addresses
            .iter()
            .any(|candidate| candidate.kind == "mapped" && candidate.preferred)
    );
    Ok(())
}

#[test]
fn this_computer_prefers_a_private_ipv4_interface() -> Result<(), Box<dyn std::error::Error>> {
    let candidates = [
        EndpointCandidate::new(
            CandidateKind::Local,
            CandidateTransport::QuicV1,
            SocketAddr::from(([100, 77, 1, 2], 44_330)),
        )?,
        EndpointCandidate::new(
            CandidateKind::Local,
            CandidateTransport::QuicV1,
            SocketAddr::from(([192, 168, 1, 20], 44_330)),
        )?,
        EndpointCandidate::new(
            CandidateKind::Direct,
            CandidateTransport::QuicV1,
            SocketAddr::from(([8, 8, 8, 8], 44_330)),
        )?,
    ];
    let networks = [InterfaceNetwork::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
    )];
    assert_eq!(self_preferred_index(&candidates, &networks), Some(1));
    Ok(())
}
