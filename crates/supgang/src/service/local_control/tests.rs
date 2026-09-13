use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::unix::fs::PermissionsExt,
};

#[test]
fn restart_is_owner_local_and_requires_a_supervisor() {
    let mut requested = false;
    assert!(matches!(
        super::restart_reply("instance", &mut requested, false),
        ControlReply::Error { .. }
    ));
    assert!(!requested);
    assert!(matches!(
        super::restart_reply("instance", &mut requested, true),
        ControlReply::Restarting { .. }
    ));
    assert!(requested);
}

use super::{import_received, internet_reachability_from_candidates, queue_update};
use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
    contact::PeerContact,
    control::ControlReply,
    identity::DeviceIdentity,
    ids::TransportKeyId,
    membership::MembershipRoles,
    peer_directory::PeerDirectory,
    profile::PeerName,
    record::{Capabilities, ENDPOINT_RECORD_VERSION, EndpointRecord, SignedEndpointRecord},
    router_mapping::RouterMappingStatus,
    service::update_delivery::UpdateDeliveryQueue,
    state,
};

fn signed_contact(
    local_state: &mut state::LocalState,
    device: &DeviceIdentity,
    port: u16,
) -> Result<PeerContact, Box<dyn std::error::Error>> {
    let membership = if let Some(existing) = local_state.membership(&device.node_id()) {
        existing.clone()
    } else {
        local_state.issue_membership(&device.verifying_key(), MembershipRoles::DEVICE, [7; 32], 10, 100)?
    };
    Ok(PeerContact {
        membership,
        endpoint: SignedEndpointRecord::sign(
            EndpointRecord {
                protocol_version: ENDPOINT_RECORD_VERSION,
                hive_id: local_state.identity().hive_id,
                node_id: device.node_id(),
                display_name: Some(PeerName::new("Test Peer")?),
                transport_key_id: TransportKeyId::from_public_material(b"test-transport"),
                generation: 0,
                sequence: 1,
                issued_at: 20,
                expires_at: 100,
                candidates: vec![EndpointCandidate::new(
                    CandidateKind::Local,
                    CandidateTransport::QuicV1,
                    SocketAddr::from(([127, 0, 0, 1], port)),
                )?],
                capabilities: Capabilities::NONE,
            },
            device,
        )?,
    })
}

#[test]
fn unverified_address_sources_are_never_reported_as_confirmed() -> Result<(), Box<dyn std::error::Error>> {
    let reflexive = EndpointCandidate::new(
        CandidateKind::Reflexive,
        CandidateTransport::QuicV1,
        SocketAddr::from(([8, 8, 8, 8], 44_330)),
    )?;
    let mapping = RouterMappingStatus::Mapped(SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 44_330));
    assert_eq!(
        internet_reachability_from_candidates(&[reflexive], mapping, false),
        "device-claimed-address"
    );
    assert_eq!(
        internet_reachability_from_candidates(&[], mapping, false),
        "gateway-reported-address"
    );
    assert_eq!(
        internet_reachability_from_candidates(&[], RouterMappingStatus::Unavailable, true),
        "peer-reported-address"
    );
    Ok(())
}

#[test]
fn first_equivocation_refreshes_gossip_and_repeats_do_not() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state_path = temporary.path().join("state");
    let mut local_state = state::initialize(&state_path)?;
    let peer = DeviceIdentity::generate()?;
    let first = signed_contact(&mut local_state, &peer, 44_330)?;
    let conflict = signed_contact(&mut local_state, &peer, 44_331)?;
    let mut directory = PeerDirectory::open(
        &state_path,
        local_state.identity().root_verifying_key,
        local_state.identity().device.node_id(),
        local_state.revocations(),
    )?;

    assert!(import_received(&mut directory, vec![first], 50)?);
    assert!(import_received(&mut directory, vec![conflict.clone()], 50)?);
    assert!(!import_received(&mut directory, vec![conflict], 50)?);
    assert!(
        directory
            .entries()
            .get(&peer.node_id())
            .is_some_and(crate::peer_directory::PeerEntry::is_conflicted)
    );
    Ok(())
}

#[test]
fn disconnected_peer_update_is_durable_instead_of_timing_dependent() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state_path = temporary.path().join("state");
    let local_state = state::initialize(&state_path)?;
    let peer = DeviceIdentity::generate()?.node_id();
    let source = temporary.path().join("release.bundle");
    fs::write(&source, b"bounded queued release")?;
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600))?;
    let digest = crate::update::prepare_outbound(&state_path, &source)?;
    let mut queue = UpdateDeliveryQueue::open(&state_path, 100)?;
    let (reply, changed) = queue_update(&state_path, &mut queue, &local_state, peer, digest);
    assert!(!changed);
    assert!(matches!(reply, ControlReply::UpdateQueued { .. }));
    drop(queue);
    assert_eq!(crate::update::status(&state_path)?.queued_peer_deliveries, 1);
    assert_eq!(
        crate::update::load_peer_deliveries(&state_path, 101)?.deliveries.len(),
        1
    );
    Ok(())
}
