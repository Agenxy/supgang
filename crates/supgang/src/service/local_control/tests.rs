use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::unix::fs::PermissionsExt,
};

#[tokio::test]
async fn accepted_control_request_survives_incoming_network_activity() -> Result<(), Box<dyn std::error::Error>> {
    exercise_control_dispatch(Some(b"SUPGIPC1\x01"), true).await
}

#[tokio::test]
async fn stalled_control_request_times_out_despite_incoming_network_activity() -> Result<(), Box<dyn std::error::Error>>
{
    exercise_control_dispatch(None, false).await
}

#[tokio::test]
async fn malformed_control_request_is_rejected_despite_incoming_network_activity()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_control_dispatch(Some(b"BADFRAME!"), false).await
}

async fn exercise_control_dispatch(body: Option<&[u8]>, expect_status: bool) -> Result<(), Box<dyn std::error::Error>> {
    use std::{collections::BTreeMap, task::Poll, time::Duration};
    use tokio::{io::AsyncWriteExt, net::UnixStream, sync::oneshot};

    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("state");
    let mut local_state = state::initialize(&path)?;
    let device = DeviceIdentity::generate()?;
    let mut contact = signed_contact(&mut local_state, &device, 44_330)?;
    let mut directory = PeerDirectory::open(
        &path,
        local_state.identity().root_verifying_key,
        local_state.identity().device.node_id(),
        local_state.revocations(),
    )?;
    let listener = crate::control::ControlListener::bind(&path)?;
    let mut client = UnixStream::connect(path.join(crate::control::CONTROL_SOCKET_FILE_NAME)).await?;
    // Hold the request open after its length prefix. Network activity becomes
    // ready only after the dispatcher has accepted this owner connection.
    client.write_all(&9_u32.to_be_bytes()).await?;
    let (network_sender, mut network_receiver) = oneshot::channel::<()>();
    let mut active = BTreeMap::new();
    let mut draining = super::super::draining::DrainingConnections::default();
    let mut restart = false;
    let mut updates = UpdateDeliveryQueue::open(&path, 50)?;
    let tunnels = super::super::tunnel::TunnelRuntime::new(&path)?;
    let mut tunnel_tasks = tokio::task::JoinSet::new();
    let transport_identity = crate::transport::TransportIdentity::generate()?;
    let mut config = super::super::ServiceConfig::new(
        crate::profile::PeerName::new("Test")?,
        "127.0.0.1:44330".parse()?,
        &["127.0.0.1:44330".parse()?],
        &[],
    )?;
    {
        let dispatch = super::poll_control_or_incoming(
            &listener,
            &mut network_receiver,
            Duration::from_secs(1),
            &mut local_state,
            &mut directory,
            &mut active,
            super::ControlView {
                draining: &mut draining,
                instance_id: "test",
                restart_requested: &mut restart,
                state_directory: &path,
                update_delivery: &mut updates,
                listen: SocketAddr::from(([127, 0, 0, 1], 44_330)),
                local_contact: &mut contact,
                router_mapping: RouterMappingStatus::Disabled,
                anchor_mode: false,
                tunnels: &tunnels,
                tunnel_tasks: &mut tunnel_tasks,
                recent_connections: Vec::new(),
                config: &mut config,
                transport_identity: &transport_identity,
            },
        );
        tokio::pin!(dispatch);
        assert!(matches!(futures_util::poll!(dispatch.as_mut()), Poll::Pending));
        network_sender.send(()).map_err(|()| "network event receiver dropped")?;
        assert!(
            matches!(futures_util::poll!(dispatch.as_mut()), Poll::Pending),
            "incoming network activity cancelled an accepted local control request"
        );
        if let Some(body) = body {
            client.write_all(body).await?;
        }
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(3), dispatch).await??,
            super::ControlActivity::Control(false)
        ));
    }
    assert_control_reply(&mut client, expect_status).await?;
    assert!(
        network_receiver.await.is_ok(),
        "the competing network event must remain available"
    );
    Ok(())
}

async fn assert_control_reply(
    client: &mut tokio::net::UnixStream,
    expect_status: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncReadExt;
    let length = client.read_u32().await?;
    assert!(length > 0 && length <= 64 * 1024);
    let mut reply = vec![0_u8; length as usize];
    client.read_exact(&mut reply).await?;
    let reply = serde_json::from_slice::<ControlReply>(&reply)?;
    if expect_status {
        assert!(matches!(reply, ControlReply::Status { .. }));
    } else {
        assert!(matches!(reply, ControlReply::Error { .. }));
    }
    Ok(())
}

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

#[test]
fn owner_revocation_requests_gossip_only_when_state_changes() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("state");
    let mut local_state = state::initialize(&path)?;
    let device = DeviceIdentity::generate()?;
    let contact = signed_contact(&mut local_state, &device, 44_330)?;
    let mut directory = PeerDirectory::open(
        &path,
        local_state.identity().root_verifying_key,
        local_state.identity().device.node_id(),
        local_state.revocations(),
    )?;
    directory.import(contact, 50)?;
    let mut active = std::collections::BTreeMap::new();
    let mut draining = super::super::draining::DrainingConnections::default();
    let (reply, changed) = super::revoke_from_control(
        &mut local_state,
        &mut directory,
        &mut active,
        &mut draining,
        device.node_id(),
    )?;
    assert!(changed);
    assert!(matches!(reply, ControlReply::Revoked { changed: true, .. }));
    assert!(directory.is_revoked(&device.node_id()));
    let (reply, changed) = super::revoke_from_control(
        &mut local_state,
        &mut directory,
        &mut active,
        &mut draining,
        device.node_id(),
    )?;
    assert!(!changed);
    assert!(matches!(reply, ControlReply::Revoked { changed: false, .. }));
    Ok(())
}

use super::{import_received, queue_update, reachability::internet_reachability_from_candidates};
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
                services: Vec::new(),
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
    let owner_mapped = EndpointCandidate::new(
        CandidateKind::Mapped,
        CandidateTransport::QuicV1,
        SocketAddr::from(([9, 9, 9, 9], 44_330)),
    )?;
    assert_eq!(
        internet_reachability_from_candidates(&[owner_mapped], RouterMappingStatus::Disabled, false),
        "owner-mapped-address-unverified"
    );
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
