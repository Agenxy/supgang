use std::{collections::BTreeMap, collections::BTreeSet, fs, net::SocketAddr, time::Duration};

use quinn::{Connection, Endpoint};

use super::{
    ActiveConnection, AuthenticatedExchange, ConnectionOrigin, LiveSessionState, ServiceConfig, SessionAuthorization,
    make_local_contact, unix_time,
};
use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
    contact::PeerContact,
    identity::DeviceIdentity,
    membership::{MAX_MEMBERSHIP_LIFETIME_SECONDS, MembershipRoles},
    peer_directory::{PEER_DIRECTORY_FILE_NAME, PeerDirectory},
    profile::PeerName,
    reachability::{ReachabilityClaim, ReachabilitySource},
    record::{Capabilities, ENDPOINT_RECORD_VERSION, EndpointRecord, SignedEndpointRecord},
    revocation::{REVOCATION_VERSION, RevocationList, SignedRevocationList},
    state,
    sync::SyncPage,
    transport::{self, TransportIdentity},
};

#[test]
fn network_change_drains_obsolete_handshakes_in_every_lane() -> Result<(), Box<dyn std::error::Error>> {
    transport::build_runtime()?.block_on(async {
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(std::future::pending::<super::SessionTaskResult>());
        let mut inbound = tokio::task::JoinSet::new();
        inbound.spawn(std::future::pending::<super::SessionTaskResult>());
        let mut priority = tokio::task::JoinSet::new();
        priority.spawn(std::future::pending::<super::SessionTaskResult>());
        let mut active = BTreeMap::new();
        let mut noncanonical = BTreeSet::new();
        let mut in_flight = true;
        super::reset_network_recovery(
            &mut active,
            &mut noncanonical,
            [&mut tasks, &mut inbound, &mut priority],
            &mut in_flight,
        )
        .await;
        assert!(!in_flight);
        assert!(tasks.is_empty());
        assert!(tasks.try_join_next().is_none());
        assert!(inbound.try_join_next().is_none());
        assert!(priority.try_join_next().is_none());
    });
    Ok(())
}

async fn connection_pair(
    server: &Endpoint,
    client: &Endpoint,
    server_key: crate::ids::TransportKeyId,
) -> Result<(Connection, Connection), Box<dyn std::error::Error>> {
    let accepting = server.clone();
    let accepted = tokio::spawn(async move {
        accepting
            .accept()
            .await
            .ok_or("server endpoint closed")?
            .await
            .map_err(|error| error.to_string())
    });
    let outgoing = tokio::time::timeout(
        Duration::from_secs(5),
        client.connect_with(
            transport::pinned_client_config(server_key)?,
            server.local_addr()?,
            "supgang.invalid",
        )?,
    )
    .await??;
    let incoming = accepted.await??;
    Ok((outgoing, incoming))
}

struct RejectedDurableSnapshot {
    events: usize,
    sequence: u64,
    revocations: SignedRevocationList,
    candidates: Vec<EndpointCandidate>,
    local_contact: PeerContact,
    peer_journal_bytes: u64,
}

impl RejectedDurableSnapshot {
    fn capture(
        local_state: &state::LocalState,
        config: &ServiceConfig,
        local_contact: &PeerContact,
        peer_journal: &std::path::Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            events: local_state.event_count(),
            sequence: local_state.sequence(),
            revocations: local_state.revocations().clone(),
            candidates: config.candidates.clone(),
            local_contact: local_contact.clone(),
            peer_journal_bytes: fs::metadata(peer_journal)?.len(),
        })
    }

    fn assert_unchanged(
        &self,
        local_state: &state::LocalState,
        directory: &PeerDirectory,
        config: &ServiceConfig,
        local_contact: &PeerContact,
        peer_journal: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(local_state.event_count(), self.events);
        assert_eq!(local_state.sequence(), self.sequence);
        assert_eq!(local_state.revocations(), &self.revocations);
        assert!(directory.entries().is_empty());
        assert_eq!(config.candidates, self.candidates);
        assert_eq!(local_contact, &self.local_contact);
        assert_eq!(fs::metadata(peer_journal)?.len(), self.peer_journal_bytes);
        Ok(())
    }
}

#[test]
fn duplicate_and_capacity_rejections_precede_every_durable_exchange_effect() -> Result<(), Box<dyn std::error::Error>> {
    transport::build_runtime()?.block_on(async {
        let temporary = tempfile::tempdir()?;
        let state_path = temporary.path().join("state");
        let mut local_state = state::initialize(&state_path)?;
        let local_transport = TransportIdentity::generate()?;
        let listen = SocketAddr::from(([0, 0, 0, 0], 44_330));
        let mut config = ServiceConfig::new(
            PeerName::new("Test Computer")?,
            listen,
            &[SocketAddr::from(([127, 0, 0, 1], 44_330))],
            &[],
        )?;
        let mut local_contact = make_local_contact(&mut local_state, &local_transport, &config)?;
        let peer = DeviceIdentity::generate()?;
        let revoked_peer = DeviceIdentity::generate()?;
        let now = unix_time()?;
        let expires_at = now.saturating_add(MAX_MEMBERSHIP_LIFETIME_SECONDS);
        let membership = local_state.issue_membership(
            &peer.verifying_key(),
            MembershipRoles::DEVICE,
            [51; 32],
            now,
            expires_at,
        )?;
        local_state.issue_membership(
            &revoked_peer.verifying_key(),
            MembershipRoles::DEVICE,
            [52; 32],
            now,
            expires_at,
        )?;
        let received_contact = PeerContact {
            membership,
            endpoint: SignedEndpointRecord::sign(
                EndpointRecord {
                    protocol_version: ENDPOINT_RECORD_VERSION,
                    hive_id: local_state.identity().hive_id,
                    node_id: peer.node_id(),
                    display_name: Some(PeerName::new("Rejected Peer")?),
                    transport_key_id: crate::ids::TransportKeyId::from_public_material(b"rejected-peer"),
                    generation: 0,
                    sequence: 1,
                    issued_at: now,
                    expires_at: now.saturating_add(3_600),
                    candidates: vec![EndpointCandidate::new(
                        CandidateKind::Local,
                        CandidateTransport::QuicV1,
                        SocketAddr::from(([127, 0, 0, 1], 44_331)),
                    )?],
                    capabilities: Capabilities::NONE,
                    services: Vec::new(),
                },
                &peer,
            )?,
        };
        let incoming_revocations = SignedRevocationList::sign(
            RevocationList {
                version: REVOCATION_VERSION,
                hive_id: local_state.identity().hive_id,
                serial: local_state.revocations().list.serial.saturating_add(1),
                issued_at: now.max(local_state.revocations().list.issued_at),
                revoked_nodes: vec![revoked_peer.node_id()],
            },
            local_state.identity().root.as_ref().ok_or("root identity missing")?,
        )?;
        let mut directory = PeerDirectory::open(
            &state_path,
            local_state.identity().root_verifying_key,
            local_state.identity().device.node_id(),
            local_state.revocations(),
        )?;
        let peer_journal = state_path.join(PEER_DIRECTORY_FILE_NAME);
        let before = RejectedDurableSnapshot::capture(&local_state, &config, &local_contact, &peer_journal)?;
        let page = SyncPage {
            contacts: vec![local_contact.clone()],
            reachability: Vec::new(),
            revocations: before.revocations.clone(),
        };
        let (page_sender, _page_receiver) = tokio::sync::watch::channel(page);
        let (event_sender, _event_receiver) = tokio::sync::mpsc::channel(4);
        let mut active = BTreeMap::new();
        let mut noncanonical_outbound = BTreeSet::new();
        let mut actor_tasks = tokio::task::JoinSet::new();
        let mut gossip_cursor = 0_usize;

        let server_identity = TransportIdentity::generate()?;
        let server = Endpoint::server(server_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let client_identity = TransportIdentity::generate()?;
        let client = Endpoint::server(client_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let (existing, _existing_remote) = connection_pair(&server, &client, server_identity.key_id()).await?;
        let (duplicate, _duplicate_remote) = connection_pair(&server, &client, server_identity.key_id()).await?;
        let (capacity, _capacity_remote) = connection_pair(&server, &client, server_identity.key_id()).await?;
        let existing_id = existing.stable_id();
        let now = unix_time()?;
        active.insert(
            peer.node_id(),
            ActiveConnection::new(
                existing,
                SessionAuthorization::new(now.saturating_add(60), now).ok_or("authorization expired")?,
                Capabilities::NONE,
            ),
        );

        let local_reachability = ReachabilityClaim::sign(
            received_contact.membership.clone(),
            &peer,
            local_state.identity().device.node_id(),
            SocketAddr::from(([8, 8, 8, 8], 50_000)),
            ReachabilitySource::PeerObserved,
            now,
        )?;

        let exchange = || AuthenticatedExchange {
            peer: peer.node_id(),
            contacts: vec![received_contact.clone()],
            revocations: incoming_revocations.clone(),
            authorization_expires_at: now.saturating_add(60),
            capabilities: Capabilities::NONE,
            reachability: Vec::new(),
            local_reachability: local_reachability.clone(),
        };
        let mut draining = super::super::draining::DrainingConnections::default();
        LiveSessionState {
            update: None,
            local_node: local_state.identity().device.node_id(),
            local_state: &mut local_state,
            directory: &mut directory,
            config: &mut config,
            local_contact: &mut local_contact,
            active: &mut active,
            draining: &mut draining,
            noncanonical_outbound: &mut noncanonical_outbound,
            page_sender: &page_sender,
            event_sender: &event_sender,
            actor_tasks: &mut actor_tasks,
            gossip_cursor: &mut gossip_cursor,
        }
        .finish_authenticated(duplicate, exchange(), ConnectionOrigin::Outbound, None)?;
        assert_eq!(
            active.get(&peer.node_id()).map(|active| active.stable_id()),
            Some(existing_id)
        );
        before.assert_unchanged(&local_state, &directory, &config, &local_contact, &peer_journal)?;

        let _existing = active.remove(&peer.node_id()).ok_or("existing connection missing")?;
        config.max_active_peers = 0;
        LiveSessionState {
            update: None,
            local_node: local_state.identity().device.node_id(),
            local_state: &mut local_state,
            directory: &mut directory,
            config: &mut config,
            local_contact: &mut local_contact,
            active: &mut active,
            draining: &mut draining,
            noncanonical_outbound: &mut noncanonical_outbound,
            page_sender: &page_sender,
            event_sender: &event_sender,
            actor_tasks: &mut actor_tasks,
            gossip_cursor: &mut gossip_cursor,
        }
        .finish_authenticated(capacity, exchange(), ConnectionOrigin::Outbound, None)?;
        assert!(active.is_empty());
        before.assert_unchanged(&local_state, &directory, &config, &local_contact, &peer_journal)?;

        server.close(0_u8.into(), b"test complete");
        client.close(0_u8.into(), b"test complete");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
