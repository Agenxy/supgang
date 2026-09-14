use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use ed25519_dalek::VerifyingKey;
use quinn::{Connection, Endpoint, Incoming};

use crate::{
    contact::PeerContact, identity::DeviceIdentity, ids::NodeId, network, peer_directory::PeerDirectory,
    revocation::SignedRevocationList, state::LocalState, sync::SyncPage,
};

use super::{
    AuthenticatedExchange, CONNECT_TIMEOUT_SECONDS, ConnectionOrigin, PeerActorRegistry, PeerEvent, PeerUpdateContext,
    SESSION_TIMEOUT_SECONDS, ServiceConfig, ServiceError, SessionAuthentication,
    active::{ActiveConnection, SessionAuthorization},
    dial_observed_peer, dial_peer, gossip_page, import_received, import_received_reachability, inbound_session,
    merge_received_revocations, register_connection,
    rendezvous::RendezvousOfferEvent,
    should_attempt_peer, unix_time,
};

#[cfg(test)]
use super::make_local_contact;

pub(super) struct LiveSessionState<'a> {
    pub(super) update: Option<&'a PeerUpdateContext>,
    pub(super) local_node: NodeId,
    pub(super) local_state: &'a mut LocalState,
    pub(super) directory: &'a mut PeerDirectory,
    pub(super) config: &'a mut ServiceConfig,
    pub(super) local_contact: &'a mut PeerContact,
    pub(super) active: &'a mut BTreeMap<NodeId, ActiveConnection>,
    pub(super) noncanonical_outbound: &'a mut BTreeSet<NodeId>,
    pub(super) page_sender: &'a tokio::sync::watch::Sender<SyncPage>,
    pub(super) event_sender: &'a tokio::sync::mpsc::Sender<PeerEvent>,
    pub(super) actor_tasks: &'a mut tokio::task::JoinSet<()>,
    pub(super) gossip_cursor: &'a mut usize,
}

struct SessionSnapshot {
    device: Arc<DeviceIdentity>,
    root_key: VerifyingKey,
    revocations: SignedRevocationList,
    local_contact: PeerContact,
    page: SyncPage,
}

pub(super) struct SessionTaskResult {
    origin: ConnectionOrigin,
    claimed_outbound_slot: bool,
    authenticated: Option<(AuthenticatedExchange, Connection)>,
}

pub(super) struct RememberedPeerSchedule {
    pub(super) target: NodeId,
    pub(super) direct_started: bool,
}

impl LiveSessionState<'_> {
    fn snapshot(&self, device: &Arc<DeviceIdentity>) -> SessionSnapshot {
        SessionSnapshot {
            device: Arc::clone(device),
            root_key: self.local_state.identity().root_verifying_key,
            revocations: self.local_state.revocations().clone(),
            local_contact: self.local_contact.clone(),
            page: self.page_sender.borrow().clone(),
        }
    }

    fn finish_authenticated(
        &mut self,
        connection: Connection,
        exchange: AuthenticatedExchange,
        origin: ConnectionOrigin,
    ) -> Result<(), ServiceError> {
        if self.local_state.revocations().contains(&exchange.peer) {
            connection.close(3_u8.into(), b"peer revoked");
            return Ok(());
        }
        let now = unix_time()?;
        let Some(authorization) = SessionAuthorization::new(exchange.authorization_expires_at, now) else {
            connection.close(3_u8.into(), b"peer authorization expired");
            return Ok(());
        };
        let connection_id = connection.stable_id();
        register_connection(
            connection,
            authorization,
            exchange.capabilities,
            exchange.peer,
            origin,
            &mut PeerActorRegistry {
                local: self.local_node,
                active: self.active,
                noncanonical_outbound: self.noncanonical_outbound,
                pages: self.page_sender,
                events: self.event_sender,
                tasks: self.actor_tasks,
                interval: self.config.retry_interval,
                max_active_peers: self.config.max_active_peers,
                anchor_mode: self.config.max_active_peers > super::MAX_ACTIVE_PEERS,
                update: self.update.cloned(),
            },
        );
        let admitted = self
            .active
            .get(&exchange.peer)
            .is_some_and(|active| active.stable_id() == connection_id);
        if !admitted {
            return Ok(());
        }
        merge_received_revocations(self.local_state, self.directory, self.active, exchange.revocations)?;
        if self.local_state.revocations().contains(&exchange.peer) {
            if let Some(active) = self.active.get(&exchange.peer) {
                active.close(3_u8.into(), b"peer revoked");
            }
            return Ok(());
        }
        let _directory_changed = import_received(self.directory, exchange.contacts, now)?;
        let mut reachability = exchange.reachability;
        reachability.push(exchange.local_reachability);
        let _claims_changed = import_received_reachability(self.directory, reachability, now);
        let page = gossip_page(
            self.local_contact,
            self.directory,
            self.local_state.revocations(),
            unix_time()?,
            self.gossip_cursor,
        );
        self.page_sender.send_replace(page);
        Ok(())
    }
}

pub(super) fn finish_ready_sessions(
    tasks: &mut tokio::task::JoinSet<SessionTaskResult>,
    outbound_in_flight: &mut bool,
    live: &mut LiveSessionState<'_>,
) -> Result<(), ServiceError> {
    while let Some(joined) = tasks.try_join_next() {
        let completed = joined?;
        if completed.claimed_outbound_slot {
            *outbound_in_flight = false;
        }
        if let Some((exchange, connection)) = completed.authenticated {
            live.finish_authenticated(connection, exchange, completed.origin)?;
        }
    }
    Ok(())
}

pub(super) fn schedule_remembered_peer(
    endpoint: &Endpoint,
    dial_cursor: &mut usize,
    retry_round: usize,
    device: &Arc<DeviceIdentity>,
    tasks: &mut tokio::task::JoinSet<SessionTaskResult>,
    live: &LiveSessionState<'_>,
) -> Option<RememberedPeerSchedule> {
    let mut peers = BTreeMap::<NodeId, Vec<_>>::new();
    for hint in live.directory.dial_hints(unix_time().ok()?) {
        let peer = hint.contact().endpoint.record.node_id;
        if should_attempt_peer(live.active, live.local_node, peer, retry_round) {
            peers.entry(peer).or_default().push(hint);
        }
    }
    let round = *dial_cursor;
    let peer_count = peers.len();
    let (target, hints) = peers.iter().nth(round % peer_count.max(1))?;
    let peer_cycle = round / peer_count.max(1);
    let hint = hints.get(dial_hint_index(peer_cycle, hints.len()))?;
    let ordered_addresses = ordered_hint_addresses(hint);
    if ordered_addresses.is_empty() {
        *dial_cursor = dial_cursor.wrapping_add(1);
        return Some(RememberedPeerSchedule {
            target: *target,
            direct_started: false,
        });
    }
    *dial_cursor = dial_cursor.wrapping_add(1);
    let expected = hint.contact().clone();
    let addresses = ordered_addresses
        .into_iter()
        .take(network::MAX_DIAL_CANDIDATES_PER_ROUND)
        .collect::<Vec<_>>();
    let endpoint = endpoint.clone();
    let snapshot = live.snapshot(device);
    tasks.spawn(async move {
        let authenticated = dial_peer(
            &endpoint,
            &SessionAuthentication {
                local_contact: &snapshot.local_contact,
                device: &snapshot.device,
                root_key: &snapshot.root_key,
                revocations: &snapshot.revocations,
                page: &snapshot.page,
            },
            &expected,
            &addresses,
        )
        .await;
        SessionTaskResult {
            origin: ConnectionOrigin::Outbound,
            claimed_outbound_slot: true,
            authenticated,
        }
    });
    Some(RememberedPeerSchedule {
        target: *target,
        direct_started: true,
    })
}

pub(super) const fn dial_hint_index(peer_cycle: usize, hint_count: usize) -> usize {
    if hint_count > 1 && peer_cycle % 4 == 3 {
        1 + ((peer_cycle / 4) % hint_count.saturating_sub(1))
    } else {
        0
    }
}

fn ordered_hint_addresses(hint: &crate::peer_directory::PeerDialHint<'_>) -> Vec<SocketAddr> {
    let networks = network::interface_networks().unwrap_or_default();
    hint.addresses()
        .iter()
        .copied()
        .filter(|address| route_compatible_address(*address, &networks))
        .collect()
}

fn route_compatible_address(address: SocketAddr, networks: &[network::InterfaceNetwork]) -> bool {
    let transport = crate::candidate::CandidateTransport::QuicV1;
    crate::candidate::EndpointCandidate::new(crate::candidate::CandidateKind::Local, transport, address)
        .or_else(|_| {
            crate::candidate::EndpointCandidate::new(crate::candidate::CandidateKind::Reflexive, transport, address)
        })
        .is_ok_and(|candidate| network::candidate_is_route_compatible(&candidate, networks))
}

pub(super) fn schedule_incoming_peer(
    incoming: Incoming,
    device: &Arc<DeviceIdentity>,
    tasks: &mut tokio::task::JoinSet<SessionTaskResult>,
    live: &LiveSessionState<'_>,
) {
    let snapshot = live.snapshot(device);
    tasks.spawn(async move {
        let authenticated = match tokio::time::timeout(Duration::from_secs(CONNECT_TIMEOUT_SECONDS), incoming).await {
            Ok(Ok(connection)) => {
                let exchange = tokio::time::timeout(
                    Duration::from_secs(SESSION_TIMEOUT_SECONDS),
                    inbound_session(
                        &connection,
                        &SessionAuthentication {
                            local_contact: &snapshot.local_contact,
                            device: &snapshot.device,
                            root_key: &snapshot.root_key,
                            revocations: &snapshot.revocations,
                            page: &snapshot.page,
                        },
                    ),
                )
                .await;
                if let Ok(Ok(exchange)) = exchange {
                    Some((exchange, connection))
                } else {
                    connection.close(1_u8.into(), b"authentication failed");
                    None
                }
            }
            _ => None,
        };
        SessionTaskResult {
            origin: ConnectionOrigin::Inbound,
            claimed_outbound_slot: false,
            authenticated,
        }
    });
}

pub(super) fn schedule_rendezvous_offers(
    endpoint: &Endpoint,
    offers: Vec<RendezvousOfferEvent>,
    device: &Arc<DeviceIdentity>,
    tasks: &mut tokio::task::JoinSet<SessionTaskResult>,
    live: &LiveSessionState<'_>,
) {
    let mut scheduled = std::collections::BTreeSet::new();
    for offer in offers {
        if tasks.len() >= super::MAX_PENDING_SESSIONS
            || offer.target == live.local_node
            || live.active.contains_key(&offer.target)
            || !live.active.contains_key(&offer.introducer)
            || !scheduled.insert((offer.target, offer.rendezvous_id))
        {
            continue;
        }
        let Some(expected) = live.directory.recovery_authority(&offer.target).cloned() else {
            continue;
        };
        let endpoint = endpoint.clone();
        let snapshot = live.snapshot(device);
        tasks.spawn(async move {
            let authenticated = dial_observed_peer(
                &endpoint,
                &SessionAuthentication {
                    local_contact: &snapshot.local_contact,
                    device: &snapshot.device,
                    root_key: &snapshot.root_key,
                    revocations: &snapshot.revocations,
                    page: &snapshot.page,
                },
                &expected,
                offer.address,
            )
            .await;
            SessionTaskResult {
                origin: ConnectionOrigin::Outbound,
                claimed_outbound_slot: false,
                authenticated,
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, collections::BTreeSet, fs, net::SocketAddr, time::Duration};

    use quinn::{Connection, Endpoint};

    use super::{
        ActiveConnection, AuthenticatedExchange, ConnectionOrigin, LiveSessionState, ServiceConfig,
        SessionAuthorization, make_local_contact, unix_time,
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
    fn duplicate_and_capacity_rejections_precede_every_durable_exchange_effect()
    -> Result<(), Box<dyn std::error::Error>> {
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
            LiveSessionState {
                update: None,
                local_node: local_state.identity().device.node_id(),
                local_state: &mut local_state,
                directory: &mut directory,
                config: &mut config,
                local_contact: &mut local_contact,
                active: &mut active,
                noncanonical_outbound: &mut noncanonical_outbound,
                page_sender: &page_sender,
                event_sender: &event_sender,
                actor_tasks: &mut actor_tasks,
                gossip_cursor: &mut gossip_cursor,
            }
            .finish_authenticated(duplicate, exchange(), ConnectionOrigin::Outbound)?;
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
                noncanonical_outbound: &mut noncanonical_outbound,
                page_sender: &page_sender,
                event_sender: &event_sender,
                actor_tasks: &mut actor_tasks,
                gossip_cursor: &mut gossip_cursor,
            }
            .finish_authenticated(capacity, exchange(), ConnectionOrigin::Outbound)?;
            assert!(active.is_empty());
            before.assert_unchanged(&local_state, &directory, &config, &local_contact, &peer_journal)?;

            server.close(0_u8.into(), b"test complete");
            client.close(0_u8.into(), b"test complete");
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }
}
