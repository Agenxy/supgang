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
    retry_schedule::candidate_batch,
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
    /// The connection registered for each peer when the session began, so an
    /// authenticated replacement over a new path can test whether it is gone.
    registered: BTreeMap<NodeId, Connection>,
}

pub(super) struct SessionTaskResult {
    origin: ConnectionOrigin,
    claimed_outbound_slot: bool,
    authenticated: Option<(AuthenticatedExchange, Connection)>,
    /// The stable identity of a registered connection proven gone.
    superseded: Option<usize>,
}

/// Finishes a session task: a connection that authenticated over a different
/// path from the one registered for its peer probes the registered one.
async fn completed(
    origin: ConnectionOrigin,
    claimed_outbound_slot: bool,
    authenticated: Option<(AuthenticatedExchange, Connection)>,
    registered: &BTreeMap<NodeId, Connection>,
) -> SessionTaskResult {
    let superseded = match &authenticated {
        Some((exchange, connection)) => super::liveness::superseded(registered, exchange.peer, connection).await,
        None => None,
    };
    SessionTaskResult {
        origin,
        claimed_outbound_slot,
        authenticated,
        superseded,
    }
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
            registered: self
                .active
                .iter()
                .map(|(peer, active)| (*peer, active.connection().clone()))
                .collect(),
        }
    }

    fn finish_authenticated(
        &mut self,
        connection: Connection,
        exchange: AuthenticatedExchange,
        origin: ConnectionOrigin,
        superseded: Option<usize>,
    ) -> Result<(), ServiceError> {
        // Only the exact connection the probe found silent is retired; one
        // registered since then, or one that answered, is left to admission.
        if let Some(stale) = superseded
            && self
                .active
                .get(&exchange.peer)
                .is_some_and(|active| active.stable_id() == stale)
            && let Some(active) = self.active.remove(&exchange.peer)
        {
            active.invalidate(b"superseded by a connection on a new path");
            self.noncanonical_outbound.remove(&exchange.peer);
        }
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
        let route = (connection.remote_address(), connection.local_ip());
        let authenticated_contact = exchange
            .contacts
            .last()
            .filter(|contact| contact.endpoint.record.node_id == exchange.peer)
            .cloned();
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
        if let Some(contact) = authenticated_contact.as_ref()
            && let Some(active) = self.active.get_mut(&exchange.peer)
        {
            active.bind_authority_record(&contact.endpoint.record);
        }
        merge_received_revocations(self.local_state, self.directory, self.active, exchange.revocations)?;
        if self.local_state.revocations().contains(&exchange.peer) {
            if let Some(active) = self.active.get(&exchange.peer) {
                active.close(3_u8.into(), b"peer revoked");
            }
            return Ok(());
        }
        let _directory_changed = import_received(self.directory, exchange.contacts, now)?;
        if let Some(contact) = authenticated_contact {
            self.directory.remember_authenticated_route(
                &self.local_state.identity().device,
                &contact,
                route.0,
                route.1,
                now,
            )?;
        }
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
            live.finish_authenticated(connection, exchange, completed.origin, completed.superseded)?;
        }
    }
    Ok(())
}

pub(super) fn schedule_remembered_peer(
    endpoint: &Endpoint,
    dial_cursor: &mut usize,
    device: &Arc<DeviceIdentity>,
    tasks: &mut tokio::task::JoinSet<SessionTaskResult>,
    live: &LiveSessionState<'_>,
) -> Option<RememberedPeerSchedule> {
    let networks = network::interface_networks().unwrap_or_default();
    let mut peers = BTreeMap::<NodeId, Vec<_>>::new();
    for hint in live.directory.dial_hints(unix_time().ok()?) {
        let peer = hint.contact().endpoint.record.node_id;
        if should_attempt_peer(live.active, peer)
            || super::retry_schedule::wants_on_link_path(live.active, peer, &networks)
        {
            peers.entry(peer).or_default().push(hint);
        }
    }
    let round = *dial_cursor;
    let peer_count = peers.len();
    let (target, hints) = peers.iter().nth(round % peer_count.max(1))?;
    let peer_cycle = round / peer_count.max(1);
    let mut candidates = recovery_candidates(hints, &networks, peer_cycle);
    if live.active.contains_key(target) {
        // A connected peer is dialled only over a directly attached path,
        // which then supersedes the indirect one (`liveness::superseded`).
        candidates.retain(|(_, address)| {
            let ip = address.ip().to_canonical();
            networks.iter().any(|network| network.contains(ip))
        });
    }
    *dial_cursor = dial_cursor.wrapping_add(1);
    if candidates.is_empty() {
        return Some(RememberedPeerSchedule {
            target: *target,
            direct_started: false,
        });
    }
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
            &candidates,
        )
        .await;
        completed(ConnectionOrigin::Outbound, true, authenticated, &snapshot.registered).await
    });
    Some(RememberedPeerSchedule {
        target: *target,
        direct_started: true,
    })
}

fn recovery_candidates(
    hints: &[crate::peer_directory::PeerDialHint<'_>],
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

fn eligible_hints<'a>(
    hints: &'a [crate::peer_directory::PeerDialHint<'a>],
    networks: &[network::InterfaceNetwork],
) -> Vec<(&'a crate::peer_directory::PeerDialHint<'a>, Vec<SocketAddr>)> {
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

#[cfg(test)]
mod recovery_tests;

pub(super) async fn reset_network_recovery(
    active: &mut BTreeMap<NodeId, ActiveConnection>,
    noncanonical: &mut BTreeSet<NodeId>,
    pending: [&mut tokio::task::JoinSet<SessionTaskResult>; 3],
    outbound_in_flight: &mut bool,
) {
    // In-flight attempts captured the old local contact and route selection.
    // Drain cancellation results before the ordinary join loop can see them.
    for tasks in pending {
        tasks.shutdown().await;
    }
    *outbound_in_flight = false;
    if let Ok(networks) = network::interface_networks() {
        super::active::retire_unroutable(active, &networks);
        noncanonical.retain(|peer| active.contains_key(peer));
    }
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
        completed(ConnectionOrigin::Inbound, false, authenticated, &snapshot.registered).await
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
            completed(ConnectionOrigin::Outbound, false, authenticated, &snapshot.registered).await
        });
    }
}

#[cfg(test)]
mod session_tests;
