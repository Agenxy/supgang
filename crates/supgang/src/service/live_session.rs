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
    pub(super) draining: &'a mut super::draining::DrainingConnections,
    pub(super) replacements: &'a mut BTreeMap<NodeId, PendingReplacement>,
    pub(super) replacement_tasks: &'a mut tokio::task::JoinSet<ReplacementResult>,
    pub(super) quality: &'a mut super::path_quality::PathQualityWatch,
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
    recent_admissions: BTreeMap<NodeId, usize>,
}

pub(super) struct SessionTaskResult {
    origin: ConnectionOrigin,
    claimed_outbound_slot: bool,
    authenticated: Option<(AuthenticatedExchange, Connection)>,
    /// The prior admission and whether it was still registered at task start.
    registered_old: Option<(usize, bool)>,
    /// The registered connection this authenticated path may replace.
    superseded: Option<super::liveness::Superseded>,
}

/// One candidate per peer. The old connection stays active while this
/// candidate proves the remote application accepted it after authentication.
pub(super) struct PendingReplacement {
    pub(super) connection: Connection,
    old_id: usize,
}

pub(super) struct ReplacementResult {
    connection: Connection,
    exchange: AuthenticatedExchange,
    origin: ConnectionOrigin,
    old_id: usize,
    proven: bool,
}

/// Finishes a session task: a connection authenticated over another path can
/// replace a silent, on-link-inferior, or materially slower registered path.
async fn completed(
    origin: ConnectionOrigin,
    claimed_outbound_slot: bool,
    authenticated: Option<(AuthenticatedExchange, Connection)>,
    registered: &BTreeMap<NodeId, Connection>,
    recent_admissions: &BTreeMap<NodeId, usize>,
) -> SessionTaskResult {
    let registered_old = authenticated
        .as_ref()
        .and_then(|(exchange, _)| registered.get(&exchange.peer))
        .map(|connection| (connection.stable_id(), true))
        .or_else(|| {
            authenticated
                .as_ref()
                .and_then(|(exchange, _)| recent_admissions.get(&exchange.peer).map(|id| (*id, false)))
        });
    let superseded = match &authenticated {
        Some((exchange, connection)) => super::liveness::superseded(registered, exchange.peer, connection).await,
        None => None,
    };
    SessionTaskResult {
        origin,
        claimed_outbound_slot,
        authenticated,
        registered_old,
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
            recent_admissions: self.quality.recent_admissions(tokio::time::Instant::now()),
        }
    }

    fn finish_authenticated(
        &mut self,
        connection: Connection,
        exchange: AuthenticatedExchange,
        origin: ConnectionOrigin,
        superseded: Option<super::liveness::Superseded>,
        registered_old: Option<(usize, bool)>,
    ) -> Result<(), ServiceError> {
        if self.local_state.revocations().contains(&exchange.peer) {
            connection.close(3_u8.into(), b"peer revoked");
            return Ok(());
        }
        let now = unix_time()?;
        if SessionAuthorization::new(exchange.authorization_expires_at, now).is_none() {
            connection.close(3_u8.into(), b"peer authorization expired");
            return Ok(());
        }
        let current = self.active.get(&exchange.peer);
        let raced = registered_old.and_then(|(old, was_active)| {
            current
                .filter(|current| current.stable_id() != old)
                .map(|current| (was_active, current))
        });
        if raced.is_some_and(|(was_active, current)| {
            was_active
                || crate::candidate::canonical_socket_address(current.remote_address())
                    != crate::candidate::canonical_socket_address(connection.remote_address())
        }) {
            connection.close(2_u8.into(), b"stale candidate lost admission race");
            return Ok(());
        }
        if registered_old.is_some_and(|(old, _)| current.is_some_and(|current| current.stable_id() == old))
            && superseded.is_none()
        {
            connection.close(2_u8.into(), b"established path kept over duplicate");
            return Ok(());
        }
        let selected_old = superseded
            .or_else(|| {
                raced.map(|(_, current)| super::liveness::Superseded {
                    id: current.stable_id(),
                    old_live: true,
                })
            })
            .filter(|stale| {
                self.active
                    .get(&exchange.peer)
                    .is_some_and(|active| active.stable_id() == stale.id)
            });
        let old = selected_old.or_else(|| {
            if self.active.contains_key(&exchange.peer) {
                None
            } else {
                registered_old.map(|(id, _)| super::liveness::Superseded { id, old_live: true })
            }
        });
        let Some(old) = old else {
            return self.admit_authenticated(connection, exchange, origin, None);
        };
        if !old.old_live {
            return self.admit_authenticated(connection, exchange, origin, Some(old.id));
        }
        if self.replacements.contains_key(&exchange.peer)
            || self.replacements.len() >= self.config.max_active_peers
            || self.draining.contains(exchange.peer)
        {
            connection.close(2_u8.into(), b"replacement already in progress");
            return Ok(());
        }
        let peer = exchange.peer;
        self.replacements.insert(
            peer,
            PendingReplacement {
                connection: connection.clone(),
                old_id: old.id,
            },
        );
        let page = self.page_sender.borrow().clone();
        let root = self.local_state.identity().root_verifying_key;
        let local = self.local_node;
        let retry_interval = self.config.retry_interval;
        self.replacement_tasks.spawn(async move {
            let proven = super::replacement_proof::prove(&connection, local, peer, &page, &root, retry_interval).await;
            ReplacementResult {
                connection,
                exchange,
                origin,
                old_id: old.id,
                proven,
            }
        });
        Ok(())
    }

    fn admit_authenticated(
        &mut self,
        connection: Connection,
        exchange: AuthenticatedExchange,
        origin: ConnectionOrigin,
        superseded: Option<usize>,
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
        let selected_old = superseded.filter(|stale| {
            self.active
                .get(&exchange.peer)
                .is_some_and(|active| active.stable_id() == *stale)
        });
        if selected_old.is_some() && self.draining.contains(exchange.peer) {
            // One drain slot per peer: keep the already-held tunnels instead
            // of evicting them for another quality migration.
            connection.close(2_u8.into(), b"previous tunnel drain in progress");
            return Ok(());
        }
        // Only the exact connection compared before authentication can move
        // to the drain slot. Keep it until the replacement is admitted.
        let old = selected_old.and_then(|_| self.active.remove(&exchange.peer));
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
            if old.is_some() || self.active.contains_key(&exchange.peer) {
                self.quality.backoff(exchange.peer, tokio::time::Instant::now());
            }
            if let Some(old) = old {
                self.active.insert(exchange.peer, old);
            }
            return Ok(());
        }
        self.quality
            .note_admitted(exchange.peer, connection_id, tokio::time::Instant::now());
        if let Some(old) = old {
            self.draining.begin(exchange.peer, old, tokio::time::Instant::now());
        }
        if let Some(contact) = authenticated_contact.as_ref()
            && let Some(active) = self.active.get_mut(&exchange.peer)
        {
            active.bind_authority_record(&contact.endpoint.record);
        }
        merge_received_revocations(
            self.local_state,
            self.directory,
            self.active,
            self.draining,
            exchange.revocations,
        )?;
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

pub(super) fn finish_ready_replacements(live: &mut LiveSessionState<'_>) -> Result<(), ServiceError> {
    while let Some(joined) = live.replacement_tasks.try_join_next() {
        let result = joined?;
        let peer = result.exchange.peer;
        let id = result.connection.stable_id();
        let current = live
            .replacements
            .get(&peer)
            .is_some_and(|slot| slot.connection.stable_id() == id && slot.old_id == result.old_id);
        if !current {
            result.connection.close(2_u8.into(), b"replacement no longer current");
            continue;
        }
        live.replacements.remove(&peer);
        let current = live.active.get(&peer).map(|active| active.stable_id());
        if result.proven && (current.is_none() || current == Some(result.old_id)) {
            // The old route can die while both peers prove the candidate.
            // In that case admit the proved connection as a new session;
            // there is no surviving old tunnel to drain.
            live.admit_authenticated(result.connection, result.exchange, result.origin, current)?;
        } else {
            result.connection.close(2_u8.into(), b"replacement proof failed");
            live.quality.backoff(peer, tokio::time::Instant::now());
        }
    }
    Ok(())
}

pub(super) async fn cancel_pending_replacements(
    replacements: &mut BTreeMap<NodeId, PendingReplacement>,
    tasks: &mut tokio::task::JoinSet<ReplacementResult>,
    reason: &'static [u8],
) {
    tasks.shutdown().await;
    for pending in replacements.values() {
        pending.connection.close(2_u8.into(), reason);
    }
    replacements.clear();
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
            live.finish_authenticated(
                connection,
                exchange,
                completed.origin,
                completed.superseded,
                completed.registered_old,
            )?;
        }
    }
    Ok(())
}

pub(super) fn schedule_remembered_peer(
    endpoint: &Endpoint,
    dial_cursor: &mut usize,
    device: &Arc<DeviceIdentity>,
    tasks: &mut tokio::task::JoinSet<SessionTaskResult>,
    live: &mut LiveSessionState<'_>,
) -> Option<RememberedPeerSchedule> {
    let now = tokio::time::Instant::now();
    let networks = network::interface_networks().unwrap_or_default();
    let mut peers = BTreeMap::<NodeId, Vec<_>>::new();
    for hint in live.directory.dial_hints(unix_time().ok()?) {
        let peer = hint.contact().endpoint.record.node_id;
        if live.replacements.contains_key(&peer) {
            continue;
        }
        if should_attempt_peer(live.active, peer)
            || (live.quality.allows_replacement(peer, now)
                && (super::retry_schedule::wants_on_link_path(live.active, peer, &networks)
                    || live.quality.wants_replacement(peer, now)))
        {
            peers.entry(peer).or_default().push(hint);
        }
    }
    let round = *dial_cursor;
    let peer_count = peers.len();
    let (target, hints) = peers.iter().nth(round % peer_count.max(1))?;
    let peer_cycle = round / peer_count.max(1);
    let mut candidates = recovery_candidates(hints, &networks, peer_cycle);
    let quality_replacement = live.quality.wants_replacement(*target, now);
    if let Some(active) = live.active.get(target) {
        // A connected peer is dialled only over a directly attached path,
        // unless its live path is measurably degraded. Never redial its same
        // address as a candidate for a quality replacement.
        let current = crate::candidate::canonical_socket_address(active.remote_address());
        candidates.retain(|(_, address)| {
            let ip = address.ip().to_canonical();
            crate::candidate::canonical_socket_address(*address) != current
                && (quality_replacement || networks.iter().any(|network| network.contains(ip)))
        });
    }
    *dial_cursor = dial_cursor.wrapping_add(1);
    if quality_replacement {
        live.quality.mark_attempt(*target, now);
    }
    if candidates.is_empty() {
        return Some(RememberedPeerSchedule {
            target: *target,
            direct_started: false,
        });
    }
    let endpoint = endpoint.clone();
    let snapshot = live.snapshot(device);
    let capped_address = live.quality.capped_address(*target);
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
            capped_address,
        )
        .await;
        completed(
            ConnectionOrigin::Outbound,
            true,
            authenticated,
            &snapshot.registered,
            &snapshot.recent_admissions,
        )
        .await
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
    capped_server_config: Option<Arc<quinn::ServerConfig>>,
    device: &Arc<DeviceIdentity>,
    tasks: &mut tokio::task::JoinSet<SessionTaskResult>,
    live: &LiveSessionState<'_>,
) {
    let snapshot = live.snapshot(device);
    tasks.spawn(async move {
        let connecting = match capped_server_config {
            Some(config) => incoming.accept_with(config),
            None => incoming.accept(),
        };
        let handshake = async move {
            match connecting {
                Ok(connecting) => connecting.await,
                Err(error) => Err(error),
            }
        };
        let authenticated = match tokio::time::timeout(Duration::from_secs(CONNECT_TIMEOUT_SECONDS), handshake).await {
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
        completed(
            ConnectionOrigin::Inbound,
            false,
            authenticated,
            &snapshot.registered,
            &snapshot.recent_admissions,
        )
        .await
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
            completed(
                ConnectionOrigin::Outbound,
                false,
                authenticated,
                &snapshot.registered,
                &snapshot.recent_admissions,
            )
            .await
        });
    }
}

#[cfg(test)]
mod session_tests;
