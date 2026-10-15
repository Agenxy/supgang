//! Private control, revocation, peer-event, and shutdown handling.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    str::FromStr,
    time::Duration,
};

use quinn::Connection;

use super::{
    PeerEvent, ServiceError,
    active::{ActiveConnection, deauthorize_revoked, prune_unauthorized, source_is_authorized},
    gossip_page, rendezvous, unix_time,
};
use crate::{
    cli_peer,
    contact::PeerContact,
    control::{self, ControlListener, ControlReply, ControlRequest, ControlStatus},
    ids::NodeId,
    peer_directory::PeerDirectory,
    router_mapping::RouterMappingStatus,
    state::LocalState,
    sync::{MAX_SYNC_CONTACTS, SyncPage},
};

mod reachability;
mod tunnel_control;
use reachability::internet_reachability;

const REVOCATION_INTAKE_INTERVAL: Duration = Duration::from_millis(50);
const SYNC_MUTATION_INTERVAL: Duration = Duration::from_millis(250);
const PEER_SYNC_MUTATION_INTERVAL: Duration = Duration::from_secs(2);

pub(super) struct SyncMutationBudget {
    last_global: Option<tokio::time::Instant>,
    last_peer: BTreeMap<NodeId, tokio::time::Instant>,
}

impl SyncMutationBudget {
    pub(super) const fn new() -> Self {
        Self {
            last_global: None,
            last_peer: BTreeMap::new(),
        }
    }

    fn allow(&mut self, peer: NodeId, now: tokio::time::Instant) -> bool {
        if self
            .last_global
            .is_some_and(|last| now.saturating_duration_since(last) < SYNC_MUTATION_INTERVAL)
            || self
                .last_peer
                .get(&peer)
                .is_some_and(|last| now.saturating_duration_since(*last) < PEER_SYNC_MUTATION_INTERVAL)
        {
            return false;
        }
        self.last_global = Some(now);
        self.last_peer.insert(peer, now);
        true
    }
}

pub(super) fn publish_gossip_if(
    changed: bool,
    sender: &tokio::sync::watch::Sender<SyncPage>,
    local_contact: &PeerContact,
    directory: &PeerDirectory,
    local_state: &LocalState,
    cursor: &mut usize,
) -> Result<(), ServiceError> {
    if changed {
        sender.send_replace(gossip_page(
            local_contact,
            directory,
            local_state.revocations(),
            unix_time()?,
            cursor,
        ));
    }
    Ok(())
}

pub(super) fn import_received(
    directory: &mut PeerDirectory,
    contacts: Vec<PeerContact>,
    now: u64,
) -> Result<bool, ServiceError> {
    directory
        .import_page(
            contacts.into_iter().take(MAX_SYNC_CONTACTS.saturating_add(1)).collect(),
            now,
        )
        .map_err(Into::into)
}

pub(super) fn import_received_reachability(
    directory: &mut PeerDirectory,
    claims: Vec<crate::reachability::ReachabilityClaim>,
    now: u64,
) -> bool {
    let mut changed = false;
    for claim in claims
        .into_iter()
        .take(crate::reachability::MAX_REACHABILITY_CLAIMS.saturating_add(1))
    {
        changed |= directory.import_reachability(claim, now).unwrap_or(false);
    }
    changed
}

pub(super) fn apply_received_revocations(
    local_state: &mut LocalState,
    incoming: crate::revocation::SignedRevocationList,
) -> Result<bool, ServiceError> {
    let changed = local_state.merge_revocations(incoming)?;
    if local_state
        .revocations()
        .contains(&local_state.identity().device.node_id())
    {
        return Err(ServiceError::LocalRevoked);
    }
    Ok(changed)
}

pub(super) fn merge_received_revocations(
    local_state: &mut LocalState,
    directory: &mut PeerDirectory,
    active: &mut BTreeMap<NodeId, ActiveConnection>,
    incoming: crate::revocation::SignedRevocationList,
) -> Result<bool, ServiceError> {
    let changed = apply_received_revocations(local_state, incoming)?;
    if changed {
        deauthorize_revoked(active, local_state.revocations());
        directory.set_revocations(local_state.revocations())?;
    }
    Ok(changed)
}

pub(super) async fn revocation_listener(
    connection: Connection,
    peer: NodeId,
    events: tokio::sync::mpsc::Sender<PeerEvent>,
) {
    let connection_id = connection.stable_id();
    loop {
        let received = crate::sync::receive_revocation_notice(&connection).await;
        tokio::time::sleep(REVOCATION_INTAKE_INTERVAL).await;
        if let Ok(revocations) = received {
            if events
                .send(PeerEvent::Revocations {
                    peer,
                    connection_id,
                    revocations,
                })
                .await
                .is_err()
            {
                return;
            }
        } else {
            return;
        }
    }
}

pub(super) struct PeerEventState<'a> {
    pub(super) active: &'a mut BTreeMap<NodeId, ActiveConnection>,
    pub(super) noncanonical_outbound: &'a mut BTreeSet<NodeId>,
    pub(super) local_state: &'a mut LocalState,
    pub(super) directory: &'a mut PeerDirectory,
    pub(super) rendezvous_offers: &'a mut Vec<rendezvous::RendezvousOfferEvent>,
    pub(super) rendezvous_intents: &'a mut rendezvous::RendezvousIntents,
    pub(super) sync_budget: &'a mut SyncMutationBudget,
}

pub(super) fn process_peer_events(
    receiver: &mut tokio::sync::mpsc::Receiver<PeerEvent>,
    state: PeerEventState<'_>,
) -> Result<bool, ServiceError> {
    let PeerEventState {
        active,
        noncanonical_outbound,
        local_state,
        directory,
        rendezvous_offers,
        rendezvous_intents,
        sync_budget,
    } = state;
    let mut directory_changed = false;
    while let Ok(event) = receiver.try_recv() {
        if let Some((peer, connection_id)) = event.source()
            && !source_is_authorized(active, local_state, peer, connection_id, unix_time()?)
        {
            continue;
        }
        match event {
            PeerEvent::Contacts {
                peer,
                connection_id,
                page,
            } => {
                if is_current_connection(active, peer, connection_id) {
                    if page
                        .revocations
                        .verify(&local_state.identity().root_verifying_key)
                        .is_err()
                    {
                        if let Some(connection) = active.remove(&peer) {
                            connection.invalidate(b"invalid revocation snapshot");
                        }
                        continue;
                    }
                    if merge_received_revocations(local_state, directory, active, page.revocations)? {
                        directory_changed = true;
                    }
                    if close_if_revoked(active, local_state, peer) {
                        continue;
                    }
                    if sync_budget.allow(peer, tokio::time::Instant::now()) {
                        directory_changed |= import_received(directory, page.contacts, unix_time()?)?;
                        // Only the verified current peer record can extend this
                        // live session, and only for its original transport pin
                        // and generation. Gossip from an unproved node cannot.
                        let now = unix_time()?;
                        if let Some(contact) = directory.usable(&peer, now)
                            && let Some(connection) = active.get(&peer)
                        {
                            connection.renew_verified_record(peer, &contact.endpoint.record, now);
                        }
                        directory_changed |= import_received_reachability(directory, page.reachability, unix_time()?);
                    }
                }
            }
            PeerEvent::Revocations {
                peer,
                connection_id,
                revocations,
            } => {
                if !is_current_connection(active, peer, connection_id) {
                    continue;
                }
                if revocations.verify(&local_state.identity().root_verifying_key).is_err() {
                    if let Some(connection) = active.remove(&peer) {
                        connection.invalidate(b"invalid revocation snapshot");
                    }
                    continue;
                }
                if merge_received_revocations(local_state, directory, active, revocations)? {
                    directory_changed = true;
                }
                close_if_revoked(active, local_state, peer);
            }
            PeerEvent::RendezvousRequest {
                peer,
                connection_id,
                rendezvous_id,
                target,
            } => {
                if is_current_connection(active, peer, connection_id) && !local_state.revocations().contains(&target) {
                    let local_can_introduce = local_state.local_membership().is_some_and(|membership| {
                        membership
                            .certificate
                            .roles
                            .contains(crate::membership::MembershipRoles::INTRODUCER)
                    });
                    if local_can_introduce {
                        let _delivered = rendezvous::introduce_active_pair(active, peer, rendezvous_id, target);
                    }
                }
            }
            PeerEvent::RendezvousOffer {
                peer,
                connection_id,
                rendezvous_id,
                target,
                address,
            } => {
                if is_current_connection(active, peer, connection_id)
                    && peer != target
                    && !active.contains_key(&target)
                    && !local_state.revocations().contains(&target)
                    && rendezvous_intents.take(target, peer, connection_id, rendezvous_id, tokio::time::Instant::now())
                    && rendezvous_offers.len() < super::PEER_EVENT_QUEUE
                {
                    rendezvous_offers.push(rendezvous::RendezvousOfferEvent {
                        introducer: peer,
                        rendezvous_id,
                        target,
                        address,
                    });
                }
            }
            PeerEvent::Closed { peer, connection_id } => {
                if is_current_connection(active, peer, connection_id) {
                    if let Some(connection) = active.remove(&peer) {
                        connection.authorization().invalidate();
                    }
                    noncanonical_outbound.remove(&peer);
                }
            }
        }
    }
    prune_unauthorized(active, local_state, unix_time()?);
    noncanonical_outbound.retain(|peer| active.contains_key(peer));
    Ok(directory_changed)
}

fn is_current_connection(active: &BTreeMap<NodeId, ActiveConnection>, peer: NodeId, connection_id: usize) -> bool {
    connection_event_is_current(active.get(&peer).map(|active| active.stable_id()), connection_id)
}

pub(super) fn connection_event_is_current(current_id: Option<usize>, event_id: usize) -> bool {
    current_id == Some(event_id)
}

fn close_if_revoked(active: &mut BTreeMap<NodeId, ActiveConnection>, local_state: &LocalState, peer: NodeId) -> bool {
    if !local_state.revocations().contains(&peer) {
        return false;
    }
    if let Some(connection) = active.remove(&peer) {
        connection.invalidate(b"peer revoked");
    }
    true
}

pub(super) struct ControlView<'a> {
    pub instance_id: &'a str,
    pub restart_requested: &'a mut bool,
    pub state_directory: &'a std::path::Path,
    pub update_delivery: &'a mut super::update_delivery::UpdateDeliveryQueue,
    pub listen: SocketAddr,
    pub local_contact: &'a mut crate::contact::PeerContact,
    pub config: &'a mut super::ServiceConfig,
    pub transport_identity: &'a crate::transport::TransportIdentity,
    pub router_mapping: RouterMappingStatus,
    pub anchor_mode: bool,
    pub tunnels: &'a super::tunnel::TunnelRuntime,
    pub tunnel_tasks: &'a mut tokio::task::JoinSet<()>,
}

pub(super) enum ControlActivity<T> {
    Control(bool),
    Incoming(T),
}

pub(super) async fn poll_control_or_incoming<T>(
    listener: &ControlListener,
    incoming: impl std::future::Future<Output = T>,
    wait: Duration,
    local_state: &mut LocalState,
    directory: &mut PeerDirectory,
    active: &mut BTreeMap<NodeId, ActiveConnection>,
    view: ControlView<'_>,
) -> Result<ControlActivity<T>, ServiceError> {
    // Only socket acceptance is cancellation-safe. Once accepted, the bounded
    // request/reply transaction must finish even if an inbound QUIC attempt
    // arrives. Otherwise that traffic can drop commands, including a reply to
    // an owner mutation that has already been committed.
    let accepted = tokio::select! {
        accepted = tokio::time::timeout(wait, listener.accept()) => accepted,
        value = incoming => return Ok(ControlActivity::Incoming(value)),
    };
    let Ok(accepted) = accepted else {
        return Ok(ControlActivity::Control(false));
    };
    if let Ok(stream) = accepted {
        let changed = handle_control(stream, local_state, directory, active, view).await?;
        return Ok(ControlActivity::Control(changed));
    }
    Ok(ControlActivity::Control(false))
}

async fn handle_control(
    mut stream: tokio::net::UnixStream,
    local_state: &mut LocalState,
    directory: &mut PeerDirectory,
    active: &mut BTreeMap<NodeId, ActiveConnection>,
    view: ControlView<'_>,
) -> Result<bool, ServiceError> {
    let ControlView {
        instance_id,
        restart_requested,
        state_directory,
        update_delivery,
        listen,
        local_contact,
        config,
        transport_identity,
        router_mapping,
        anchor_mode,
        tunnels,
        tunnel_tasks,
    } = view;
    let request = tokio::time::timeout(Duration::from_secs(2), control::read_request(&mut stream)).await;
    if let Ok(Ok(ControlRequest::Connect { target, name })) = request {
        tunnel_control::connect(stream, target, name, local_state, active, tunnels, tunnel_tasks).await;
        return Ok(false);
    }
    let (reply, changed) = match request {
        Ok(Ok(ControlRequest::AddMapped { address })) => {
            let result = tunnel_control::add_mapped_endpoint(
                tunnels,
                state_directory,
                address.into(),
                config,
                local_state,
                transport_identity,
                local_contact,
            );
            match result {
                Ok(changed) => (ControlReply::EndpointChanged, changed),
                Err(tunnel_control::PublicationError::Policy(message)) => (ControlReply::Error { message }, false),
                Err(tunnel_control::PublicationError::Authority(error)) => return Err(error),
            }
        }
        Ok(Ok(ControlRequest::TunnelLimits {
            per_peer,
            total,
            idle_seconds,
        })) => match tunnels.save_limits(
            state_directory,
            usize::from(per_peer),
            usize::from(total),
            u64::from(idle_seconds),
        ) {
            Ok(()) => ControlReply::LimitsSaved,
            Err(message) => ControlReply::Error { message },
        }
        .into_unchanged(),
        Ok(Ok(ControlRequest::Expose { name, port })) => {
            tunnel_control::expose(tunnels, state_directory, name, port, active).into_unchanged()
        }
        Ok(Ok(ControlRequest::Connect { .. })) => unreachable_connect_reply().into_unchanged(),
        Ok(Ok(ControlRequest::Restart)) => {
            restart_reply(instance_id, restart_requested, is_supervised()).into_unchanged()
        }
        Ok(Ok(ControlRequest::Status)) => ControlReply::Status {
            value: ControlStatus {
                version: env!("CARGO_PKG_VERSION").to_owned(),
                process_id: std::process::id(),
                startup_id: crate::control::startup_id(),
                instance_id: instance_id.to_owned(),
                restart_supported: is_supervised(),
                name: local_contact
                    .endpoint
                    .record
                    .display_name
                    .as_ref()
                    .map_or_else(|| "computer".to_owned(), ToString::to_string),
                hive_id: local_state.identity().hive_id.to_string(),
                node_id: local_state.identity().device.node_id().to_string(),
                listen: listen.to_string(),
                active_peers: active.len(),
                known_peers: directory.entries().len(),
                router_mapping: router_mapping.name().to_owned(),
                internet_reachability: internet_reachability(
                    local_contact,
                    router_mapping,
                    directory,
                    local_state.identity().device.node_id(),
                    unix_time().unwrap_or(0),
                )
                .to_owned(),
                connection_recovery: "automatic-multi-path".to_owned(),
                mode: if anchor_mode { "anchor" } else { "device" }.to_owned(),
                member_count: local_state.member_count(),
                event_count: local_state.event_count(),
            },
        }
        .into_unchanged(),
        Ok(Ok(ControlRequest::Peers)) => match unix_time() {
            Ok(now) => {
                let mut value = cli_peer::peers_from_directory(
                    directory,
                    &local_state.identity().root_verifying_key,
                    now,
                    cli_peer::running_local_row(local_contact, directory, now),
                );
                for peer in &mut value.peers {
                    let connection = NodeId::from_str(&peer.node_id)
                        .ok()
                        .and_then(|node| active.get(&node))
                        .filter(|connection| {
                            connection.close_reason().is_none() && connection.authorization().is_current(now)
                        });
                    peer.connected = Some(connection.is_some());
                    peer.connection = connection.map(|connection| {
                        let statistics = connection.stats();
                        crate::cli_peer_types::PeerConnection {
                            remote_address: crate::candidate::canonical_socket_address(connection.remote_address())
                                .to_string(),
                            received_datagrams: statistics.udp_rx.datagrams,
                            sent_datagrams: statistics.udp_tx.datagrams,
                        }
                    });
                }
                ControlReply::Peers { value }
            }
            Err(error) => ControlReply::Error {
                message: error.to_string(),
            },
        }
        .into_unchanged(),
        // This computer answers for itself from the record it signs, as any member
        // would answer for it: checked now against the root, its membership, the
        // record's validity and the revocations known here, so a record this
        // service holds but could no longer prove is refused, not served.
        Ok(Ok(ControlRequest::Resolve(node_id))) if node_id == local_state.identity().device.node_id() => {
            match unix_time() {
                Err(error) => ControlReply::Error {
                    message: error.to_string(),
                },
                Ok(_) if directory.is_revoked(&node_id) => ControlReply::Error {
                    message: "this computer's identity is revoked".to_owned(),
                },
                Ok(now) => match local_contact.verify(&local_state.identity().root_verifying_key, now) {
                    Ok(()) => ControlReply::Resolve {
                        value: cli_peer::resolve_local_live(local_contact, directory, now),
                    },
                    Err(error) => ControlReply::Error {
                        message: format!("this computer's signed record is not currently valid: {error}"),
                    },
                },
            }
            .into_unchanged()
        }
        Ok(Ok(ControlRequest::Resolve(node_id))) => unix_time()
            .map_or_else(
                |error| ControlReply::Error {
                    message: error.to_string(),
                },
                |now| {
                    cli_peer::resolve_from_directory(directory, node_id, now).map_or_else(
                        |message| ControlReply::Error { message },
                        |value| ControlReply::Resolve { value },
                    )
                },
            )
            .into_unchanged(),
        Ok(Ok(ControlRequest::Revoke(node_id))) => revoke_from_control(local_state, directory, active, node_id)?,
        Ok(Ok(ControlRequest::Update { target, digest })) => {
            queue_update(state_directory, update_delivery, local_state, target, digest)
        }
        Ok(Err(_)) | Err(_) => ControlReply::Error {
            message: "local control request is invalid".to_owned(),
        }
        .into_unchanged(),
    };
    let _write = tokio::time::timeout(Duration::from_secs(2), control::write_reply(&mut stream, &reply)).await;
    Ok(changed)
}

fn unreachable_connect_reply() -> ControlReply {
    ControlReply::Error {
        message: "local tunnel request was not admitted".to_owned(),
    }
}

fn is_supervised() -> bool {
    std::env::var_os("SUPGANG_SUPERVISED").is_some_and(|value| value == "1")
}

fn restart_reply(instance_id: &str, requested: &mut bool, supervised: bool) -> ControlReply {
    if !supervised {
        return ControlReply::Error {
            message: "this foreground process has no background supervisor to restart it".to_owned(),
        };
    }
    *requested = true;
    ControlReply::Restarting {
        instance_id: instance_id.to_owned(),
    }
}

fn queue_update(
    state_directory: &std::path::Path,
    delivery_queue: &mut super::update_delivery::UpdateDeliveryQueue,
    local_state: &LocalState,
    target: NodeId,
    digest: [u8; 32],
) -> (ControlReply, bool) {
    let result = (|| {
        let _root = local_state
            .identity()
            .root
            .as_ref()
            .ok_or("this computer does not hold the hive root needed to authorize a remote update")?;
        if target == local_state.identity().device.node_id() || local_state.revocations().contains(&target) {
            return Err("the selected peer is not eligible for an update");
        }
        let queued = crate::update::queue_peer_delivery(
            state_directory,
            target,
            digest,
            unix_time().map_err(|_| "the system clock is invalid")?,
        )
        .map_err(|_| "the prepared update could not be queued safely")?;
        delivery_queue.enqueue(queued);
        Ok::<(), &str>(())
    })();
    match result {
        Ok(()) => (
            ControlReply::UpdateQueued {
                node_id: target.to_string(),
                digest: hex::encode(digest),
            },
            false,
        ),
        Err(message) => (
            ControlReply::Error {
                message: message.to_owned(),
            },
            false,
        ),
    }
}

trait UnchangedReply {
    fn into_unchanged(self) -> (ControlReply, bool);
}

impl UnchangedReply for ControlReply {
    fn into_unchanged(self) -> (ControlReply, bool) {
        (self, false)
    }
}

fn revoke_from_control(
    local_state: &mut LocalState,
    directory: &mut PeerDirectory,
    active: &mut BTreeMap<NodeId, ActiveConnection>,
    node_id: NodeId,
) -> Result<(ControlReply, bool), ServiceError> {
    let before = local_state.revocations().list.serial;
    let result = unix_time().and_then(|now| local_state.revoke(node_id, now).map_err(ServiceError::from));
    let revocations = match result {
        Ok(revocations) => revocations,
        Err(error) if authoritative_persistence_failed(&error) => return Err(error),
        Err(error) => {
            return Ok((
                ControlReply::Error {
                    message: error.to_string(),
                },
                false,
            ));
        }
    };
    let changed = revocations.list.serial > before;
    if changed {
        deauthorize_revoked(active, &revocations);
    }
    if changed {
        directory.set_revocations(&revocations)?;
    }
    Ok((
        ControlReply::Revoked {
            node_id: node_id.to_string(),
            serial: revocations.list.serial,
            changed,
        },
        changed,
    ))
}

const fn authoritative_persistence_failed(error: &ServiceError) -> bool {
    matches!(
        error,
        ServiceError::State(
            crate::state::StateError::Journal(_)
                | crate::state::StateError::Storage(_)
                | crate::state::StateError::ReadOnlySnapshot
        )
    )
}

#[cfg(test)]
mod tests;
