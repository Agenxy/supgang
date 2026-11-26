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

mod agent_keygen_control;
mod agent_sign_control;
mod reachability;
mod update_control;
use update_control::queue_update;
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
    draining: &mut super::draining::DrainingConnections,
    incoming: crate::revocation::SignedRevocationList,
) -> Result<bool, ServiceError> {
    let changed = apply_received_revocations(local_state, incoming)?;
    if changed {
        deauthorize_revoked(active, local_state.revocations());
        draining.invalidate_revoked(local_state.revocations());
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

mod peer_events;
pub(super) use peer_events::{PeerEventState, process_peer_events};

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
    pub(super) draining: &'a mut super::draining::DrainingConnections,
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
    pub sign_tasks: &'a mut tokio::task::JoinSet<()>,
    pub recent_connections: Vec<crate::control::ConnectionEvent>,
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
        draining,
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
        sign_tasks,
        recent_connections,
    } = view;
    let request = tokio::time::timeout(Duration::from_secs(2), control::read_request(&mut stream)).await;
    if let Ok(Ok(ControlRequest::Connect { target, name })) = &request {
        tunnel_control::connect(stream, *target, *name, local_state, active, tunnels, tunnel_tasks).await;
        return Ok(false);
    }
    if let Ok(Ok(ControlRequest::AgentSign {
        target,
        request: payload,
        length,
    })) = &request
    {
        agent_sign_control::handle(
            stream,
            *target,
            payload.clone(),
            *length,
            local_state,
            active,
            sign_tasks,
        )
        .await;
        return Ok(false);
    }
    if let Ok(Ok(ControlRequest::AgentKeygen {
        target,
        request: payload,
        length,
    })) = &request
    {
        agent_keygen_control::handle(
            stream,
            *target,
            payload.clone(),
            *length,
            local_state,
            active,
            sign_tasks,
        )
        .await;
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
            let (reply, removes_grant) = tunnel_control::expose(tunnels, state_directory, name, port, active);
            if removes_grant {
                draining.invalidate_all(b"local tunnel policy changed");
            }
            reply.into_unchanged()
        }
        Ok(Ok(ControlRequest::Exposures)) => tunnels.exposure_reply().into_unchanged(),
        Ok(Ok(
            ControlRequest::Connect { .. } | ControlRequest::AgentSign { .. } | ControlRequest::AgentKeygen { .. },
        )) => unreachable_connect_reply().into_unchanged(),
        Ok(Ok(ControlRequest::Restart)) => {
            restart_reply(instance_id, restart_requested, is_supervised()).into_unchanged()
        }
        Ok(Ok(ControlRequest::Status)) => {
            let now = unix_time().unwrap_or(0);
            ControlReply::Status {
                value: ControlStatus {
                    version: config.release_identity.version().to_owned(),
                    commit: config.release_identity.commit_str().to_owned(),
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
                        now,
                    )
                    .to_owned(),
                    connection_recovery: "automatic-multi-path".to_owned(),
                    mode: if anchor_mode { "anchor" } else { "device" }.to_owned(),
                    member_count: local_state.member_count(),
                    event_count: local_state.event_count(),
                    recent_connections,
                    update_notice: super::release_awareness::current_update_notice(
                        &config.release_identity,
                        active,
                        directory,
                        now,
                    ),
                },
            }
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
                if let Some(this_computer) = value.this_computer.as_mut() {
                    this_computer.release = Some(crate::release::ReleaseInfo::from(&config.release_identity));
                }
                for peer in &mut value.peers {
                    let connection = NodeId::from_str(&peer.node_id)
                        .ok()
                        .and_then(|node| active.get(&node))
                        .filter(|connection| {
                            connection.close_reason().is_none() && connection.authorization().is_current(now)
                        });
                    peer.connected = Some(connection.is_some());
                    peer.release = connection
                        .and_then(ActiveConnection::peer_release)
                        .map(crate::release::ReleaseInfo::from);
                    peer.connection = connection.map(|connection| {
                        let statistics = connection.stats();
                        crate::cli_peer_types::PeerConnection {
                            remote_address: crate::candidate::canonical_socket_address(connection.remote_address())
                                .to_string(),
                            received_datagrams: statistics.udp_rx.datagrams,
                            sent_datagrams: statistics.udp_tx.datagrams,
                            path: Some((&statistics.path).into()),
                            active_tunnels: Some(connection.active_tunnels()),
                            tunnel_limit: Some(connection.tunnel_limit()),
                        }
                    });
                }
                value.update_notice =
                    super::release_awareness::current_update_notice(&config.release_identity, active, directory, now);
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
        Ok(Ok(ControlRequest::Revoke(node_id))) => {
            revoke_from_control(local_state, directory, active, draining, node_id)?
        }
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
    draining: &mut super::draining::DrainingConnections,
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
        draining.invalidate_revoked(&revocations);
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
