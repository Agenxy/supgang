//! Private control, revocation, peer-event, and shutdown handling.

use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

use quinn::{Connection, Endpoint};

use super::{PeerEvent, ServiceError, unix_time};
use crate::{
    cli_peer,
    contact::PeerContact,
    control::{self, ControlListener, ControlReply, ControlRequest, ControlStatus},
    ids::NodeId,
    peer_directory::{ImportDecision, PeerDirectory, PeerDirectoryError},
    state::LocalState,
    sync::MAX_SYNC_CONTACTS,
};

pub(super) fn import_received(
    directory: &mut PeerDirectory,
    contacts: Vec<PeerContact>,
    now: u64,
) -> Result<bool, ServiceError> {
    let mut changed = false;
    for contact in contacts.into_iter().take(MAX_SYNC_CONTACTS.saturating_add(1)) {
        match directory.import(contact, now) {
            Ok(ImportDecision::AcceptedFirst | ImportDecision::AcceptedNewer) => changed = true,
            Err(error @ (PeerDirectoryError::Journal(_) | PeerDirectoryError::Storage(_))) => {
                return Err(error.into());
            }
            Ok(ImportDecision::Duplicate | ImportDecision::RejectedStale) | Err(_) => {}
        }
    }
    Ok(changed)
}

pub(super) fn apply_received_revocations(
    local_state: &mut LocalState,
    directory: &mut PeerDirectory,
    incoming: crate::revocation::SignedRevocationList,
) -> Result<bool, ServiceError> {
    let changed = local_state.merge_revocations(incoming)?;
    if changed {
        directory.set_revocations(local_state.revocations())?;
    }
    if local_state
        .revocations()
        .contains(&local_state.identity().device.node_id())
    {
        return Err(ServiceError::LocalRevoked);
    }
    Ok(changed)
}

pub(super) fn broadcast_revocations(
    active: &BTreeMap<NodeId, Connection>,
    revocations: &crate::revocation::SignedRevocationList,
    except: Option<NodeId>,
) {
    for (node_id, connection) in active {
        if Some(*node_id) == except {
            continue;
        }
        let connection = connection.clone();
        let revocations = revocations.clone();
        let close_after_delivery = revocations.contains(node_id);
        tokio::spawn(async move {
            let delivered = tokio::time::timeout(
                Duration::from_secs(2),
                crate::sync::send_revocation_notice(&connection, &revocations),
            )
            .await
            .is_ok_and(|result| result.is_ok());
            if close_after_delivery || !delivered {
                connection.close(3_u8.into(), b"revocation update");
            }
        });
    }
}

pub(super) fn merge_and_broadcast_revocations(
    local_state: &mut LocalState,
    directory: &mut PeerDirectory,
    active: &BTreeMap<NodeId, Connection>,
    incoming: crate::revocation::SignedRevocationList,
    except: Option<NodeId>,
) -> Result<bool, ServiceError> {
    let changed = apply_received_revocations(local_state, directory, incoming)?;
    if changed {
        broadcast_revocations(active, local_state.revocations(), except);
    }
    Ok(changed)
}

pub(super) fn spawn_revocation_listener(
    connection: Connection,
    peer: NodeId,
    events: tokio::sync::mpsc::Sender<PeerEvent>,
) {
    tokio::spawn(async move {
        loop {
            if let Ok(revocations) = crate::sync::receive_revocation_notice(&connection).await {
                if events.send(PeerEvent::Revocations { peer, revocations }).await.is_err() {
                    return;
                }
            } else {
                connection.close(1_u8.into(), b"invalid revocation notice");
                let _closed = events.send(PeerEvent::Closed { peer }).await;
                return;
            }
        }
    });
}

pub(super) fn process_peer_events(
    receiver: &mut tokio::sync::mpsc::Receiver<PeerEvent>,
    active: &mut BTreeMap<NodeId, Connection>,
    local_state: &mut LocalState,
    directory: &mut PeerDirectory,
) -> Result<bool, ServiceError> {
    let mut directory_changed = false;
    while let Ok(event) = receiver.try_recv() {
        match event {
            PeerEvent::Contacts { peer, page } => {
                if active.contains_key(&peer) {
                    if page
                        .revocations
                        .verify(&local_state.identity().root_verifying_key)
                        .is_err()
                    {
                        if let Some(connection) = active.remove(&peer) {
                            connection.close(1_u8.into(), b"invalid revocation snapshot");
                        }
                        continue;
                    }
                    if merge_and_broadcast_revocations(local_state, directory, active, page.revocations, Some(peer))? {
                        directory_changed = true;
                    }
                    if !local_state.revocations().contains(&peer) {
                        directory_changed |= import_received(directory, page.contacts, unix_time()?)?;
                    }
                }
            }
            PeerEvent::Revocations { peer, revocations } => {
                if !active.contains_key(&peer) {
                    continue;
                }
                if revocations.verify(&local_state.identity().root_verifying_key).is_err() {
                    if let Some(connection) = active.remove(&peer) {
                        connection.close(1_u8.into(), b"invalid revocation snapshot");
                    }
                    continue;
                }
                if merge_and_broadcast_revocations(local_state, directory, active, revocations, Some(peer))? {
                    directory_changed = true;
                }
            }
            PeerEvent::Closed { peer } => {
                active.remove(&peer);
            }
        }
    }
    active.retain(|_, connection| connection.close_reason().is_none());
    Ok(directory_changed)
}

pub(super) async fn stop_if_requested(receiver: &mut tokio::sync::mpsc::Receiver<()>, endpoint: &Endpoint) -> bool {
    if receiver.try_recv().is_err() {
        return false;
    }
    endpoint.close(0_u8.into(), b"service shutdown");
    let _idle = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
    true
}

pub(super) fn shutdown_receiver() -> Result<tokio::sync::mpsc::Receiver<()>, ServiceError> {
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(ServiceError::Signal)?;
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    let interrupt_sender = sender.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _sent = interrupt_sender.send(()).await;
        }
    });
    tokio::spawn(async move {
        if terminate.recv().await.is_some() {
            let _sent = sender.send(()).await;
        }
    });
    Ok(receiver)
}

pub(super) async fn poll_control(
    listener: &ControlListener,
    wait: Duration,
    local_state: &mut LocalState,
    directory: &mut PeerDirectory,
    active: &BTreeMap<NodeId, Connection>,
    listen: SocketAddr,
) -> bool {
    let Ok(accepted) = tokio::time::timeout(wait, listener.accept()).await else {
        return false;
    };
    if let Ok(mut stream) = accepted {
        handle_control(&mut stream, local_state, directory, active, listen).await;
    }
    true
}

async fn handle_control(
    stream: &mut tokio::net::UnixStream,
    local_state: &mut LocalState,
    directory: &mut PeerDirectory,
    active: &BTreeMap<NodeId, Connection>,
    listen: SocketAddr,
) {
    let request = tokio::time::timeout(Duration::from_secs(2), control::read_request(stream)).await;
    let (reply, _changed) = match request {
        Ok(Ok(ControlRequest::Status)) => ControlReply::Status {
            value: ControlStatus {
                hive_id: local_state.identity().hive_id.to_string(),
                node_id: local_state.identity().device.node_id().to_string(),
                listen: listen.to_string(),
                active_peers: active.len(),
                known_peers: directory.entries().len(),
                member_count: local_state.member_count(),
                event_count: local_state.event_count(),
            },
        }
        .into_unchanged(),
        Ok(Ok(ControlRequest::Peers)) => match unix_time() {
            Ok(now) => ControlReply::Peers {
                value: cli_peer::peers_from_directory(directory, &local_state.identity().root_verifying_key, now),
            },
            Err(error) => ControlReply::Error {
                message: error.to_string(),
            },
        }
        .into_unchanged(),
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
        Ok(Ok(ControlRequest::Revoke(node_id))) => revoke_from_control(local_state, directory, active, node_id),
        Ok(Err(_)) | Err(_) => ControlReply::Error {
            message: "local control request is invalid".to_owned(),
        }
        .into_unchanged(),
    };
    let _write = tokio::time::timeout(Duration::from_secs(2), control::write_reply(stream, &reply)).await;
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
    active: &BTreeMap<NodeId, Connection>,
    node_id: NodeId,
) -> (ControlReply, bool) {
    let before = local_state.revocations().list.serial;
    let result = unix_time().and_then(|now| local_state.revoke(node_id, now).map_err(ServiceError::from));
    let revocations = match result {
        Ok(revocations) => revocations,
        Err(error) => {
            return (
                ControlReply::Error {
                    message: error.to_string(),
                },
                false,
            );
        }
    };
    let changed = revocations.list.serial > before;
    if changed && directory.set_revocations(&revocations).is_err() {
        return (
            ControlReply::Error {
                message: "revocation persisted but local peer view could not be updated; restart the service"
                    .to_owned(),
            },
            true,
        );
    }
    if changed {
        broadcast_revocations(active, &revocations, None);
    }
    (
        ControlReply::Revoked {
            node_id: node_id.to_string(),
            serial: revocations.list.serial,
            changed,
        },
        changed,
    )
}
