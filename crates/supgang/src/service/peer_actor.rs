//! Canonical long-lived connection selection and bounded background reconciliation.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use quinn::Connection;

use crate::{
    ids::{HiveId, NodeId},
    peer_stream::{self, StreamKind},
    sync::SyncPage,
    update_wire::{self, UpdateWireError},
};

use super::{
    ConnectionOrigin, PeerEvent, SESSION_TIMEOUT_SECONDS,
    active::{ActiveConnection, SessionAuthorization},
    rendezvous, revocation_listener, sync,
};

const CLOSED_EVENT_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) struct PeerActorRegistry<'a> {
    pub(super) local: NodeId,
    pub(super) active: &'a mut BTreeMap<NodeId, ActiveConnection>,
    pub(super) noncanonical_outbound: &'a mut BTreeSet<NodeId>,
    pub(super) pages: &'a tokio::sync::watch::Sender<SyncPage>,
    pub(super) events: &'a tokio::sync::mpsc::Sender<PeerEvent>,
    pub(super) tasks: &'a mut tokio::task::JoinSet<()>,
    pub(super) interval: Duration,
    pub(super) max_active_peers: usize,
    pub(super) update: Option<PeerUpdateContext>,
}

#[derive(Clone)]
struct PeerActorContext {
    connection: Connection,
    peer: NodeId,
    initiator: bool,
    pages: tokio::sync::watch::Receiver<SyncPage>,
    events: tokio::sync::mpsc::Sender<PeerEvent>,
    interval: Duration,
    update: Option<PeerUpdateContext>,
    tunnel_admission: Arc<tokio::sync::Semaphore>,
    authorization: SessionAuthorization,
    /// Why this session ended, shared with the registered connection so the
    /// connection history can say.
    ended: Arc<std::sync::OnceLock<&'static [u8]>>,
}

#[derive(Clone)]
pub(super) struct PeerUpdateContext {
    pub(super) state_directory: Arc<PathBuf>,
    pub(super) root_key: ed25519_dalek::VerifyingKey,
    pub(super) hive_id: HiveId,
    pub(super) local_node: NodeId,
    pub(super) admission: Arc<tokio::sync::Semaphore>,
    pub(super) tunnels: Option<super::tunnel::TunnelRuntime>,
}

impl PeerUpdateContext {
    pub(super) fn new(state_directory: &std::path::Path, identity: &crate::storage::LocalIdentity) -> Self {
        Self {
            state_directory: Arc::new(state_directory.to_path_buf()),
            root_key: identity.root_verifying_key,
            hive_id: identity.hive_id,
            local_node: identity.device.node_id(),
            admission: Arc::new(tokio::sync::Semaphore::new(1)),
            tunnels: None,
        }
    }
}

pub(super) fn register_connection(
    connection: Connection,
    authorization: SessionAuthorization,
    capabilities: crate::record::Capabilities,
    peer: NodeId,
    origin: ConnectionOrigin,
    registry: &mut PeerActorRegistry<'_>,
) {
    let offered = offered_connection(registry.local, peer, origin);
    let preferred = offered == OfferedConnection::Preferred;
    let current = if !registry.active.contains_key(&peer) {
        CurrentConnection::None
    } else if registry.noncanonical_outbound.contains(&peer) {
        CurrentConnection::Fallback
    } else {
        CurrentConnection::Preferred
    };
    let decision = connection_admission(offered, current, registry.active.len() >= registry.max_active_peers);
    if decision == ConnectionAdmission::ReplaceFallback {
        registry.noncanonical_outbound.remove(&peer);
        if let Some(replaced) = registry.active.remove(&peer) {
            replaced.invalidate(b"preferred connection replaced fallback");
        }
    } else if decision == ConnectionAdmission::Reject {
        connection.close(2_u8.into(), b"duplicate or neighbor limit");
        return;
    }
    let limit = registry
        .update
        .as_ref()
        .and_then(|update| update.tunnels.as_ref())
        .map_or(4, |runtime| runtime.policy.borrow().per_peer);
    let tunnel_admission = Arc::new(tokio::sync::Semaphore::new(limit));
    let registered = ActiveConnection::new(connection.clone(), authorization.clone(), capabilities)
        .with_tunnel_admission(tunnel_admission.clone());
    let ended = registered.retired_slot();
    registry.active.insert(peer, registered);
    if preferred {
        registry.noncanonical_outbound.remove(&peer);
    } else {
        registry.noncanonical_outbound.insert(peer);
    }
    registry.tasks.spawn(supervise_connection(PeerActorContext {
        connection,
        peer,
        initiator: registry.local < peer,
        pages: registry.pages.subscribe(),
        events: registry.events.clone(),
        interval: registry.interval,
        update: registry.update.clone(),
        authorization,
        tunnel_admission,
        ended,
    }));
}

pub(super) fn reap_ready_tasks(tasks: &mut tokio::task::JoinSet<()>) -> Result<(), super::ServiceError> {
    while let Some(result) = tasks.try_join_next() {
        result?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionAdmission {
    Accept,
    ReplaceFallback,
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OfferedConnection {
    Preferred,
    Fallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CurrentConnection {
    None,
    Preferred,
    Fallback,
}

const fn connection_admission(
    offered: OfferedConnection,
    current: CurrentConnection,
    at_capacity: bool,
) -> ConnectionAdmission {
    match current {
        CurrentConnection::Fallback if matches!(offered, OfferedConnection::Preferred) => {
            ConnectionAdmission::ReplaceFallback
        }
        CurrentConnection::Preferred | CurrentConnection::Fallback => ConnectionAdmission::Reject,
        CurrentConnection::None if at_capacity => ConnectionAdmission::Reject,
        CurrentConnection::None => ConnectionAdmission::Accept,
    }
}

fn offered_connection(local: NodeId, peer: NodeId, origin: ConnectionOrigin) -> OfferedConnection {
    // Both ends must rank the same connection identically. A role-local
    // preference for inbound connections makes an anchor replace a connection
    // its peer considers preferred; that peer then rejects the replacement.
    // Anchor capacity is configured separately and cannot affect this ordering.
    let preferred = matches!(origin, ConnectionOrigin::Outbound) == (local < peer);
    if preferred {
        OfferedConnection::Preferred
    } else {
        OfferedConnection::Fallback
    }
}

/// Consecutive failed contact exchanges a live session tolerates. One slow
/// exchange on a lossy or loaded path is not evidence the peer is gone, and
/// ending the session would end every tunnel on it. A dead path is retired by
/// the silence probe and QUIC's idle timeout.
const MAX_SYNC_FAILURES: u32 = 3;

/// Runs one peer's authenticated session until it ends, and says why.
async fn peer_actor(context: PeerActorContext) -> &'static [u8] {
    let PeerActorContext {
        connection,
        peer,
        initiator,
        pages,
        events,
        interval,
        update,
        authorization,
        tunnel_admission,
        ended: _,
    } = context;
    let connection_id = connection.stable_id();
    let mut tunnels = tokio::task::JoinSet::new();
    let mut sync_failures = 0_u32;
    loop {
        while tunnels.try_join_next().is_some() {}
        let exchanged = tokio::select! {
            () = tokio::time::sleep(interval), if initiator => {
                let page = pages.borrow().clone();
                exchange_outbound(&connection, &page).await
            }
            accepted = peer_stream::accept(&connection) => {
                let Ok((kind, mut send, mut receive)) = accepted else {
                    return b"peer stream acceptance ended";
                };
                match kind {
                    StreamKind::Sync if !initiator => {
                        let page = pages.borrow().clone();
                        tokio::time::timeout(
                            Duration::from_secs(SESSION_TIMEOUT_SECONDS),
                            sync::exchange_inbound_stream(&mut send, &mut receive, &page),
                        )
                        .await
                        .ok()
                        .and_then(Result::ok)
                    }
                    StreamKind::Sync => return b"peer opened a sync stream out of turn",
                    StreamKind::Service => {
                        let Some(runtime) = update.as_ref().and_then(|context| context.tunnels.clone()) else {
                            continue;
                        };
                        if tunnels.len() >= runtime.policy.borrow().per_peer { continue; }
                        tunnels.spawn(super::tunnel::incoming(
                            send, receive, runtime, authorization.clone(), tunnel_admission.clone(),
                        ));
                        continue;
                    }
                    StreamKind::Update => {
                        let Some(update) = update.as_ref() else {
                            return b"peer offered an update this computer cannot receive";
                        };
                        let received = update_wire::receive(
                            send,
                            receive,
                            update_wire::ReceiveContext {
                                state_directory: &update.state_directory,
                                root_key: &update.root_key,
                                hive_id: update.hive_id,
                                local_node: update.local_node,
                                authenticated_peer: peer,
                                authorization: &authorization,
                                admission: &update.admission,
                            },
                        )
                        .await;
                        if matches!(
                            received,
                            Err(UpdateWireError::InvalidPreface | UpdateWireError::Rejected | UpdateWireError::Failed)
                        ) {
                            return b"peer update delivery failed";
                        }
                        continue;
                    }
                }
            }
        };
        match exchanged {
            Some(page) => {
                sync_failures = 0;
                if send_contacts(&events, peer, connection_id, page).await.is_err() {
                    return b"service stopped";
                }
            }
            None if connection.close_reason().is_some() => return b"connection closed during sync",
            None => {
                sync_failures = sync_failures.saturating_add(1);
                if sync_failures >= MAX_SYNC_FAILURES {
                    return b"contact sync failed repeatedly";
                }
            }
        }
    }
}

/// One bounded outbound contact exchange; `None` if it did not complete.
async fn exchange_outbound(connection: &Connection, page: &SyncPage) -> Option<SyncPage> {
    let (mut send, mut receive) = tokio::time::timeout(
        Duration::from_secs(SESSION_TIMEOUT_SECONDS),
        peer_stream::open(connection, StreamKind::Sync),
    )
    .await
    .ok()?
    .ok()?;
    tokio::time::timeout(
        Duration::from_secs(SESSION_TIMEOUT_SECONDS),
        sync::exchange_outbound_stream(&mut send, &mut receive, page),
    )
    .await
    .ok()?
    .ok()
}

async fn send_contacts(
    events: &tokio::sync::mpsc::Sender<PeerEvent>,
    peer: NodeId,
    connection_id: usize,
    page: SyncPage,
) -> Result<(), ()> {
    events
        .send(PeerEvent::Contacts {
            peer,
            connection_id,
            page,
        })
        .await
        .map_err(|_| ())
}

async fn supervise_connection(context: PeerActorContext) {
    let connection = context.connection.clone();
    let peer = context.peer;
    let events = context.events.clone();
    let authorization = context.authorization.clone();
    let connection_id = connection.stable_id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(u64::MAX, |duration| duration.as_secs());
    let ended = Arc::clone(&context.ended);
    let reason: &'static [u8] = tokio::select! {
        reason = peer_actor(context) => reason,
        () = revocation_listener(connection.clone(), peer, events.clone()) => b"revocation stream ended",
        () = rendezvous::listener(connection.clone(), peer, events.clone()) => b"rendezvous stream ended",
        () = authorization.wait_until_invalid(now) => b"session authorization lapsed",
    };
    let _first = ended.set(reason);
    authorization.invalidate();
    connection.close(1_u8.into(), reason);
    let _closed = send_closed_event(&events, PeerEvent::Closed { peer, connection_id }, CLOSED_EVENT_TIMEOUT).await;
}

async fn send_closed_event(events: &tokio::sync::mpsc::Sender<PeerEvent>, event: PeerEvent, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, events.send(event))
        .await
        .is_ok_and(|result| result.is_ok())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        net::SocketAddr,
        time::Duration,
    };

    use super::{
        ConnectionAdmission, CurrentConnection, OfferedConnection, PeerActorContext, PeerActorRegistry,
        connection_admission, offered_connection, register_connection, send_closed_event, supervise_connection,
    };
    use crate::{
        identity::RootIdentity,
        ids::NodeId,
        record::Capabilities,
        revocation::SignedRevocationList,
        service::{ConnectionOrigin, active::SessionAuthorization},
        sync::SyncPage,
    };

    fn authorization() -> Result<SessionAuthorization, Box<dyn std::error::Error>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|_| "test clock is before the Unix epoch")?
            .as_secs();
        SessionAuthorization::new(now.saturating_add(60), now).ok_or_else(|| "fresh test authorization missing".into())
    }

    #[test]
    fn a_preferred_path_replaces_only_an_outbound_fallback() {
        assert_eq!(
            connection_admission(OfferedConnection::Preferred, CurrentConnection::Fallback, false),
            ConnectionAdmission::ReplaceFallback
        );
        assert_eq!(
            connection_admission(OfferedConnection::Preferred, CurrentConnection::Preferred, false),
            ConnectionAdmission::Reject
        );
    }

    #[test]
    fn both_ends_classify_the_same_reverse_direction_connection_as_fallback() {
        let lower = NodeId::from_bytes([1; 32]);
        let higher = NodeId::from_bytes([2; 32]);
        assert_eq!(
            offered_connection(lower, higher, ConnectionOrigin::Outbound),
            OfferedConnection::Preferred
        );
        assert_eq!(
            offered_connection(higher, lower, ConnectionOrigin::Inbound),
            OfferedConnection::Preferred
        );
        assert_eq!(
            offered_connection(higher, lower, ConnectionOrigin::Outbound),
            OfferedConnection::Fallback
        );
        assert_eq!(
            offered_connection(lower, higher, ConnectionOrigin::Inbound),
            OfferedConnection::Fallback
        );
        assert_eq!(
            connection_admission(OfferedConnection::Fallback, CurrentConnection::None, false),
            ConnectionAdmission::Accept
        );
    }

    #[test]
    fn connection_preference_is_symmetric_and_independent_of_roles() {
        let lower = NodeId::from_bytes([1; 32]);
        let higher = NodeId::from_bytes([2; 32]);
        assert_eq!(
            offered_connection(lower, higher, ConnectionOrigin::Outbound),
            offered_connection(higher, lower, ConnectionOrigin::Inbound),
        );
        assert_eq!(
            offered_connection(lower, higher, ConnectionOrigin::Inbound),
            offered_connection(higher, lower, ConnectionOrigin::Outbound),
        );
    }

    #[test]
    fn capacity_is_enforced_without_changing_connection_preference() {
        let local = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        assert_eq!(
            offered_connection(local, peer, ConnectionOrigin::Inbound),
            OfferedConnection::Fallback
        );
        assert_eq!(
            offered_connection(local, peer, ConnectionOrigin::Outbound),
            OfferedConnection::Preferred
        );
        assert_eq!(
            connection_admission(OfferedConnection::Fallback, CurrentConnection::None, true),
            ConnectionAdmission::Reject
        );
    }

    #[test]
    fn both_ends_retain_a_live_reverse_direction_connection() -> Result<(), Box<dyn std::error::Error>> {
        crate::transport::build_runtime()?.block_on(async {
            let server_identity = crate::transport::TransportIdentity::generate()?;
            let server =
                quinn::Endpoint::server(server_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let client_identity = crate::transport::TransportIdentity::generate()?;
            let client =
                quinn::Endpoint::server(client_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let accepting = server.clone();
            let accepted = tokio::spawn(async move {
                accepting
                    .accept()
                    .await
                    .ok_or("server endpoint closed")?
                    .await
                    .map_err(|error| error.to_string())
            });
            let client_connection = tokio::time::timeout(
                Duration::from_secs(5),
                client.connect_with(
                    crate::transport::pinned_client_config(server_identity.key_id())?,
                    server.local_addr()?,
                    "supgang.invalid",
                )?,
            )
            .await??;
            let server_connection = accepted.await??;
            let root = RootIdentity::generate()?;
            let page = SyncPage {
                contacts: Vec::new(),
                reachability: Vec::new(),
                revocations: SignedRevocationList::empty(&root, 1)?,
            };
            let lower = NodeId::from_bytes([1; 32]);
            let higher = NodeId::from_bytes([2; 32]);
            let (lower_pages, _lower_page_receiver) = tokio::sync::watch::channel(page.clone());
            let (higher_pages, _higher_page_receiver) = tokio::sync::watch::channel(page);
            let (lower_events, _lower_event_receiver) = tokio::sync::mpsc::channel(4);
            let (higher_events, _higher_event_receiver) = tokio::sync::mpsc::channel(4);
            let mut lower_active = BTreeMap::new();
            let mut higher_active = BTreeMap::new();
            let mut lower_fallbacks = BTreeSet::new();
            let mut higher_fallbacks = BTreeSet::new();
            let mut lower_tasks = tokio::task::JoinSet::new();
            let mut higher_tasks = tokio::task::JoinSet::new();

            register_connection(
                server_connection.clone(),
                authorization()?,
                Capabilities::NONE,
                higher,
                ConnectionOrigin::Inbound,
                &mut PeerActorRegistry {
                    local: lower,
                    active: &mut lower_active,
                    noncanonical_outbound: &mut lower_fallbacks,
                    pages: &lower_pages,
                    events: &lower_events,
                    tasks: &mut lower_tasks,
                    interval: Duration::from_secs(30),
                    max_active_peers: 8,
                    update: None,
                },
            );
            register_connection(
                client_connection.clone(),
                authorization()?,
                Capabilities::NONE,
                lower,
                ConnectionOrigin::Outbound,
                &mut PeerActorRegistry {
                    local: higher,
                    active: &mut higher_active,
                    noncanonical_outbound: &mut higher_fallbacks,
                    pages: &higher_pages,
                    events: &higher_events,
                    tasks: &mut higher_tasks,
                    interval: Duration::from_secs(30),
                    max_active_peers: 8,
                    update: None,
                },
            );

            assert!(lower_active.contains_key(&higher));
            assert!(higher_active.contains_key(&lower));
            assert!(lower_fallbacks.contains(&higher));
            assert!(higher_fallbacks.contains(&lower));
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(server_connection.close_reason().is_none());
            assert!(client_connection.close_reason().is_none());

            server.close(0_u8.into(), b"test complete");
            client.close(0_u8.into(), b"test complete");
            lower_tasks.shutdown().await;
            higher_tasks.shutdown().await;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn reconciliation_failure_closes_the_transport_and_all_sibling_listeners() -> Result<(), Box<dyn std::error::Error>>
    {
        crate::transport::build_runtime()?.block_on(async {
            let server_identity = crate::transport::TransportIdentity::generate()?;
            let server =
                quinn::Endpoint::server(server_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let client_identity = crate::transport::TransportIdentity::generate()?;
            let client =
                quinn::Endpoint::server(client_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let accepting = server.clone();
            let accepted = tokio::spawn(async move {
                accepting
                    .accept()
                    .await
                    .ok_or("server endpoint closed")?
                    .await
                    .map_err(|error| error.to_string())
            });
            let client_connection = tokio::time::timeout(
                Duration::from_secs(5),
                client.connect_with(
                    crate::transport::pinned_client_config(server_identity.key_id())?,
                    server.local_addr()?,
                    "supgang.invalid",
                )?,
            )
            .await??;
            let server_connection = accepted.await??;
            let server_connection_id = server_connection.stable_id();
            let root = RootIdentity::generate()?;
            let page = SyncPage {
                contacts: Vec::new(),
                reachability: Vec::new(),
                revocations: SignedRevocationList::empty(&root, 1)?,
            };
            let (_page_sender, page_receiver) = tokio::sync::watch::channel(page);
            let (event_sender, mut event_receiver) = tokio::sync::mpsc::channel(4);
            let peer = NodeId::from_bytes([9; 32]);
            let mut actor_tasks = tokio::task::JoinSet::new();
            actor_tasks.spawn(supervise_connection(PeerActorContext {
                connection: server_connection,
                peer,
                initiator: false,
                pages: page_receiver,
                events: event_sender,
                interval: Duration::from_secs(30),
                update: None,
                authorization: authorization()?,
                tunnel_admission: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
                ended: std::sync::Arc::new(std::sync::OnceLock::new()),
            }));

            let (mut malformed, _receive) = client_connection.open_bi().await?;
            malformed.write_all(&0_u32.to_be_bytes()).await?;
            malformed.finish()?;
            tokio::time::timeout(Duration::from_secs(2), client_connection.closed()).await?;
            let closed_event = tokio::time::timeout(Duration::from_secs(2), event_receiver.recv())
                .await?
                .ok_or("closed event missing")?;
            assert!(matches!(
                closed_event,
                super::PeerEvent::Closed { peer: closed_peer, connection_id }
                    if closed_peer == peer && connection_id == server_connection_id
            ));
            tokio::time::timeout(Duration::from_secs(2), actor_tasks.join_next())
                .await?
                .ok_or("tracked connection task missing")??;
            server.close(0_u8.into(), b"test complete");
            client.close(0_u8.into(), b"test complete");
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn a_saturated_event_queue_cannot_retain_a_closed_connection_task() -> Result<(), Box<dyn std::error::Error>> {
        crate::transport::build_runtime()?.block_on(async {
            let (events, _receiver) = tokio::sync::mpsc::channel(1);
            let peer = NodeId::from_bytes([5; 32]);
            assert!(
                events
                    .try_send(super::PeerEvent::Closed { peer, connection_id: 1 })
                    .is_ok()
            );
            assert!(
                !send_closed_event(
                    &events,
                    super::PeerEvent::Closed { peer, connection_id: 2 },
                    Duration::from_millis(10),
                )
                .await
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }
}
