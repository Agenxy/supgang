//! Single-owner Supgang peer service with bounded retry and contact gossip.

use std::{collections::BTreeMap, io, net::SocketAddr, path::Path, time::Duration};

use quinn::{Connection, Endpoint};
use thiserror::Error;

use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate, MAX_CANDIDATES},
    contact::PeerContact,
    control::{self, ControlListener},
    ids::NodeId,
    peer_directory::{PeerDirectory, PeerDirectoryError},
    record::Capabilities,
    session,
    state::{self, LocalState, StateError},
    sync::{self, MAX_SYNC_CONTACTS, SyncPage},
    transport::{self, TransportError, TransportIdentity},
    transport_storage::{self, TransportStorageError},
};

mod local_control;

use local_control::{
    import_received, merge_and_broadcast_revocations, poll_control, process_peer_events, shutdown_receiver,
    spawn_revocation_listener, stop_if_requested,
};

/// Maximum candidates tried for one peer during one retry round.
pub const MAX_DIAL_CANDIDATES_PER_ROUND: usize = 4;
/// Full-handshake deadline for one address candidate.
pub const CONNECT_TIMEOUT_SECONDS: u64 = 4;
/// Mutual-authentication and one-page reconciliation deadline.
pub const SESSION_TIMEOUT_SECONDS: u64 = 12;
/// Default delay between peer retry rounds.
pub const DEFAULT_RETRY_SECONDS: u64 = 15;
/// Default signed endpoint lifetime.
pub const DEFAULT_RECORD_LIFETIME_SECONDS: u64 = 6 * 60 * 60;
/// Maximum long-lived authenticated neighbors retained by one service.
pub const MAX_ACTIVE_PEERS: usize = 8;
/// Maximum pending peer-actor events waiting for the single state owner.
pub const PEER_EVENT_QUEUE: usize = 32;
/// Maximum recent authenticated-peer reflexive observations advertised at once.
pub const MAX_REFLEXIVE_CANDIDATES: usize = 4;

/// Explicit service network policy. Nothing is discovered through a public dependency.
#[derive(Clone, Debug)]
pub struct ServiceConfig {
    /// Local UDP socket on which QUIC accepts connections.
    pub listen: SocketAddr,
    /// Addresses intentionally published in this device's signed record.
    pub candidates: Vec<EndpointCandidate>,
    /// Delay between bounded attempts to one remembered peer.
    pub retry_interval: Duration,
    /// Lifetime of each locally signed endpoint record.
    pub record_lifetime: Duration,
}

impl ServiceConfig {
    /// Creates a strict service configuration from explicit local and direct addresses.
    ///
    /// # Errors
    ///
    /// Rejects port zero, absent or excessive advertisements, invalid address
    /// scope, retry below one second, and record lifetime outside one hour to
    /// seven days.
    pub fn new(
        listen: SocketAddr,
        local_addresses: &[SocketAddr],
        direct_addresses: &[SocketAddr],
    ) -> Result<Self, ServiceError> {
        if listen.port() == 0 {
            return Err(ServiceError::InvalidConfiguration);
        }
        let count = local_addresses.len().saturating_add(direct_addresses.len());
        if count == 0 || count > MAX_CANDIDATES {
            return Err(ServiceError::InvalidConfiguration);
        }
        let mut candidates = Vec::with_capacity(count);
        for address in local_addresses {
            candidates.push(
                EndpointCandidate::new(CandidateKind::Local, CandidateTransport::QuicV1, *address)
                    .map_err(|_| ServiceError::InvalidConfiguration)?,
            );
        }
        for address in direct_addresses {
            candidates.push(
                EndpointCandidate::new(CandidateKind::Direct, CandidateTransport::QuicV1, *address)
                    .map_err(|_| ServiceError::InvalidConfiguration)?,
            );
        }
        candidates.sort_unstable();
        candidates.dedup();
        Ok(Self {
            listen,
            candidates,
            retry_interval: Duration::from_secs(DEFAULT_RETRY_SECONDS),
            record_lifetime: Duration::from_secs(DEFAULT_RECORD_LIFETIME_SECONDS),
        })
    }

    /// Replaces retry and record lifetimes after enforcing release bounds.
    ///
    /// # Errors
    ///
    /// Rejects retry below one second and record lifetimes outside one hour to
    /// seven days.
    pub fn with_intervals(mut self, retry: Duration, record_lifetime: Duration) -> Result<Self, ServiceError> {
        if retry < Duration::from_secs(1)
            || !(Duration::from_hours(1)..=Duration::from_hours(168)).contains(&record_lifetime)
        {
            return Err(ServiceError::InvalidConfiguration);
        }
        self.retry_interval = retry;
        self.record_lifetime = record_lifetime;
        Ok(self)
    }
}

/// A fatal service initialization or authoritative-state failure.
#[derive(Debug, Error)]
pub enum ServiceError {
    /// Service policy contains an unsafe or unsupported value.
    #[error("service configuration is invalid")]
    InvalidConfiguration,
    /// Protected authoritative state failed to open or update.
    #[error("service authoritative state failed validation")]
    State(#[from] StateError),
    /// Protected transport identity failed to load or initialize.
    #[error("service transport identity failed validation")]
    TransportStorage(#[from] TransportStorageError),
    /// QUIC/TLS configuration, runtime, or socket setup failed.
    #[error("service secure transport initialization failed")]
    Transport(#[from] TransportError),
    /// The durable peer cache failed to open.
    #[error("service peer directory failed validation")]
    PeerDirectory(#[from] PeerDirectoryError),
    /// The private local-control socket failed validation or setup.
    #[error("service local control failed validation")]
    Control(#[from] control::ControlError),
    /// The platform clock is invalid.
    #[error("system clock is before the UNIX epoch")]
    InvalidSystemTime,
    /// Operating-system termination handlers could not be installed.
    #[error("service shutdown signal handling failed")]
    Signal(#[source] io::Error),
    /// This device's stable identity is present in the current root revocation set.
    #[error("local device identity is revoked")]
    LocalRevoked,
    /// The caller's readiness notification failed after the socket bound.
    #[error("service readiness notification failed")]
    Readiness(#[source] io::Error),
}

/// Runs the service until the process receives an operating-system termination.
///
/// Per-peer network failures are expected and remain local retry state. Fatal
/// protected-state or configuration failures return to the caller.
///
/// # Errors
///
/// Returns only for fatal startup, clock, protected-state, or transport errors.
pub fn run(state_directory: impl AsRef<Path>, config: ServiceConfig) -> Result<(), ServiceError> {
    run_with_ready(state_directory, config, || Ok(()))
}

/// Runs the service and invokes `ready` only after protected state validates
/// and the UDP socket successfully binds.
///
/// # Errors
///
/// Returns fatal startup and service errors, including a failed readiness hook.
pub fn run_with_ready(
    state_directory: impl AsRef<Path>,
    config: ServiceConfig,
    ready: impl FnOnce() -> io::Result<()>,
) -> Result<(), ServiceError> {
    validate_config(&config)?;
    let mut local_state = state::open(state_directory.as_ref())?;
    if local_state
        .revocations()
        .contains(&local_state.identity().device.node_id())
    {
        return Err(ServiceError::LocalRevoked);
    }
    let transport_identity = transport_storage::load_or_create(state_directory.as_ref())?;
    let root_key = local_state.identity().root_verifying_key;
    let mut directory = PeerDirectory::open(
        state_directory.as_ref(),
        root_key,
        local_state.identity().device.node_id(),
        local_state.revocations(),
    )?;
    let runtime = transport::build_runtime()?;
    let control_listener = {
        let _runtime_guard = runtime.enter();
        ControlListener::bind(state_directory.as_ref())?
    };
    runtime.block_on(async {
        let endpoint =
            Endpoint::server(transport_identity.server_config()?, config.listen).map_err(TransportError::Endpoint)?;
        ready().map_err(ServiceError::Readiness)?;
        service_loop(
            endpoint,
            transport_identity,
            &control_listener,
            &mut local_state,
            &mut directory,
            config,
        )
        .await
    })
}

fn validate_config(config: &ServiceConfig) -> Result<(), ServiceError> {
    if config.listen.port() == 0
        || config.candidates.is_empty()
        || config.candidates.len() > MAX_CANDIDATES
        || config.retry_interval < Duration::from_secs(1)
        || !(Duration::from_hours(1)..=Duration::from_hours(168)).contains(&config.record_lifetime)
    {
        return Err(ServiceError::InvalidConfiguration);
    }
    Ok(())
}

async fn service_loop(
    endpoint: Endpoint,
    transport_identity: TransportIdentity,
    control_listener: &ControlListener,
    local_state: &mut LocalState,
    directory: &mut PeerDirectory,
    mut config: ServiceConfig,
) -> Result<(), ServiceError> {
    let mut local_contact = make_local_contact(local_state, &transport_identity, &config)?;
    if local_state
        .revocations()
        .contains(&local_state.identity().device.node_id())
    {
        return Err(ServiceError::LocalRevoked);
    }
    let mut dial_cursor = 0_usize;
    let mut gossip_cursor = 0_usize;
    let local_node = local_state.identity().device.node_id();
    let initial_page = gossip_page(
        &local_contact,
        directory,
        local_state.revocations(),
        unix_time()?,
        &mut gossip_cursor,
    );
    let (page_sender, _unused_page_receiver) = tokio::sync::watch::channel(initial_page);
    let (event_sender, mut event_receiver) = tokio::sync::mpsc::channel(PEER_EVENT_QUEUE);
    let mut active = BTreeMap::<NodeId, Connection>::new();
    let mut shutdown = shutdown_receiver()?;
    let mut next_dial = tokio::time::Instant::now() + initial_retry_delay(local_node, config.retry_interval);
    let refresh_delay = config.record_lifetime / 2;
    let mut next_refresh = tokio::time::Instant::now() + refresh_delay;

    loop {
        if stop_if_requested(&mut shutdown, &endpoint).await {
            return Ok(());
        }
        let mut directory_changed = process_peer_events(&mut event_receiver, &mut active, local_state, directory)?;
        let now = tokio::time::Instant::now();
        if now >= next_refresh {
            local_contact = make_local_contact(local_state, &transport_identity, &config)?;
            next_refresh = now + refresh_delay;
            directory_changed = true;
        }
        if directory_changed {
            let page = gossip_page(
                &local_contact,
                directory,
                local_state.revocations(),
                unix_time()?,
                &mut gossip_cursor,
            );
            page_sender.send_replace(page);
        }
        if now >= next_dial {
            let hints = directory
                .dial_hints()
                .into_iter()
                .filter(|contact| {
                    let peer = contact.endpoint.record.node_id;
                    local_node < peer && !active.contains_key(&peer)
                })
                .cloned()
                .collect::<Vec<_>>();
            if let Some(expected) = hints.get(dial_cursor % hints.len().max(1)).cloned() {
                dial_cursor = dial_cursor.wrapping_add(1);
                let page = page_sender.borrow().clone();
                if let Some((exchange, connection)) =
                    dial_peer(&endpoint, &local_contact, local_state, &expected, &page).await
                {
                    merge_and_broadcast_revocations(local_state, directory, &active, exchange.revocations, None)?;
                    if local_state.revocations().contains(&exchange.peer) {
                        connection.close(3_u8.into(), b"peer revoked");
                        next_dial = tokio::time::Instant::now() + config.retry_interval;
                        continue;
                    }
                    let _directory_changed = import_received(directory, exchange.contacts, unix_time()?)?;
                    if apply_reflexive_observation(&mut config, exchange.observed_local_address) {
                        local_contact = make_local_contact(local_state, &transport_identity, &config)?;
                    }
                    register_connection(
                        connection,
                        exchange.peer,
                        ConnectionOrigin::Outbound,
                        &mut PeerActorRegistry {
                            local: local_node,
                            active: &mut active,
                            pages: &page_sender,
                            events: &event_sender,
                            interval: config.retry_interval,
                        },
                    );
                    let page = gossip_page(
                        &local_contact,
                        directory,
                        local_state.revocations(),
                        unix_time()?,
                        &mut gossip_cursor,
                    );
                    page_sender.send_replace(page);
                }
            }
            next_dial = tokio::time::Instant::now() + config.retry_interval;
        }

        let until_dial = next_dial.saturating_duration_since(tokio::time::Instant::now());
        let until_refresh = next_refresh.saturating_duration_since(tokio::time::Instant::now());
        let wait = until_dial.min(until_refresh).min(Duration::from_secs(1));
        let control_wait = wait.min(Duration::from_millis(100));
        if poll_control(
            control_listener,
            control_wait,
            local_state,
            directory,
            &active,
            config.listen,
        )
        .await
        {
            let page = gossip_page(
                &local_contact,
                directory,
                local_state.revocations(),
                unix_time()?,
                &mut gossip_cursor,
            );
            page_sender.send_replace(page);
            continue;
        }
        let network_wait = wait.saturating_sub(control_wait);
        if let Ok(Some(incoming)) = tokio::time::timeout(network_wait, endpoint.accept()).await {
            if !incoming.remote_address_validated() && incoming.may_retry() {
                let _retry_result = incoming.retry();
                continue;
            }
            let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_secs(CONNECT_TIMEOUT_SECONDS), incoming).await
            else {
                continue;
            };
            let page = page_sender.borrow().clone();
            if let Ok(Ok(exchange)) = tokio::time::timeout(
                Duration::from_secs(SESSION_TIMEOUT_SECONDS),
                inbound_session(&connection, &local_contact, local_state, &page),
            )
            .await
            {
                merge_and_broadcast_revocations(local_state, directory, &active, exchange.revocations, None)?;
                if local_state.revocations().contains(&exchange.peer) {
                    connection.close(3_u8.into(), b"peer revoked");
                    continue;
                }
                let _directory_changed = import_received(directory, exchange.contacts, unix_time()?)?;
                if apply_reflexive_observation(&mut config, exchange.observed_local_address) {
                    local_contact = make_local_contact(local_state, &transport_identity, &config)?;
                }
                register_connection(
                    connection,
                    exchange.peer,
                    ConnectionOrigin::Inbound,
                    &mut PeerActorRegistry {
                        local: local_node,
                        active: &mut active,
                        pages: &page_sender,
                        events: &event_sender,
                        interval: config.retry_interval,
                    },
                );
                let page = gossip_page(
                    &local_contact,
                    directory,
                    local_state.revocations(),
                    unix_time()?,
                    &mut gossip_cursor,
                );
                page_sender.send_replace(page);
            } else {
                connection.close(1_u8.into(), b"authentication failed");
            }
        }
    }
}

fn make_local_contact(
    state: &mut LocalState,
    transport_identity: &TransportIdentity,
    config: &ServiceConfig,
) -> Result<PeerContact, ServiceError> {
    let now = unix_time()?;
    let membership = state.local_membership().cloned().ok_or(StateError::IdentityMismatch)?;
    let endpoint = state.sign_endpoint_record(
        transport_identity.key_id(),
        config.candidates.clone(),
        Capabilities::NONE,
        now,
        now.saturating_add(config.record_lifetime.as_secs()),
    )?;
    Ok(PeerContact { membership, endpoint })
}

fn gossip_page(
    local: &PeerContact,
    directory: &PeerDirectory,
    revocations: &crate::revocation::SignedRevocationList,
    now: u64,
    cursor: &mut usize,
) -> SyncPage {
    let peers = directory.usable_contacts(now);
    let mut page = Vec::with_capacity(MAX_SYNC_CONTACTS);
    page.push(local.clone());
    if peers.is_empty() {
        return SyncPage {
            contacts: page,
            revocations: revocations.clone(),
        };
    }
    for offset in 0..MAX_SYNC_CONTACTS.saturating_sub(1).min(peers.len()) {
        if let Some(contact) = peers.get(cursor.wrapping_add(offset) % peers.len()) {
            page.push((*contact).clone());
        }
    }
    *cursor = cursor.wrapping_add(MAX_SYNC_CONTACTS.saturating_sub(1));
    SyncPage {
        contacts: page,
        revocations: revocations.clone(),
    }
}

async fn dial_peer(
    endpoint: &Endpoint,
    local_contact: &PeerContact,
    local_state: &LocalState,
    expected: &PeerContact,
    page: &SyncPage,
) -> Option<(AuthenticatedExchange, Connection)> {
    for candidate in expected
        .endpoint
        .record
        .candidates
        .iter()
        .take(MAX_DIAL_CANDIDATES_PER_ROUND)
    {
        let client_config = transport::pinned_client_config(expected.endpoint.record.transport_key_id).ok()?;
        let Ok(connecting) = endpoint.connect_with(client_config, candidate.address(), "supgang.invalid") else {
            continue;
        };
        let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_secs(CONNECT_TIMEOUT_SECONDS), connecting).await
        else {
            continue;
        };
        let result = tokio::time::timeout(
            Duration::from_secs(SESSION_TIMEOUT_SECONDS),
            outbound_session(&connection, local_contact, local_state, expected, page),
        )
        .await;
        if let Ok(Ok(received)) = result {
            return Some((received, connection));
        }
        connection.close(1_u8.into(), b"authentication failed");
    }
    None
}

async fn outbound_session(
    connection: &Connection,
    local_contact: &PeerContact,
    local_state: &LocalState,
    expected: &PeerContact,
    page: &SyncPage,
) -> Result<AuthenticatedExchange, ()> {
    let authenticated = session::authenticate_outbound(
        connection,
        local_contact,
        &local_state.identity().device,
        expected,
        &local_state.identity().root_verifying_key,
        local_state.revocations(),
        unix_time().map_err(|_| ())?,
    )
    .await
    .map_err(|_| ())?;
    let synchronized = sync::exchange_outbound(connection, page).await.map_err(|_| ())?;
    synchronized
        .revocations
        .verify(&local_state.identity().root_verifying_key)
        .map_err(|_| ())?;
    let mut contacts = synchronized.contacts;
    let peer = authenticated.contact.endpoint.record.node_id;
    contacts.push(authenticated.contact);
    Ok(AuthenticatedExchange {
        peer,
        contacts,
        revocations: synchronized.revocations,
        observed_local_address: authenticated.observed_local_address,
    })
}

async fn inbound_session(
    connection: &Connection,
    local_contact: &PeerContact,
    local_state: &LocalState,
    page: &SyncPage,
) -> Result<AuthenticatedExchange, ()> {
    let authenticated = session::authenticate_inbound(
        connection,
        local_contact,
        &local_state.identity().device,
        &local_state.identity().root_verifying_key,
        local_state.revocations(),
        unix_time().map_err(|_| ())?,
    )
    .await
    .map_err(|_| ())?;
    let synchronized = sync::exchange_inbound(connection, page).await.map_err(|_| ())?;
    synchronized
        .revocations
        .verify(&local_state.identity().root_verifying_key)
        .map_err(|_| ())?;
    let mut contacts = synchronized.contacts;
    let peer = authenticated.contact.endpoint.record.node_id;
    contacts.push(authenticated.contact);
    Ok(AuthenticatedExchange {
        peer,
        contacts,
        revocations: synchronized.revocations,
        observed_local_address: authenticated.observed_local_address,
    })
}

struct AuthenticatedExchange {
    peer: NodeId,
    contacts: Vec<PeerContact>,
    revocations: crate::revocation::SignedRevocationList,
    observed_local_address: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionOrigin {
    Inbound,
    Outbound,
}

enum PeerEvent {
    Contacts {
        peer: NodeId,
        page: SyncPage,
    },
    Revocations {
        peer: NodeId,
        revocations: crate::revocation::SignedRevocationList,
    },
    Closed {
        peer: NodeId,
    },
}

struct PeerActorRegistry<'a> {
    local: NodeId,
    active: &'a mut BTreeMap<NodeId, Connection>,
    pages: &'a tokio::sync::watch::Sender<SyncPage>,
    events: &'a tokio::sync::mpsc::Sender<PeerEvent>,
    interval: Duration,
}

fn register_connection(
    connection: Connection,
    peer: NodeId,
    origin: ConnectionOrigin,
    registry: &mut PeerActorRegistry<'_>,
) {
    let preferred = matches!(origin, ConnectionOrigin::Outbound) == (registry.local < peer);
    if !preferred || registry.active.contains_key(&peer) || registry.active.len() >= MAX_ACTIVE_PEERS {
        connection.close(2_u8.into(), b"duplicate or neighbor limit");
        return;
    }
    registry.active.insert(peer, connection.clone());
    let page_receiver = registry.pages.subscribe();
    let event_sender = registry.events.clone();
    let notice_connection = connection.clone();
    tokio::spawn(peer_actor(
        connection,
        peer,
        registry.local < peer,
        page_receiver,
        event_sender,
        registry.interval,
    ));
    let notice_events = registry.events.clone();
    spawn_revocation_listener(notice_connection, peer, notice_events);
}

async fn peer_actor(
    connection: Connection,
    peer: NodeId,
    initiator: bool,
    pages: tokio::sync::watch::Receiver<SyncPage>,
    events: tokio::sync::mpsc::Sender<PeerEvent>,
    interval: Duration,
) {
    loop {
        if initiator {
            tokio::time::sleep(interval).await;
        }
        let page = pages.borrow().clone();
        let exchange = if initiator {
            tokio::time::timeout(
                Duration::from_secs(SESSION_TIMEOUT_SECONDS),
                sync::exchange_outbound(&connection, &page),
            )
            .await
        } else {
            tokio::time::timeout(
                interval
                    .saturating_mul(3)
                    .max(Duration::from_secs(SESSION_TIMEOUT_SECONDS)),
                sync::exchange_inbound(&connection, &page),
            )
            .await
        };
        let Ok(Ok(page)) = exchange else {
            break;
        };
        if events.send(PeerEvent::Contacts { peer, page }).await.is_err() {
            return;
        }
    }
    let _closed = events.send(PeerEvent::Closed { peer }).await;
}

fn apply_reflexive_observation(config: &mut ServiceConfig, address: SocketAddr) -> bool {
    let Ok(candidate) = EndpointCandidate::new(CandidateKind::Reflexive, CandidateTransport::QuicV1, address) else {
        return false;
    };
    if config.candidates.contains(&candidate) {
        return false;
    }
    let reflexive_count = config
        .candidates
        .iter()
        .filter(|existing| existing.kind() == CandidateKind::Reflexive)
        .count();
    if reflexive_count >= MAX_REFLEXIVE_CANDIDATES {
        if let Some(index) = config
            .candidates
            .iter()
            .position(|existing| existing.kind() == CandidateKind::Reflexive)
        {
            config.candidates.remove(index);
        }
    } else if config.candidates.len() >= MAX_CANDIDATES {
        return false;
    }
    config.candidates.push(candidate);
    config.candidates.sort_unstable();
    true
}

fn unix_time() -> Result<u64, ServiceError> {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ServiceError::InvalidSystemTime)
}

fn initial_retry_delay(node: NodeId, interval: Duration) -> Duration {
    let bytes = node.as_bytes();
    let seed = u16::from_be_bytes([bytes[0], bytes[1]]);
    let maximum_millis = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX).max(1);
    let minimum_millis = 250_u64.min(maximum_millis);
    let jitter_window = maximum_millis.saturating_sub(minimum_millis).max(1);
    Duration::from_millis(minimum_millis + (u64::from(seed) % jitter_window))
}

#[cfg(test)]
mod tests;
