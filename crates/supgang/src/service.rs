//! Single-owner Supgang peer service with bounded retry and contact gossip.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::SocketAddr,
    num::NonZeroU16,
    path::Path,
    sync::Arc,
    time::Duration,
};

use quinn::Endpoint;
use thiserror::Error;

use crate::{
    candidate::{EndpointCandidate, MAX_CANDIDATES},
    control::{self, ControlListener},
    ids::NodeId,
    peer_directory::{PeerDirectory, PeerDirectoryError},
    profile::PeerName,
    record::ServiceAdvert,
    router_mapping::{RouterMapping, RouterMappingStatus, shutdown as shutdown_router_mapping},
    settings::{DEFAULT_ADDRESS_HISTORY, MAX_ADDRESS_HISTORY, MIN_ADDRESS_HISTORY},
    state::{self, LocalState, StateError},
    sync::{self, SyncPage},
    transport::{self, TransportError, TransportIdentity},
    transport_storage::{self, TransportStorageError},
};

mod active;
mod admission;
mod config;
mod connection;
mod contact_state;
mod draining;
mod events;
mod gateway_reachability;
mod history;
mod interface_refresh;
mod live_session;
pub(crate) mod liveness;
mod local_control;
mod path_quality;
mod peer_actor;
mod rendezvous;
mod retry_schedule;
mod silence;
mod tunnel;
mod update_delivery;

use active::ActiveConnection;
pub(crate) use active::SessionAuthorization;
use admission::InboundAdmission;
use connection::{AuthenticatedExchange, SessionAuthentication, dial_observed_peer, dial_peer, inbound_session};
use contact_state::{gossip_page, make_local_contact};
use events::{PeerEvent, shutdown_receiver, stop_if_requested};
use gateway_reachability::replace_gateway_reachability;
use interface_refresh::{
    InterfaceRefreshHealth, RouterMappingUpdateBudget, bounded_automatic_interfaces, interface_addresses,
    refresh_service_candidates,
};
use live_session::{
    LiveSessionState, SessionTaskResult, finish_ready_sessions, schedule_remembered_peer, schedule_rendezvous_offers,
};
use local_control::{
    ControlActivity, ControlView, PeerEventState, import_received, import_received_reachability,
    merge_received_revocations, poll_control_or_incoming, process_peer_events, publish_gossip_if, revocation_listener,
};
use peer_actor::{PeerActorRegistry, PeerUpdateContext, reap_ready_tasks, register_connection};
use retry_schedule::{aligned_retry_delay, next_service_wait, retry_epoch, should_attempt_peer};
use update_delivery::UpdateDeliveryQueue;

#[cfg(test)]
use connection::candidate_race_delay;
#[cfg(test)]
use interface_refresh::replace_interface_candidates;

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
/// Maximum authenticated neighbors retained by an explicit always-on anchor.
pub const MAX_ANCHOR_PEERS: usize = 64;
/// Maximum pending peer-actor events waiting for the single state owner.
pub const PEER_EVENT_QUEUE: usize = 32;
/// Compatibility ceiling across the independently bounded session pools.
pub const MAX_PENDING_SESSIONS: usize = 18;
/// Maximum unauthenticated inbound handshakes allowed to run concurrently.
pub const MAX_PENDING_INBOUND_SESSIONS: usize = 8;
/// Reserved inbound lane for source networks already bound to verified peer history.
pub const MAX_PENDING_PRIORITY_INBOUND_SESSIONS: usize = 2;
/// Maximum authenticated-recovery handshakes allowed to run concurrently.
pub const MAX_PENDING_OUTBOUND_SESSIONS: usize = 8;
/// Stagger between ranked connection candidates in one bounded race.
pub const CANDIDATE_RACE_DELAY_MILLIS: u64 = 125;
/// Interval for detecting automatic local interface changes without polling a public service.
pub const AUTOMATIC_INTERFACE_REFRESH_SECONDS: u64 = 5;

/// Explicit service network policy. Nothing is discovered through a public dependency.
#[derive(Clone, Debug)]
pub struct ServiceConfig {
    /// Device-signed human label advertised with every endpoint refresh.
    pub display_name: PeerName,
    /// Local UDP socket on which QUIC accepts connections.
    pub listen: SocketAddr,
    /// Addresses intentionally published in this device's signed record.
    pub candidates: Vec<EndpointCandidate>,
    /// Services this computer advertises in that record, read from the
    /// profile when the service starts, as the name is.
    pub services: Vec<ServiceAdvert>,
    /// Delay between bounded attempts to one remembered peer.
    pub retry_interval: Duration,
    /// Lifetime of each locally signed endpoint record.
    pub record_lifetime: Duration,
    /// Number of historically signed peer addresses retained for recovery.
    pub address_history: usize,
    /// Whether active interface candidates are re-enumerated after network changes.
    pub automatic_interface_refresh: bool,
    /// Whether the local gateway maintains a renewable UDP mapping.
    pub automatic_router_mapping: bool,
    /// Maximum authenticated neighbors retained by this process.
    pub max_active_peers: usize,
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
    /// Owner renewal is required before this device can advertise again.
    #[error("this computer's membership has expired; renew it with the hive owner")]
    MembershipExpired,
    /// The caller's readiness notification failed after the socket bound.
    #[error("service readiness notification failed")]
    Readiness(#[source] io::Error),
    /// A bounded network-session worker panicked or was canceled unexpectedly.
    #[error("service network-session worker failed")]
    SessionTask(#[from] tokio::task::JoinError),
    /// Protected peer-update delivery state failed validation.
    #[error("service update-delivery state failed validation")]
    Update(#[from] crate::update::UpdateError),
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
    let policy =
        crate::tunnel_policy::load(state_directory.as_ref()).map_err(|_| ServiceError::InvalidConfiguration)?;
    config.clone().with_mapped_addresses(&policy.mapped)?;
    if local_state
        .revocations()
        .contains(&local_state.identity().device.node_id())
    {
        return Err(ServiceError::LocalRevoked);
    }
    let transport_identity = transport_storage::load_or_create(state_directory.as_ref())?;
    let root_key = local_state.identity().root_verifying_key;
    let mut directory = PeerDirectory::open_with_history_limit(
        state_directory.as_ref(),
        root_key,
        local_state.identity().device.node_id(),
        local_state.revocations(),
        config.address_history,
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
            state_directory.as_ref(),
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
        || !(1..=MAX_ANCHOR_PEERS).contains(&config.max_active_peers)
        || !(MIN_ADDRESS_HISTORY..=MAX_ADDRESS_HISTORY).contains(&config.address_history)
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
    state_directory: &Path,
    local_state: &mut LocalState,
    directory: &mut PeerDirectory,
    mut config: ServiceConfig,
) -> Result<(), ServiceError> {
    let capped_server_config = Arc::new(transport_identity.server_config_with_mtu_cap(true)?);
    let initial_tunnel_policy =
        crate::tunnel_policy::load(state_directory).map_err(|_| ServiceError::InvalidConfiguration)?;
    if !initial_tunnel_policy.mapped.is_empty() {
        config = config.with_mapped_addresses(&initial_tunnel_policy.mapped)?;
    }
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
    let hive_id = local_state.identity().hive_id;
    let initial_page = gossip_page(
        &local_contact,
        directory,
        local_state.revocations(),
        unix_time()?,
        &mut gossip_cursor,
    );
    let (page_sender, _unused_page_receiver) = tokio::sync::watch::channel(initial_page);
    let (event_sender, mut event_receiver) = tokio::sync::mpsc::channel(PEER_EVENT_QUEUE);
    let mut active = BTreeMap::<NodeId, ActiveConnection>::new();
    let mut draining = draining::DrainingConnections::default();
    let mut noncanonical_outbound = BTreeSet::<NodeId>::new();
    let mut rendezvous_intents = rendezvous::RendezvousIntents::new();
    let mut sync_mutation_budget = local_control::SyncMutationBudget::new();
    let network_identity = Arc::new(local_state.identity().device.duplicate_for_network_actor());
    let mut inbound_tasks = tokio::task::JoinSet::new();
    let mut priority_inbound_tasks = tokio::task::JoinSet::new();
    let mut outbound_tasks = tokio::task::JoinSet::new();
    let mut actor_tasks = tokio::task::JoinSet::new();
    let mut inbound_admission = InboundAdmission::new();
    let mut outbound_in_flight = false;
    let mut shutdown = shutdown_receiver()?;
    let mut instance_bytes = [0_u8; 16];
    getrandom::fill(&mut instance_bytes).map_err(|_| ServiceError::InvalidConfiguration)?;
    let instance_id = hex::encode(instance_bytes);
    let mut restart_requested = false;
    let mut next_dial =
        tokio::time::Instant::now() + aligned_retry_delay(hive_id, system_time_since_epoch()?, config.retry_interval);
    let refresh_delay = config.record_lifetime / 2;
    let mut next_refresh = tokio::time::Instant::now() + refresh_delay;
    let interface_refresh = Duration::from_secs(AUTOMATIC_INTERFACE_REFRESH_SECONDS);
    let mut next_interface_refresh = tokio::time::Instant::now() + interface_refresh;
    let mut router_mapping = NonZeroU16::new(config.listen.port())
        .filter(|_port| config.automatic_router_mapping)
        .map(RouterMapping::start);
    let mut router_mapping_budget = RouterMappingUpdateBudget::new(tokio::time::Instant::now());
    let mut interface_refresh_health = InterfaceRefreshHealth::new();
    let anchor_mode = config.max_active_peers > MAX_ACTIVE_PEERS;
    let mut update_context = PeerUpdateContext::new(state_directory, local_state.identity());
    let tunnels = tunnel::TunnelRuntime::new(state_directory).map_err(|_| ServiceError::InvalidConfiguration)?;
    update_context.tunnels = Some(tunnels.clone());
    let mut tunnel_tasks = tokio::task::JoinSet::new();
    let mut update_delivery = UpdateDeliveryQueue::open(state_directory, unix_time()?)?;
    let mut silence = silence::SilenceWatch::default();
    let mut path_quality = path_quality::PathQualityWatch::default();
    let mut history = history::ConnectionHistory::default();
    loop {
        if restart_requested || stop_if_requested(&mut shutdown, &endpoint).await {
            break;
        }
        let mut directory_changed = false;
        let now = tokio::time::Instant::now();
        draining.reap(local_state.revocations(), now);
        let wall_refresh = contact_state::needs_wall_clock_refresh(
            local_contact.endpoint.record.issued_at,
            local_contact.endpoint.record.expires_at,
            unix_time()?,
            refresh_delay.as_secs(),
        );
        if wall_refresh {
            next_interface_refresh = now;
            next_dial = now + aligned_retry_delay(hive_id, system_time_since_epoch()?, config.retry_interval);
        }
        let candidate_refresh = refresh_service_candidates(
            &mut router_mapping,
            &mut router_mapping_budget,
            now,
            &mut next_interface_refresh,
            interface_refresh,
            &mut config,
            &mut interface_refresh_health,
        );
        if let Some(status) = candidate_refresh.mapping_changed {
            directory_changed |= replace_gateway_reachability(local_state, directory, local_node, status)?;
        }
        directory_changed |= contact_state::refresh_contact_if_due(
            local_state,
            &transport_identity,
            &config,
            &mut local_contact,
            &mut next_refresh,
            (now, unix_time()?),
            candidate_refresh.interfaces_changed,
        )?;
        if candidate_refresh.interfaces_changed {
            live_session::reset_network_recovery(
                &mut active,
                &mut noncanonical_outbound,
                [&mut outbound_tasks, &mut inbound_tasks, &mut priority_inbound_tasks],
                &mut outbound_in_flight,
            )
            .await;
        }
        if silence.retire_departed(&mut active) {
            noncanonical_outbound.retain(|peer| active.contains_key(peer));
            next_dial = now;
        }
        silence.observe(&active);
        path_quality.observe(&active, now);
        history.observe(&active, unix_time()?);
        publish_gossip_if(
            directory_changed,
            &page_sender,
            &local_contact,
            directory,
            local_state,
            &mut gossip_cursor,
        )?;
        let mut rendezvous_offers = Vec::new();
        let directory_changed = process_peer_events(
            &mut event_receiver,
            PeerEventState {
                active: &mut active,
                draining: &mut draining,
                noncanonical_outbound: &mut noncanonical_outbound,
                local_state,
                directory,
                rendezvous_offers: &mut rendezvous_offers,
                rendezvous_intents: &mut rendezvous_intents,
                sync_budget: &mut sync_mutation_budget,
            },
        )?;
        reap_ready_tasks(&mut actor_tasks)?;
        reap_ready_tasks(&mut tunnel_tasks)?;
        let mut unused_outbound_slot = false;
        finish_ready_sessions(
            &mut priority_inbound_tasks,
            &mut unused_outbound_slot,
            &mut LiveSessionState {
                update: Some(&update_context),
                local_node,
                local_state,
                directory,
                config: &mut config,
                local_contact: &mut local_contact,
                active: &mut active,
                draining: &mut draining,
                noncanonical_outbound: &mut noncanonical_outbound,
                page_sender: &page_sender,
                event_sender: &event_sender,
                actor_tasks: &mut actor_tasks,
                gossip_cursor: &mut gossip_cursor,
            },
        )?;
        finish_ready_sessions(
            &mut inbound_tasks,
            &mut unused_outbound_slot,
            &mut LiveSessionState {
                update: Some(&update_context),
                local_node,
                local_state,
                directory,
                config: &mut config,
                local_contact: &mut local_contact,
                active: &mut active,
                draining: &mut draining,
                noncanonical_outbound: &mut noncanonical_outbound,
                page_sender: &page_sender,
                event_sender: &event_sender,
                actor_tasks: &mut actor_tasks,
                gossip_cursor: &mut gossip_cursor,
            },
        )?;
        update_delivery.drive(
            state_directory,
            &update_context.admission,
            local_state,
            &active,
            unix_time()?,
        )?;
        finish_ready_sessions(
            &mut outbound_tasks,
            &mut outbound_in_flight,
            &mut LiveSessionState {
                update: Some(&update_context),
                local_node,
                local_state,
                directory,
                config: &mut config,
                local_contact: &mut local_contact,
                active: &mut active,
                draining: &mut draining,
                noncanonical_outbound: &mut noncanonical_outbound,
                page_sender: &page_sender,
                event_sender: &event_sender,
                actor_tasks: &mut actor_tasks,
                gossip_cursor: &mut gossip_cursor,
            },
        )?;
        rendezvous_offers.truncate(MAX_PENDING_OUTBOUND_SESSIONS.saturating_sub(outbound_tasks.len()));
        schedule_rendezvous_offers(
            &endpoint,
            rendezvous_offers,
            &network_identity,
            &mut outbound_tasks,
            &LiveSessionState {
                update: Some(&update_context),
                local_node,
                local_state,
                directory,
                config: &mut config,
                local_contact: &mut local_contact,
                active: &mut active,
                draining: &mut draining,
                noncanonical_outbound: &mut noncanonical_outbound,
                page_sender: &page_sender,
                event_sender: &event_sender,
                actor_tasks: &mut actor_tasks,
                gossip_cursor: &mut gossip_cursor,
            },
        );
        publish_gossip_if(
            directory_changed,
            &page_sender,
            &local_contact,
            directory,
            local_state,
            &mut gossip_cursor,
        )?;
        let now = tokio::time::Instant::now();
        // Anchors must participate in outbound recovery too. Besides recovering
        // through an open peer firewall, synchronized outbound rounds are the
        // only sovereign chance of crossing compatible NATs without a relay.
        if now >= next_dial && !outbound_in_flight {
            let retry_round = retry_epoch(system_time_since_epoch()?, config.retry_interval);
            if outbound_tasks.len() < MAX_PENDING_OUTBOUND_SESSIONS
                && let Some(scheduled) = schedule_remembered_peer(
                    &endpoint,
                    &mut dial_cursor,
                    &mut path_quality,
                    &network_identity,
                    &mut outbound_tasks,
                    &LiveSessionState {
                        update: Some(&update_context),
                        local_node,
                        local_state,
                        directory,
                        config: &mut config,
                        local_contact: &mut local_contact,
                        active: &mut active,
                        draining: &mut draining,
                        noncanonical_outbound: &mut noncanonical_outbound,
                        page_sender: &page_sender,
                        event_sender: &event_sender,
                        actor_tasks: &mut actor_tasks,
                        gossip_cursor: &mut gossip_cursor,
                    },
                )
            {
                outbound_in_flight = scheduled.direct_started;
                if let Some(intent) = rendezvous::request_introduction(&active, scheduled.target, retry_round) {
                    rendezvous_intents.remember(intent, tokio::time::Instant::now());
                }
            }
            next_dial = tokio::time::Instant::now()
                + aligned_retry_delay(hive_id, system_time_since_epoch()?, config.retry_interval);
        }

        let wait = draining.bound_wait(next_service_wait(
            outbound_in_flight,
            next_dial,
            next_refresh,
            config.automatic_interface_refresh.then_some(next_interface_refresh),
        ));
        let activity = poll_control_or_incoming(
            control_listener,
            endpoint.accept(),
            wait,
            local_state,
            directory,
            &mut active,
            ControlView {
                draining: &mut draining,
                instance_id: &instance_id,
                restart_requested: &mut restart_requested,
                state_directory: &update_context.state_directory,
                update_delivery: &mut update_delivery,
                listen: config.listen,
                local_contact: &mut local_contact,
                router_mapping: router_mapping
                    .as_ref()
                    .map_or(RouterMappingStatus::Disabled, RouterMapping::status),
                anchor_mode,
                tunnels: &tunnels,
                tunnel_tasks: &mut tunnel_tasks,
                recent_connections: history.events(),
                config: &mut config,
                transport_identity: &transport_identity,
            },
        )
        .await?;
        let incoming = match activity {
            ControlActivity::Control(control_changed) => {
                publish_gossip_if(
                    control_changed,
                    &page_sender,
                    &local_contact,
                    directory,
                    local_state,
                    &mut gossip_cursor,
                )?;
                None
            }
            ControlActivity::Incoming(incoming) => incoming,
        };
        if let Some(incoming) = incoming {
            let incoming_mtu_cap = path_quality
                .capped_source(incoming.remote_address())
                .then(|| Arc::clone(&capped_server_config));
            admission::schedule_admitted_incoming(
                incoming,
                incoming_mtu_cap,
                &mut inbound_admission,
                &network_identity,
                &mut inbound_tasks,
                &mut priority_inbound_tasks,
                &LiveSessionState {
                    update: Some(&update_context),
                    local_node,
                    local_state,
                    directory,
                    config: &mut config,
                    local_contact: &mut local_contact,
                    active: &mut active,
                    draining: &mut draining,
                    noncanonical_outbound: &mut noncanonical_outbound,
                    page_sender: &page_sender,
                    event_sender: &event_sender,
                    actor_tasks: &mut actor_tasks,
                    gossip_cursor: &mut gossip_cursor,
                },
            );
        }
    }
    endpoint.close(0_u8.into(), b"service handoff");
    inbound_tasks.shutdown().await;
    priority_inbound_tasks.shutdown().await;
    outbound_tasks.shutdown().await;
    actor_tasks.shutdown().await;
    shutdown_router_mapping(&mut router_mapping).await;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionOrigin {
    Inbound,
    Outbound,
}

fn unix_time() -> Result<u64, ServiceError> {
    system_time_since_epoch().map(|duration| duration.as_secs())
}

fn system_time_since_epoch() -> Result<Duration, ServiceError> {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|_| ServiceError::InvalidSystemTime)
}

#[cfg(test)]
mod tests;
