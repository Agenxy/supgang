//! Central authority retained with every live peer connection.

use std::{
    collections::BTreeMap,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use quinn::Connection;

use crate::{ids::NodeId, record::Capabilities, revocation::SignedRevocationList, state::LocalState};

/// Cloneable cancellation and expiry state shared by a connection's actors.
#[derive(Clone, Debug)]
pub struct SessionAuthorization {
    expires_at: Arc<AtomicU64>,
    invalidated: Arc<AtomicBool>,
    changed: Arc<tokio::sync::Notify>,
}

impl SessionAuthorization {
    pub fn new(expires_at: u64, now: u64) -> Option<Self> {
        (expires_at >= now).then(|| Self {
            expires_at: Arc::new(AtomicU64::new(expires_at)),
            invalidated: Arc::new(AtomicBool::new(false)),
            changed: Arc::new(tokio::sync::Notify::new()),
        })
    }

    pub fn is_current(&self, now: u64) -> bool {
        !self.invalidated.load(Ordering::Acquire) && self.expires_at.load(Ordering::Acquire) >= now
    }

    pub fn invalidate(&self) {
        if !self.invalidated.swap(true, Ordering::AcqRel) {
            self.changed.notify_waiters();
        }
    }

    fn renew(&self, expires_at: u64, now: u64) {
        if self.is_current(now) && expires_at > self.expires_at.fetch_max(expires_at, Ordering::AcqRel) {
            self.changed.notify_waiters();
        }
    }

    pub async fn wait_until_invalid(&self, now: u64) {
        if !self.is_current(now) {
            return;
        }
        let started = tokio::time::Instant::now();
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let current = now.saturating_add(started.elapsed().as_secs());
            if !self.is_current(current) {
                return;
            }
            let expiry = tokio::time::sleep(Duration::from_secs(
                self.expires_at
                    .load(Ordering::Acquire)
                    .saturating_sub(current)
                    .saturating_add(1),
            ));
            tokio::select! {
                () = expiry => {}
                () = changed => {}
            }
        }
    }
}

/// A QUIC connection that cannot outlive its authenticated authorization.
#[derive(Clone)]
pub(super) struct ActiveConnection {
    connection: Connection,
    authorization: SessionAuthorization,
    capabilities: Capabilities,
    authority_record: Option<(crate::ids::TransportKeyId, u64)>,
    /// The directly attached network the remote was on when this connection
    /// was made, if any: the LAN the path depends on.
    link: Option<crate::network::InterfaceNetwork>,
    pub(super) tunnel_admission: Arc<tokio::sync::Semaphore>,
    /// Why this service ended the connection, for the connection history.
    retired: Arc<std::sync::OnceLock<&'static [u8]>>,
}

impl ActiveConnection {
    pub(super) fn new(connection: Connection, authorization: SessionAuthorization, capabilities: Capabilities) -> Self {
        let remote = connection.remote_address().ip().to_canonical();
        let link = crate::network::interface_networks()
            .ok()
            .and_then(|networks| networks.into_iter().find(|network| network.contains(remote)));
        Self {
            connection,
            authorization,
            capabilities,
            authority_record: None,
            link,
            tunnel_admission: Arc::new(tokio::sync::Semaphore::new(4)),
            retired: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub(super) const fn bind_authority_record(&mut self, record: &crate::record::EndpointRecord) {
        self.authority_record = Some((record.transport_key_id, record.generation));
    }

    pub(super) fn renew_verified_record(&self, peer: NodeId, record: &crate::record::EndpointRecord, now: u64) {
        if record.node_id == peer && self.authority_record == Some((record.transport_key_id, record.generation)) {
            self.authorization.renew(record.expires_at, now);
        }
    }

    pub(super) fn with_tunnel_admission(mut self, admission: Arc<tokio::sync::Semaphore>) -> Self {
        self.tunnel_admission = admission;
        self
    }

    pub(super) const fn authorization(&self) -> &SessionAuthorization {
        &self.authorization
    }

    pub(super) fn invalidate(&self, reason: &'static [u8]) {
        let _first = self.retired.set(reason);
        self.authorization.invalidate();
        self.connection.close(3_u8.into(), reason);
    }

    /// The reason this service gave when it ended the connection, if it did.
    pub(super) fn retired_reason(&self) -> Option<&'static [u8]> {
        self.retired.get().copied()
    }

    pub(super) const fn connection(&self) -> &Connection {
        &self.connection
    }

    pub(super) const fn can_introduce(&self) -> bool {
        self.capabilities.contains(Capabilities::INTRODUCER)
    }
}

impl Deref for ActiveConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

pub(super) fn deauthorize_revoked(active: &mut BTreeMap<NodeId, ActiveConnection>, revocations: &SignedRevocationList) {
    let revoked = active
        .keys()
        .copied()
        .filter(|node_id| revocations.contains(node_id))
        .collect::<Vec<_>>();
    for node_id in revoked {
        if let Some(connection) = active.remove(&node_id) {
            connection.invalidate(b"peer revoked");
        }
    }
}

pub(super) fn source_is_authorized(
    active: &mut BTreeMap<NodeId, ActiveConnection>,
    local_state: &LocalState,
    peer: NodeId,
    connection_id: usize,
    now: u64,
) -> bool {
    let current = active.get(&peer).is_some_and(|connection| {
        connection.stable_id() == connection_id
            && connection.close_reason().is_none()
            && connection.authorization().is_current(now)
            && !local_state.revocations().contains(&peer)
    });
    if current {
        return true;
    }
    let must_remove = active
        .get(&peer)
        .is_some_and(|connection| connection.stable_id() == connection_id);
    if must_remove && let Some(connection) = active.remove(&peer) {
        connection.invalidate(b"peer authorization ended");
    }
    false
}

pub(super) fn prune_unauthorized(active: &mut BTreeMap<NodeId, ActiveConnection>, local_state: &LocalState, now: u64) {
    let ended = active
        .iter()
        .filter(|(peer, connection)| {
            connection.close_reason().is_some()
                || !connection.authorization().is_current(now)
                || local_state.revocations().contains(peer)
        })
        .map(|(peer, _)| *peer)
        .collect::<Vec<_>>();
    for peer in ended {
        if let Some(connection) = active.remove(&peer) {
            connection.invalidate(b"peer authorization ended");
        }
    }
}

pub(super) fn retire_unroutable(
    active: &mut BTreeMap<NodeId, ActiveConnection>,
    networks: &[crate::network::InterfaceNetwork],
) {
    active.retain(|_, connection| {
        let compatible = crate::network::address_is_route_compatible(connection.remote_address(), networks);
        if !compatible {
            connection.invalidate(b"network route changed");
            return false;
        }
        // A private remote stays routable through any default route, so a
        // connection made across a LAN this computer has left would otherwise
        // be reported live, and suppress redialing, until QUIC's idle timeout.
        // The LAN it was made on being gone is exact evidence. Paths through
        // a router or VPN were never on-link and are left to QUIC.
        let departed = connection.link.is_some_and(|link| !networks.contains(&link));
        if departed {
            connection.invalidate(b"local network left this computer");
        }
        !departed
    });
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

    use super::{ActiveConnection, SessionAuthorization, deauthorize_revoked, source_is_authorized};
    use crate::{
        identity::DeviceIdentity, membership::MembershipRoles, record::Capabilities, state,
        transport::TransportIdentity,
    };

    #[test]
    fn session_authority_requires_both_time_and_live_cancellation_state() -> Result<(), Box<dyn std::error::Error>> {
        let authorization = SessionAuthorization::new(100, 99).ok_or("fresh authorization missing")?;
        assert!(authorization.is_current(100));
        assert!(!authorization.is_current(101));
        authorization.invalidate();
        assert!(!authorization.is_current(99));
        assert!(SessionAuthorization::new(99, 100).is_none());
        Ok(())
    }

    #[test]
    fn renewal_extends_shared_authority_without_shortening_or_reviving_it() -> Result<(), Box<dyn std::error::Error>> {
        let authorization = SessionAuthorization::new(100, 99).ok_or("fresh authorization missing")?;
        let retained = authorization.clone();
        authorization.renew(200, 100);
        assert!(retained.is_current(200));
        authorization.renew(150, 101);
        assert!(retained.is_current(200));
        authorization.renew(300, 201);
        assert!(!retained.is_current(201));
        let authorization = SessionAuthorization::new(100, 99).ok_or("fresh authorization missing")?;
        authorization.invalidate();
        authorization.renew(300, 99);
        assert!(!authorization.is_current(99));
        Ok(())
    }

    #[tokio::test]
    async fn renewal_keeps_waiter_alive_past_original_expiry_then_revocation_wakes_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let authorization = SessionAuthorization::new(100, 100).ok_or("fresh authorization missing")?;
        let retained = authorization.clone();
        let waiter = tokio::spawn(async move { retained.wait_until_invalid(100).await });
        tokio::task::yield_now().await;
        authorization.renew(200, 100);
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert!(!waiter.is_finished());
        authorization.invalidate();
        tokio::time::timeout(Duration::from_secs(1), waiter).await??;
        Ok(())
    }

    #[test]
    fn revocation_removes_authority_before_the_connection_can_emit_more_work() -> Result<(), Box<dyn std::error::Error>>
    {
        crate::transport::build_runtime()?.block_on(async {
            let temporary = tempfile::tempdir()?;
            let mut local_state = state::initialize(temporary.path().join("state"))?;
            let peer = DeviceIdentity::generate()?;
            let issued_at = local_state.revocations().list.issued_at;
            local_state.issue_membership(
                &peer.verifying_key(),
                MembershipRoles::DEVICE,
                [7; 32],
                issued_at,
                issued_at.saturating_add(60),
            )?;

            let server_identity = TransportIdentity::generate()?;
            let server =
                quinn::Endpoint::server(server_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let client_identity = TransportIdentity::generate()?;
            let client =
                quinn::Endpoint::server(client_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let accepting = server.clone();
            let accepted = tokio::spawn(async move {
                accepting
                    .accept()
                    .await
                    .ok_or("server closed")?
                    .await
                    .map_err(|error| error.to_string())
            });
            let client_connection = client
                .connect_with(
                    crate::transport::pinned_client_config(server_identity.key_id())?,
                    server.local_addr()?,
                    "supgang.invalid",
                )?
                .await?;
            let connection = accepted.await??;
            let connection_id = connection.stable_id();
            let authorization = SessionAuthorization::new(issued_at.saturating_add(60), issued_at)
                .ok_or("fresh authorization missing")?;
            let retained_authorization = authorization.clone();
            let mut admitted = ActiveConnection::new(connection, authorization, Capabilities::NONE);
            let mut record = crate::record::EndpointRecord {
                protocol_version: crate::record::ENDPOINT_RECORD_VERSION,
                hive_id: local_state.identity().hive_id,
                node_id: peer.node_id(),
                display_name: Some(crate::profile::PeerName::new("peer")?),
                transport_key_id: client_identity.key_id(),
                generation: 1,
                sequence: 1,
                issued_at,
                expires_at: issued_at.saturating_add(60),
                candidates: Vec::new(),
                capabilities: Capabilities::NONE,
                services: Vec::new(),
            };
            admitted.bind_authority_record(&record);
            record.expires_at = issued_at.saturating_add(120);
            record.generation = 2;
            admitted.renew_verified_record(peer.node_id(), &record, issued_at);
            assert!(!retained_authorization.is_current(record.expires_at));
            record.generation = 1;
            record.transport_key_id = server_identity.key_id();
            admitted.renew_verified_record(peer.node_id(), &record, issued_at);
            assert!(!retained_authorization.is_current(record.expires_at));
            record.transport_key_id = client_identity.key_id();
            admitted.renew_verified_record(local_state.identity().device.node_id(), &record, issued_at);
            assert!(!retained_authorization.is_current(record.expires_at));
            admitted.renew_verified_record(peer.node_id(), &record, issued_at);
            assert!(retained_authorization.is_current(record.expires_at));
            let mut active = BTreeMap::from([(peer.node_id(), admitted)]);
            assert!(source_is_authorized(
                &mut active,
                &local_state,
                peer.node_id(),
                connection_id,
                issued_at,
            ));

            let revocations = local_state.revoke(peer.node_id(), issued_at.saturating_add(1))?;
            deauthorize_revoked(&mut active, &revocations);
            assert!(active.is_empty());
            assert!(!retained_authorization.is_current(issued_at));
            tokio::time::timeout(Duration::from_secs(2), client_connection.closed()).await?;
            server.close(0_u8.into(), b"test complete");
            client.close(0_u8.into(), b"test complete");
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }
}
