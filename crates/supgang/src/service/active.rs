//! Central authority retained with every live peer connection.

use std::{
    collections::BTreeMap,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use quinn::Connection;

use crate::{ids::NodeId, record::Capabilities, revocation::SignedRevocationList, state::LocalState};

/// Cloneable cancellation and expiry state shared by a connection's actors.
#[derive(Clone, Debug)]
pub struct SessionAuthorization {
    expires_at: u64,
    invalidated: Arc<AtomicBool>,
    changed: Arc<tokio::sync::Notify>,
}

impl SessionAuthorization {
    pub fn new(expires_at: u64, now: u64) -> Option<Self> {
        (expires_at >= now).then(|| Self {
            expires_at,
            invalidated: Arc::new(AtomicBool::new(false)),
            changed: Arc::new(tokio::sync::Notify::new()),
        })
    }

    pub fn is_current(&self, now: u64) -> bool {
        !self.invalidated.load(Ordering::Acquire) && self.expires_at >= now
    }

    pub fn invalidate(&self) {
        if !self.invalidated.swap(true, Ordering::AcqRel) {
            self.changed.notify_waiters();
        }
    }

    pub async fn wait_until_invalid(&self, now: u64) {
        if !self.is_current(now) {
            return;
        }
        let expiry = tokio::time::sleep(Duration::from_secs(
            self.expires_at.saturating_sub(now).saturating_add(1),
        ));
        tokio::pin!(expiry);
        loop {
            let changed = self.changed.notified();
            if !self.is_current(now) {
                return;
            }
            tokio::select! {
                () = &mut expiry => return,
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
}

impl ActiveConnection {
    pub(super) const fn new(
        connection: Connection,
        authorization: SessionAuthorization,
        capabilities: Capabilities,
    ) -> Self {
        Self {
            connection,
            authorization,
            capabilities,
        }
    }

    pub(super) const fn authorization(&self) -> &SessionAuthorization {
        &self.authorization
    }

    pub(super) fn invalidate(&self, reason: &'static [u8]) {
        self.authorization.invalidate();
        self.connection.close(3_u8.into(), reason);
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
            let mut active = BTreeMap::from([(
                peer.node_id(),
                ActiveConnection::new(connection, authorization, Capabilities::NONE),
            )]);
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
