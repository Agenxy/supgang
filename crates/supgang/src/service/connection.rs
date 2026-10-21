//! Bounded candidate racing and authenticated session exchange.

use std::{net::SocketAddr, time::Duration};

use quinn::{Connection, Endpoint};

use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
    contact::PeerContact,
    ids::NodeId,
    network, session, sync, transport,
};

use super::{CANDIDATE_RACE_DELAY_MILLIS, CONNECT_TIMEOUT_SECONDS, SESSION_TIMEOUT_SECONDS, SyncPage, unix_time};

pub(super) async fn dial_peer(
    endpoint: &Endpoint,
    authentication: &SessionAuthentication<'_>,
    candidates: &[(PeerContact, SocketAddr)],
    capped_address: Option<SocketAddr>,
) -> Option<(AuthenticatedExchange, Connection)> {
    let local_networks = network::interface_networks().unwrap_or_default();
    let candidates = candidates
        .iter()
        .filter(|(_, address)| network::address_is_route_compatible(*address, &local_networks))
        .map(|(expected, address)| (expected, *address))
        .take(network::MAX_DIAL_CANDIDATES_PER_ROUND)
        .collect::<Vec<_>>();
    dial_candidates(endpoint, authentication, &candidates, capped_address).await
}

pub(super) async fn dial_observed_peer(
    endpoint: &Endpoint,
    authentication: &SessionAuthentication<'_>,
    expected: &PeerContact,
    address: SocketAddr,
) -> Option<(AuthenticatedExchange, Connection)> {
    let transport = CandidateTransport::QuicV1;
    let candidate = EndpointCandidate::new(CandidateKind::Local, transport, address)
        .or_else(|_| EndpointCandidate::new(CandidateKind::Reflexive, transport, address))
        .ok()?;
    let local_networks = network::interface_networks().unwrap_or_default();
    if !network::candidate_is_route_compatible(&candidate, &local_networks) {
        return None;
    }
    dial_addresses(endpoint, authentication, expected, &[address]).await
}

async fn dial_addresses(
    endpoint: &Endpoint,
    authentication: &SessionAuthentication<'_>,
    expected: &PeerContact,
    addresses: &[SocketAddr],
) -> Option<(AuthenticatedExchange, Connection)> {
    let candidates = addresses
        .iter()
        .take(network::MAX_DIAL_CANDIDATES_PER_ROUND)
        .map(|address| (expected, *address))
        .collect::<Vec<_>>();
    dial_candidates(endpoint, authentication, &candidates, None).await
}

async fn dial_candidates(
    endpoint: &Endpoint,
    authentication: &SessionAuthentication<'_>,
    candidates: &[(&PeerContact, SocketAddr)],
    capped_address: Option<SocketAddr>,
) -> Option<(AuthenticatedExchange, Connection)> {
    let mut attempts = tokio::task::JoinSet::new();
    for (index, (expected, address)) in candidates
        .iter()
        .copied()
        .take(network::MAX_DIAL_CANDIDATES_PER_ROUND)
        .enumerate()
    {
        let endpoint = endpoint.clone();
        let cap_mtu = capped_address.is_some_and(|capped| {
            crate::candidate::canonical_socket_address(capped) == crate::candidate::canonical_socket_address(address)
        });
        let client_config =
            transport::pinned_client_config_with_mtu_cap(expected.endpoint.record.transport_key_id, cap_mtu).ok()?;
        attempts.spawn(async move {
            tokio::time::sleep(candidate_race_delay(index)).await;
            let connecting = endpoint.connect_with(client_config, address, "supgang.invalid").ok()?;
            let connection = tokio::time::timeout(Duration::from_secs(CONNECT_TIMEOUT_SECONDS), connecting)
                .await
                .ok()?
                .ok()?;
            Some((index, connection))
        });
    }
    while let Some(joined) = attempts.join_next().await {
        let Ok(Some((index, connection))) = joined else {
            continue;
        };
        let (expected, _) = candidates.get(index)?;
        let result = tokio::time::timeout(
            Duration::from_secs(SESSION_TIMEOUT_SECONDS),
            outbound_session(&connection, authentication, expected),
        )
        .await;
        if let Ok(Ok(exchange)) = result {
            attempts.abort_all();
            return Some((exchange, connection));
        }
        connection.close(1_u8.into(), b"authentication failed");
    }
    None
}

pub(super) const fn candidate_race_delay(index: usize) -> Duration {
    Duration::from_millis(CANDIDATE_RACE_DELAY_MILLIS.saturating_mul(index as u64))
}

async fn outbound_session(
    connection: &Connection,
    authentication: &SessionAuthentication<'_>,
    expected: &PeerContact,
) -> Result<AuthenticatedExchange, ()> {
    let authenticated = session::authenticate_outbound(
        connection,
        authentication.local_contact,
        authentication.device,
        expected,
        authentication.root_key,
        authentication.revocations,
        unix_time().map_err(|_| ())?,
    )
    .await
    .map_err(|_| ())?;
    let synchronized = sync::exchange_outbound(connection, authentication.page)
        .await
        .map_err(|_| ())?;
    synchronized
        .revocations
        .verify(authentication.root_key)
        .map_err(|_| ())?;
    let mut contacts = synchronized.contacts;
    let peer = authenticated.contact.endpoint.record.node_id;
    let capabilities = authenticated.contact.endpoint.record.capabilities;
    contacts.push(authenticated.contact);
    Ok(AuthenticatedExchange {
        peer,
        contacts,
        revocations: synchronized.revocations,
        authorization_expires_at: authenticated.authorization_expires_at,
        capabilities,
        reachability: synchronized.reachability,
        local_reachability: authenticated.local_reachability,
    })
}

pub(super) async fn inbound_session(
    connection: &Connection,
    authentication: &SessionAuthentication<'_>,
) -> Result<AuthenticatedExchange, ()> {
    let authenticated = session::authenticate_inbound(
        connection,
        authentication.local_contact,
        authentication.device,
        authentication.root_key,
        authentication.revocations,
        unix_time().map_err(|_| ())?,
    )
    .await
    .map_err(|_| ())?;
    let synchronized = sync::exchange_inbound(connection, authentication.page)
        .await
        .map_err(|_| ())?;
    synchronized
        .revocations
        .verify(authentication.root_key)
        .map_err(|_| ())?;
    let mut contacts = synchronized.contacts;
    let peer = authenticated.contact.endpoint.record.node_id;
    let capabilities = authenticated.contact.endpoint.record.capabilities;
    contacts.push(authenticated.contact);
    Ok(AuthenticatedExchange {
        peer,
        contacts,
        revocations: synchronized.revocations,
        authorization_expires_at: authenticated.authorization_expires_at,
        capabilities,
        reachability: synchronized.reachability,
        local_reachability: authenticated.local_reachability,
    })
}

pub(super) struct AuthenticatedExchange {
    pub(super) peer: NodeId,
    pub(super) contacts: Vec<PeerContact>,
    pub(super) revocations: crate::revocation::SignedRevocationList,
    pub(super) authorization_expires_at: u64,
    pub(super) capabilities: crate::record::Capabilities,
    pub(super) reachability: Vec<crate::reachability::ReachabilityClaim>,
    pub(super) local_reachability: crate::reachability::ReachabilityClaim,
}

pub(super) struct SessionAuthentication<'a> {
    pub(super) local_contact: &'a PeerContact,
    pub(super) device: &'a crate::identity::DeviceIdentity,
    pub(super) root_key: &'a ed25519_dalek::VerifyingKey,
    pub(super) revocations: &'a crate::revocation::SignedRevocationList,
    pub(super) page: &'a SyncPage,
}

#[cfg(test)]
mod tests;
