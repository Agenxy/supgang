//! Authenticated introducer policy and bounded rendezvous event intake.

use std::{collections::BTreeMap, time::Duration};

use quinn::Connection;

use crate::{
    ids::NodeId,
    rendezvous::{self, RENDEZVOUS_ID_BYTES, RendezvousMessage},
};

use super::{PeerEvent, active::ActiveConnection};

/// An address offer accepted from one currently authenticated introducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RendezvousOfferEvent {
    pub(super) introducer: NodeId,
    pub(super) rendezvous_id: [u8; RENDEZVOUS_ID_BYTES],
    pub(super) target: NodeId,
    pub(super) address: std::net::SocketAddr,
}

const REQUEST_INTAKE_INTERVAL: Duration = Duration::from_secs(1);
const OFFER_INTAKE_INTERVAL: Duration = Duration::from_millis(250);
const FRAME_INTAKE_INTERVAL: Duration = Duration::from_millis(50);
const INTENT_LIFETIME: Duration = Duration::from_secs(30);
const MAX_PENDING_INTENTS: usize = 16;

/// Recently requested peers for which one observed-address offer may be used.
///
/// This makes an authenticated introducer useful without letting it turn an
/// idle member into a general-purpose packet source. An offer is useful only
/// after this device independently tried to recover the named peer, and that
/// permission is consumed by the first accepted offer.
pub(super) struct RendezvousIntents {
    targets: BTreeMap<NodeId, RendezvousIntent>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RendezvousIntent {
    target: NodeId,
    introducer: NodeId,
    connection_id: usize,
    rendezvous_id: [u8; RENDEZVOUS_ID_BYTES],
    expires_at: tokio::time::Instant,
}

impl RendezvousIntents {
    pub(super) const fn new() -> Self {
        Self {
            targets: BTreeMap::new(),
        }
    }

    pub(super) fn remember(&mut self, intent: RendezvousIntent, now: tokio::time::Instant) {
        self.prune(now);
        if self.targets.len() >= MAX_PENDING_INTENTS
            && !self.targets.contains_key(&intent.target)
            && let Some(oldest) = self
                .targets
                .iter()
                .min_by_key(|(_, intent)| intent.expires_at)
                .map(|(node, _)| *node)
        {
            self.targets.remove(&oldest);
        }
        self.targets.insert(intent.target, intent);
    }

    pub(super) fn take(
        &mut self,
        target: NodeId,
        introducer: NodeId,
        connection_id: usize,
        rendezvous_id: [u8; RENDEZVOUS_ID_BYTES],
        now: tokio::time::Instant,
    ) -> bool {
        self.prune(now);
        let matches = self.targets.get(&target).is_some_and(|intent| {
            intent.introducer == introducer
                && intent.connection_id == connection_id
                && intent.rendezvous_id == rendezvous_id
        });
        matches && self.targets.remove(&target).is_some()
    }

    fn prune(&mut self, now: tokio::time::Instant) {
        self.targets.retain(|_, intent| intent.expires_at > now);
    }
}

/// Listens only for unreliable traversal frames on one authenticated session.
///
/// Invalid, future-version, or excess datagrams are ignored. They cannot alter
/// durable state, and closing a valid session would make version skew a denial
/// primitive. The QUIC receive buffer and event queue provide hard memory bounds.
pub(super) async fn listener(connection: Connection, peer: NodeId, events: tokio::sync::mpsc::Sender<PeerEvent>) {
    let connection_id = connection.stable_id();
    let mut next_request = tokio::time::Instant::now();
    let mut next_offer = tokio::time::Instant::now();
    let mut next_frame = tokio::time::Instant::now();
    loop {
        let received = rendezvous::receive(&connection).await;
        let now = tokio::time::Instant::now();
        if now < next_frame {
            tokio::time::sleep_until(next_frame).await;
        }
        next_frame = tokio::time::Instant::now() + FRAME_INTAKE_INTERVAL;
        let Ok(message) = received else {
            if connection.close_reason().is_some() {
                return;
            }
            continue;
        };
        let now = tokio::time::Instant::now();
        let event = match message {
            RendezvousMessage::Request { rendezvous_id, target } if now >= next_request => {
                next_request = now + REQUEST_INTAKE_INTERVAL;
                PeerEvent::RendezvousRequest {
                    peer,
                    connection_id,
                    rendezvous_id,
                    target,
                }
            }
            RendezvousMessage::Offer {
                rendezvous_id,
                target,
                address,
            } if now >= next_offer => {
                next_offer = now + OFFER_INTAKE_INTERVAL;
                PeerEvent::RendezvousOffer {
                    peer,
                    connection_id,
                    rendezvous_id,
                    target,
                    address,
                }
            }
            RendezvousMessage::Request { .. } | RendezvousMessage::Offer { .. } => continue,
        };
        if events.try_send(event).is_err() && events.is_closed() {
            return;
        }
    }
}

/// Asks one rotating active member to introduce this device to `target`.
pub(super) fn request_introduction(
    active: &BTreeMap<NodeId, ActiveConnection>,
    target: NodeId,
    round: usize,
) -> Option<RendezvousIntent> {
    let introducers = active
        .iter()
        .filter(|(node, connection)| {
            **node != target && connection.close_reason().is_none() && connection.can_introduce()
        })
        .collect::<Vec<_>>();
    if introducers.is_empty() {
        return None;
    }
    let mut rendezvous_id = [0_u8; RENDEZVOUS_ID_BYTES];
    if getrandom::fill(&mut rendezvous_id).is_err() {
        return None;
    }
    let request = RendezvousMessage::Request { rendezvous_id, target };
    for offset in 0..introducers.len() {
        let index = round.wrapping_add(offset) % introducers.len();
        if introducers
            .get(index)
            .is_some_and(|(_, connection)| rendezvous::send(connection, &request).is_ok())
        {
            let Some((introducer, connection)) = introducers.get(index).copied() else {
                continue;
            };
            return Some(RendezvousIntent {
                target,
                introducer: *introducer,
                connection_id: connection.stable_id(),
                rendezvous_id,
                expires_at: tokio::time::Instant::now() + INTENT_LIFETIME,
            });
        }
    }
    None
}

/// Forwards symmetric offers only between two currently authenticated members.
pub(super) fn introduce_active_pair(
    active: &BTreeMap<NodeId, ActiveConnection>,
    requester: NodeId,
    rendezvous_id: [u8; RENDEZVOUS_ID_BYTES],
    target: NodeId,
) -> usize {
    if requester == target {
        return 0;
    }
    let Some(requester_connection) = active.get(&requester) else {
        return 0;
    };
    let Some(target_connection) = active.get(&target) else {
        return 0;
    };
    let to_requester = RendezvousMessage::Offer {
        rendezvous_id,
        target,
        address: target_connection.remote_address(),
    };
    let to_target = RendezvousMessage::Offer {
        rendezvous_id,
        target: requester,
        address: requester_connection.remote_address(),
    };
    usize::from(rendezvous::send(requester_connection, &to_requester).is_ok())
        + usize::from(rendezvous::send(target_connection, &to_target).is_ok())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

    use super::{
        MAX_PENDING_INTENTS, RendezvousIntent, RendezvousIntents, RendezvousOfferEvent, introduce_active_pair,
        request_introduction,
    };
    use crate::{
        ids::NodeId,
        record::Capabilities,
        service::active::{ActiveConnection, SessionAuthorization},
    };

    fn intent(target: NodeId, now: tokio::time::Instant) -> RendezvousIntent {
        RendezvousIntent {
            target,
            introducer: NodeId::from_bytes([5; 32]),
            connection_id: 7,
            rendezvous_id: [8; 16],
            expires_at: now + Duration::from_secs(30),
        }
    }

    #[test]
    fn offer_event_keeps_introducer_separate_from_target() {
        let event = RendezvousOfferEvent {
            introducer: NodeId::from_bytes([1; 32]),
            rendezvous_id: [2; 16],
            target: NodeId::from_bytes([3; 32]),
            address: std::net::SocketAddr::from(([198, 51, 100, 4], 44_330)),
        };
        assert_ne!(event.introducer, event.target);
    }

    #[test]
    fn address_offers_require_recent_single_use_local_intent() {
        let now = tokio::time::Instant::now();
        let target = NodeId::from_bytes([4; 32]);
        let expected = intent(target, now);
        let mut intents = RendezvousIntents::new();
        assert!(!intents.take(target, expected.introducer, 7, [8; 16], now));
        intents.remember(expected, now);
        assert!(!intents.take(target, NodeId::from_bytes([6; 32]), 7, [8; 16], now));
        assert!(!intents.take(target, expected.introducer, 9, [8; 16], now));
        assert!(!intents.take(target, expected.introducer, 7, [9; 16], now));
        assert!(intents.take(target, expected.introducer, 7, [8; 16], now));
        assert!(!intents.take(target, expected.introducer, 7, [8; 16], now));
        intents.remember(expected, now);
        assert!(!intents.take(target, expected.introducer, 7, [8; 16], now + Duration::from_secs(31),));
    }

    #[test]
    fn address_offer_intents_have_a_fixed_memory_ceiling() {
        let now = tokio::time::Instant::now();
        let mut intents = RendezvousIntents::new();
        for value in 0..=MAX_PENDING_INTENTS {
            intents.remember(
                intent(NodeId::from_bytes([u8::try_from(value).unwrap_or(u8::MAX); 32]), now),
                now,
            );
        }
        assert_eq!(intents.targets.len(), MAX_PENDING_INTENTS);
    }

    #[test]
    fn introducer_never_forwards_private_observed_addresses() -> Result<(), Box<dyn std::error::Error>> {
        crate::transport::build_runtime()?.block_on(async {
            let hub_identity = crate::transport::TransportIdentity::generate()?;
            let hub = quinn::Endpoint::server(hub_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let mut clients = Vec::new();
            let mut hub_connections = Vec::new();
            for _index in 0..2 {
                let client_identity = crate::transport::TransportIdentity::generate()?;
                let client =
                    quinn::Endpoint::server(client_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
                let accepting = hub.clone();
                let accepted = tokio::spawn(async move {
                    let incoming = accepting.accept().await.ok_or("hub endpoint closed")?;
                    incoming.await.map_err(|error| error.to_string())
                });
                let connection = tokio::time::timeout(
                    Duration::from_secs(5),
                    client.connect_with(
                        crate::transport::pinned_client_config(hub_identity.key_id())?,
                        hub.local_addr()?,
                        "supgang.invalid",
                    )?,
                )
                .await??;
                clients.push((client, connection));
                hub_connections.push(accepted.await??);
            }
            let requester = NodeId::from_bytes([1; 32]);
            let target = NodeId::from_bytes([2; 32]);
            let mut connected_clients = clients.into_iter();
            let (requester_endpoint, _requester_connection) =
                connected_clients.next().ok_or("requester client missing")?;
            let (target_endpoint, _target_connection) = connected_clients.next().ok_or("target client missing")?;
            let mut connected_hub = hub_connections.into_iter();
            let hub_requester = connected_hub.next().ok_or("requester hub connection missing")?;
            let hub_target = connected_hub.next().ok_or("target hub connection missing")?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                .as_secs();
            let authorization =
                || SessionAuthorization::new(now.saturating_add(60), now).ok_or("fresh authorization missing");
            let active = BTreeMap::from([
                (
                    requester,
                    ActiveConnection::new(hub_requester.clone(), authorization()?, Capabilities::NONE),
                ),
                (
                    target,
                    ActiveConnection::new(hub_target.clone(), authorization()?, Capabilities::NONE),
                ),
            ]);
            assert!(hub_requester.remote_address().ip().is_loopback());
            assert!(hub_target.remote_address().ip().is_loopback());
            assert!(request_introduction(&active, target, 0).is_none());
            assert_eq!(introduce_active_pair(&active, requester, [3; 16], target), 0);
            hub.close(0_u8.into(), b"test complete");
            requester_endpoint.close(0_u8.into(), b"test complete");
            target_endpoint.close(0_u8.into(), b"test complete");
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        Ok(())
    }
}
