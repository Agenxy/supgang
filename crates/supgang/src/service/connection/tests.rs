//! Two real QUIC endpoints behind test-only outbound-required UDP filters.
//! Known addresses are supplied by the fixture; this is not address discovery.

use std::{sync::Arc, time::Duration};

use quinn::{Connection, Endpoint};

use super::{SessionAuthentication, dial_addresses, inbound_session, unix_time};
use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
    contact::PeerContact,
    identity::{DeviceIdentity, RootIdentity},
    membership::{MEMBERSHIP_VERSION, MembershipCertificate, MembershipRoles, SignedMembership},
    record::{Capabilities, ENDPOINT_RECORD_VERSION, EndpointRecord, SignedEndpointRecord},
    revocation::SignedRevocationList,
    sync::SyncPage,
    transport::{self, TransportIdentity},
};

mod filter;
mod liveness_cases;
mod nat_cases;
mod nat_lab;
use filter::FilteredSocket;

struct Peer {
    endpoint: Endpoint,
    device: DeviceIdentity,
    contact: PeerContact,
    page: SyncPage,
}

impl Peer {
    fn new(
        root: &RootIdentity,
        serial: u8,
        socket: Arc<dyn quinn::AsyncUdpSocket>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let device = DeviceIdentity::generate()?;
        let identity = TransportIdentity::generate()?;
        let endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(identity.server_config()?),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        let now = unix_time()?;
        let address = endpoint.local_addr()?;
        let membership = SignedMembership::sign(
            MembershipCertificate {
                version: MEMBERSHIP_VERSION,
                hive_id: root.hive_id(),
                node_id: device.node_id(),
                device_verifying_key: device.verifying_key().to_bytes(),
                serial: u64::from(serial),
                issued_at: now,
                expires_at: now + 3_600,
                roles: MembershipRoles::DEVICE,
                admission_nonce: [serial; 32],
            },
            root,
        )?;
        let endpoint_record = SignedEndpointRecord::sign(
            EndpointRecord {
                protocol_version: ENDPOINT_RECORD_VERSION,
                hive_id: root.hive_id(),
                node_id: device.node_id(),
                display_name: Some(crate::profile::PeerName::new("Test Peer")?),
                transport_key_id: identity.key_id(),
                generation: 0,
                sequence: 1,
                issued_at: now,
                expires_at: now + 3_600,
                candidates: vec![
                    EndpointCandidate::new(CandidateKind::Local, CandidateTransport::QuicV1, address).or_else(
                        |_| EndpointCandidate::new(CandidateKind::Direct, CandidateTransport::QuicV1, address),
                    )?,
                ],
                capabilities: Capabilities::NONE,
                services: Vec::new(),
            },
            &device,
        )?;
        let contact = PeerContact {
            membership,
            endpoint: endpoint_record,
        };
        let page = SyncPage {
            contacts: vec![contact.clone()],
            reachability: Vec::new(),
            revocations: SignedRevocationList::empty(root, now)?,
        };
        Ok(Self {
            endpoint,
            device,
            contact,
            page,
        })
    }

    fn authentication<'a>(&'a self, root: &'a ed25519_dalek::VerifyingKey) -> SessionAuthentication<'a> {
        SessionAuthentication {
            local_contact: &self.contact,
            device: &self.device,
            root_key: root,
            revocations: &self.page.revocations,
            page: &self.page,
        }
    }

    async fn accept(&self, root: &ed25519_dalek::VerifyingKey) -> Result<Connection, String> {
        let incoming = loop {
            let incoming = self.endpoint.accept().await.ok_or("endpoint closed")?;
            if incoming.remote_address_validated() {
                break incoming;
            }
            incoming.retry().map_err(|_| "retry failed")?;
        };
        let connection = incoming.await.map_err(|_| "handshake failed")?;
        let exchange = inbound_session(&connection, &self.authentication(root))
            .await
            .map_err(|()| "proof failed")?;
        assert_ne!(exchange.peer, self.device.node_id());
        Ok(connection)
    }
}

#[test]
fn two_peers_authenticate_without_a_relay_when_both_open_their_filter() -> Result<(), Box<dyn std::error::Error>> {
    transport::build_runtime()?.block_on(async {
        let root = RootIdentity::generate()?;
        let first_filter = FilteredSocket::new()?;
        let second_filter = FilteredSocket::new()?;
        let first = Peer::new(&root, 1, first_filter)?;
        let second = Peer::new(&root, 2, second_filter.clone())?;
        let key = root.verifying_key();
        let first_address = first.endpoint.local_addr()?;
        let second_address = second.endpoint.local_addr()?;

        // One-sided attempts cannot cross the recipient's filter.
        let blocked = first.endpoint.connect_with(
            transport::pinned_client_config(second.contact.endpoint.record.transport_key_id)?,
            second_address,
            "supgang.invalid",
        )?;
        assert!(tokio::time::timeout(Duration::from_millis(400), blocked).await.is_err());
        assert!(second_filter.dropped() > 0);

        // Both sides execute the production candidate dial + device proof + sync.
        let first_auth = first.authentication(&key);
        let second_auth = second.authentication(&key);
        let first_targets = [second_address];
        let second_targets = [first_address];
        let exchange = async {
            tokio::join!(
                dial_addresses(&first.endpoint, &first_auth, &second.contact, &first_targets),
                dial_addresses(&second.endpoint, &second_auth, &first.contact, &second_targets),
                first.accept(&key),
                second.accept(&key),
            )
        };
        let (first_result, second_result, first_inbound, second_inbound) =
            tokio::time::timeout(Duration::from_secs(12), exchange).await?;
        let (first_exchange, first_connection) = first_result.ok_or("first outbound did not authenticate")?;
        let (second_exchange, second_connection) = second_result.ok_or("second outbound did not authenticate")?;
        let first_inbound = first_inbound?;
        let second_inbound = second_inbound?;
        assert_eq!(first_exchange.peer, second.device.node_id());
        assert_eq!(second_exchange.peer, first.device.node_id());
        assert!(first_exchange.contacts.contains(&second.contact));
        assert!(second_exchange.contacts.contains(&first.contact));
        assert!(first_connection.close_reason().is_none());
        assert!(second_connection.close_reason().is_none());
        assert!(first_inbound.close_reason().is_none());
        assert!(second_inbound.close_reason().is_none());
        let now = unix_time()?;
        let authorization =
            super::super::active::SessionAuthorization::new(now + 60, now).ok_or("authorization missing")?;
        let mut active = std::collections::BTreeMap::from([(
            second.device.node_id(),
            super::super::active::ActiveConnection::new(
                first_connection.clone(),
                authorization.clone(),
                Capabilities::NONE,
            ),
        )]);
        let home = [crate::network::InterfaceNetwork::new(
            "127.0.0.1".parse()?,
            "255.0.0.0".parse()?,
        )];
        super::super::active::retire_unroutable(&mut active, &home);
        assert_eq!(active.len(), 1);
        assert!(authorization.is_current(now));
        let away = [crate::network::InterfaceNetwork::new(
            "10.0.0.2".parse()?,
            "255.255.255.0".parse()?,
        )];
        super::super::active::retire_unroutable(&mut active, &away);
        assert!(active.is_empty());
        assert!(!authorization.is_current(now));
        assert!(first_connection.close_reason().is_some());
        first.endpoint.close(0_u8.into(), b"test complete");
        second.endpoint.close(0_u8.into(), b"test complete");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
