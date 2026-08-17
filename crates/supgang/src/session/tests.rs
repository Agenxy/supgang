use std::net::{Ipv4Addr, SocketAddr};

use proptest::prelude::*;

use super::{
    authenticate_inbound, authenticate_outbound, decode_client_hello, decode_client_proof, decode_server_ack,
    decode_server_hello,
};
use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
    contact::PeerContact,
    identity::{DeviceIdentity, RootIdentity},
    membership::{MEMBERSHIP_VERSION, MembershipCertificate, MembershipRoles, SignedMembership},
    record::{Capabilities, ENDPOINT_RECORD_VERSION, EndpointRecord, SignedEndpointRecord},
    revocation::SignedRevocationList,
    sync::SyncPage,
    transport::{TransportIdentity, build_runtime, pinned_client_config},
};

fn contact(
    root: &RootIdentity,
    device: &DeviceIdentity,
    transport: &TransportIdentity,
    serial: u64,
    port: u16,
) -> Result<PeerContact, Box<dyn std::error::Error>> {
    let membership = SignedMembership::sign(
        MembershipCertificate {
            version: MEMBERSHIP_VERSION,
            hive_id: root.hive_id(),
            node_id: device.node_id(),
            device_verifying_key: device.verifying_key().to_bytes(),
            serial,
            issued_at: 10,
            expires_at: 1_000,
            roles: MembershipRoles::DEVICE,
            admission_nonce: [u8::try_from(serial)?; 32],
        },
        root,
    )?;
    let endpoint = SignedEndpointRecord::sign(
        EndpointRecord {
            protocol_version: ENDPOINT_RECORD_VERSION,
            hive_id: root.hive_id(),
            node_id: device.node_id(),
            transport_key_id: transport.key_id(),
            generation: 0,
            sequence: 1,
            issued_at: 20,
            expires_at: 100,
            candidates: vec![EndpointCandidate::new(
                CandidateKind::Local,
                CandidateTransport::QuicV1,
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            )?],
            capabilities: Capabilities::NONE,
        },
        device,
    )?;
    Ok(PeerContact { membership, endpoint })
}

#[test]
fn mutually_authenticates_devices_and_tls_channel() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = build_runtime()?;
    runtime.block_on(async {
        let root = RootIdentity::generate()?;
        let server_device = DeviceIdentity::generate()?;
        let client_device = DeviceIdentity::generate()?;
        let server_transport = TransportIdentity::generate()?;
        let client_transport = TransportIdentity::generate()?;
        let server = quinn::Endpoint::server(
            server_transport.server_config()?,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )?;
        let server_address = server.local_addr()?;
        let server_contact = contact(&root, &server_device, &server_transport, 1, server_address.port())?;
        let client_contact = contact(&root, &client_device, &client_transport, 2, 4_434)?;
        let revocations = SignedRevocationList::empty(&root, 10)?;
        let mut client = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let client_address = client.local_addr()?;
        client.set_default_client_config(pinned_client_config(server_transport.key_id())?);

        let server_contact_for_task = server_contact.clone();
        let root_key = root.verifying_key();
        let server_revocations = revocations.clone();
        let accepting_server = server.clone();
        let server_task = tokio::spawn(async move {
            let incoming = accepting_server.accept().await.ok_or("server endpoint closed")?;
            let connection = incoming.await.map_err(|error| error.to_string())?;
            let authenticated = authenticate_inbound(
                &connection,
                &server_contact_for_task,
                &server_device,
                &root_key,
                &server_revocations,
                50,
            )
            .await
            .map_err(|error| error.to_string())?;
            let page = SyncPage {
                contacts: vec![server_contact_for_task.clone()],
                revocations: server_revocations,
            };
            let synchronized = crate::sync::exchange_inbound(&connection, &page)
                .await
                .map_err(|error| error.to_string())?;
            Ok::<_, String>((authenticated, synchronized, connection))
        });
        let connection = client.connect(server_address, "supgang.invalid")?.await?;
        let authenticated_server = authenticate_outbound(
            &connection,
            &client_contact,
            &client_device,
            &server_contact,
            &root.verifying_key(),
            &revocations,
            50,
        )
        .await?;
        let client_page = SyncPage {
            contacts: vec![client_contact.clone()],
            revocations,
        };
        let synchronized = crate::sync::exchange_outbound(&connection, &client_page).await?;
        let (authenticated_client, server_synchronized, server_connection) = server_task.await??;
        assert_eq!(
            authenticated_server.contact.endpoint.record.node_id,
            server_contact.endpoint.record.node_id
        );
        assert_eq!(
            authenticated_client.contact.endpoint.record.node_id,
            client_contact.endpoint.record.node_id
        );
        assert_eq!(synchronized.contacts.as_slice(), std::slice::from_ref(&server_contact));
        assert_eq!(
            server_synchronized.contacts.as_slice(),
            std::slice::from_ref(&client_contact)
        );
        assert_eq!(authenticated_server.observed_local_address, client_address);
        assert_eq!(authenticated_client.observed_local_address, server_address);
        drop(server_connection);
        server.close(0_u8.into(), b"test complete");
        client.wait_idle().await;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

proptest! {
    #[test]
    fn arbitrary_authentication_messages_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..20_000)) {
        let _client_hello = decode_client_hello(&bytes);
        let _server_hello = decode_server_hello(&bytes);
        let _client_proof = decode_client_proof(&bytes);
        let _server_ack = decode_server_ack(&bytes);
    }
}
