//! These sockets never send traffic to the actual public Internet.
//! Public tuples are fixtures, not endpoints discovered by this experiment.

use std::{sync::Arc, time::Duration};

use super::{
    Peer, RootIdentity, dial_addresses,
    nat_lab::{NatLab, Policy},
    transport,
};

#[test]
fn translated_ipv4_peers_authenticate_with_known_tuples_and_bilateral_sends() -> Result<(), Box<dyn std::error::Error>>
{
    transport::build_runtime()?.block_on(async {
        let lab = Arc::new(NatLab::default());
        let root = RootIdentity::generate()?;
        let key = root.verifying_key();
        let first_address = "8.8.8.8:51001".parse()?;
        let second_address = "9.9.9.9:52002".parse()?;
        let first = Peer::new(
            &root,
            1,
            lab.socket("10.0.0.2:44330".parse()?, first_address, Policy::Restricted)?,
        )?;
        let second = Peer::new(
            &root,
            2,
            lab.socket("10.1.0.2:44330".parse()?, second_address, Policy::Restricted)?,
        )?;
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
            tokio::time::timeout(Duration::from_secs(5), exchange).await?;
        let (first_exchange, first_connection) = first_result.ok_or("first translation failed")?;
        let (second_exchange, second_connection) = second_result.ok_or("second translation failed")?;
        assert_eq!(first_exchange.peer, second.device.node_id());
        assert_eq!(second_exchange.peer, first.device.node_id());
        // The peer reports the translated socket, never the private host tuple.
        assert_eq!(first_exchange.local_reachability.address, first_address);
        assert_eq!(second_exchange.local_reachability.address, second_address);
        assert_eq!(first_connection.remote_address(), second_address);
        assert_eq!(second_connection.remote_address(), first_address);
        assert!(first_inbound?.close_reason().is_none());
        assert!(second_inbound?.close_reason().is_none());
        first.endpoint.close(0_u8.into(), b"test complete");
        second.endpoint.close(0_u8.into(), b"test complete");
        Ok(())
    })
}

#[test]
fn translated_ipv4_client_recovers_by_dialing_a_known_public_peer() -> Result<(), Box<dyn std::error::Error>> {
    transport::build_runtime()?.block_on(async {
        let lab = Arc::new(NatLab::default());
        let root = RootIdentity::generate()?;
        let key = root.verifying_key();
        let public = "9.9.9.9:44330".parse()?;
        let external = "8.8.8.8:56000".parse()?;
        let client = Peer::new(
            &root,
            1,
            lab.socket("10.0.0.2:44330".parse()?, external, Policy::Restricted)?,
        )?;
        let server = Peer::new(&root, 2, lab.socket(public, public, Policy::Public)?)?;
        let auth = client.authentication(&key);
        let targets = [public];
        let exchange = async {
            tokio::join!(
                dial_addresses(&client.endpoint, &auth, &server.contact, &targets),
                server.accept(&key)
            )
        };
        let (result, inbound) = tokio::time::timeout(Duration::from_secs(5), exchange).await?;
        let (observed, connection) = result.ok_or("outbound translation failed")?;
        assert_eq!(observed.local_reachability.address, external);
        assert_eq!(observed.peer, server.device.node_id());
        assert_eq!(inbound?.remote_address(), external);
        assert!(connection.close_reason().is_none());
        client.endpoint.close(0_u8.into(), b"test complete");
        server.endpoint.close(0_u8.into(), b"test complete");
        Ok(())
    })
}

#[test]
fn stale_mappings_and_blocked_udp_do_not_produce_false_success() -> Result<(), Box<dyn std::error::Error>> {
    transport::build_runtime()?.block_on(async {
        for policy in [Policy::Restricted, Policy::Blocked] {
            let lab = Arc::new(NatLab::default());
            let root = RootIdentity::generate()?;
            let key = root.verifying_key();
            let first = Peer::new(
                &root,
                1,
                lab.socket("10.0.0.2:44330".parse()?, "8.8.8.8:51001".parse()?, policy)?,
            )?;
            let second = Peer::new(
                &root,
                2,
                lab.socket("10.1.0.2:44330".parse()?, "9.9.9.9:52002".parse()?, policy)?,
            )?;
            let first_auth = first.authentication(&key);
            let second_auth = second.authentication(&key);
            // The actual ports were reassigned. No participant tells the peers the new tuples.
            let first_targets = [if matches!(policy, Policy::Blocked) {
                "9.9.9.9:52002".parse()?
            } else {
                "9.9.9.9:52000".parse()?
            }];
            let second_targets = [if matches!(policy, Policy::Blocked) {
                "8.8.8.8:51001".parse()?
            } else {
                "8.8.8.8:51000".parse()?
            }];
            let exchange = async {
                tokio::select! {
                    result = dial_addresses(&first.endpoint, &first_auth, &second.contact, &first_targets) => {
                        assert!(result.is_none());
                    }
                    result = dial_addresses(&second.endpoint, &second_auth, &first.contact, &second_targets) => {
                        assert!(result.is_none());
                    }
                    result = first.accept(&key) => assert!(result.is_err()),
                    result = second.accept(&key) => assert!(result.is_err()),
                }
            };
            assert!(
                tokio::time::timeout(Duration::from_millis(700), exchange)
                    .await
                    .is_err()
            );
            first.endpoint.close(0_u8.into(), b"test complete");
            second.endpoint.close(0_u8.into(), b"test complete");
        }
        Ok(())
    })
}

#[test]
fn dual_stack_dialer_reaches_ipv4_without_waiting_for_an_ipv6_batch_to_fail() -> Result<(), Box<dyn std::error::Error>>
{
    transport::build_runtime()?.block_on(async {
        let lab = Arc::new(NatLab::default());
        let root = RootIdentity::generate()?;
        let key = root.verifying_key();
        let public = "9.9.9.9:44330".parse()?;
        let client = Peer::new(
            &root,
            1,
            lab.socket("[fd00::1]:44330".parse()?, "8.8.8.8:56000".parse()?, Policy::Restricted)?,
        )?;
        let server = Peer::new(&root, 2, lab.socket(public, public, Policy::Public)?)?;
        let auth = client.authentication(&key);
        let mut targets = (1..=7)
            .map(|port| std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)))
            .collect::<Vec<_>>();
        targets.push(public);
        let targets = super::super::super::retry_schedule::candidate_batch(&targets, 0);
        let mut historical = server.contact.clone();
        let mut old_record = historical.endpoint.record.clone();
        old_record.transport_key_id = crate::transport::TransportIdentity::generate()?.key_id();
        historical.endpoint = crate::record::SignedEndpointRecord::sign(old_record, &server.device)?;
        let candidates = targets
            .iter()
            .map(|address| {
                let expected = if address.is_ipv4() {
                    &server.contact
                } else {
                    &historical
                };
                (expected, *address)
            })
            .collect::<Vec<_>>();
        let exchange = async {
            tokio::join!(
                super::super::dial_candidates(&client.endpoint, &auth, &candidates, None),
                server.accept(&key)
            )
        };
        let (result, inbound) = tokio::time::timeout(Duration::from_secs(3), exchange).await?;
        let (observed, connection) = result.ok_or("IPv4 fallback did not authenticate")?;
        assert_eq!(observed.peer, server.device.node_id());
        assert_eq!(
            crate::candidate::canonical_socket_address(connection.remote_address()),
            public
        );
        assert!(inbound?.close_reason().is_none());
        client.endpoint.close(0_u8.into(), b"test complete");
        server.endpoint.close(0_u8.into(), b"test complete");
        Ok(())
    })
}

#[test]
fn candidate_specific_transport_pin_does_not_replace_expected_device_identity() -> Result<(), Box<dyn std::error::Error>>
{
    transport::build_runtime()?.block_on(async {
        let lab = Arc::new(NatLab::default());
        let root = RootIdentity::generate()?;
        let key = root.verifying_key();
        let public = "9.9.9.9:44330".parse()?;
        let client = Peer::new(
            &root,
            1,
            lab.socket("10.0.0.2:44330".parse()?, "8.8.8.8:56000".parse()?, Policy::Restricted)?,
        )?;
        let server = Peer::new(&root, 2, lab.socket(public, public, Policy::Public)?)?;
        let auth = client.authentication(&key);
        // A valid different member asserts the real server's public TLS key.
        // TLS pinning alone must not authenticate it as the expected device.
        let mut wrong_device = client.contact.clone();
        let mut record = wrong_device.endpoint.record.clone();
        record.transport_key_id = server.contact.endpoint.record.transport_key_id;
        wrong_device.endpoint = crate::record::SignedEndpointRecord::sign(record, &client.device)?;
        wrong_device.verify(&key, super::unix_time()?)?;
        let candidates = [(&wrong_device, public)];
        let exchange = async {
            tokio::join!(
                super::super::dial_candidates(&client.endpoint, &auth, &candidates, None),
                server.accept(&key)
            )
        };
        let (result, inbound) = tokio::time::timeout(Duration::from_secs(5), exchange).await?;
        assert!(
            result.is_none(),
            "a matching TLS key cannot substitute another device identity"
        );
        assert!(inbound.is_err());
        client.endpoint.close(0_u8.into(), b"test complete");
        server.endpoint.close(0_u8.into(), b"test complete");
        Ok(())
    })
}
