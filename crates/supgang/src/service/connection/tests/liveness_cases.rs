//! The liveness probe against real QUIC over the simulated network: a
//! connection whose peer still answers is live, and one whose peer has left
//! the network is judged gone within the probe's bounded window.

use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};

use super::{Peer, RootIdentity, dial_addresses, transport};
use crate::simnet::{Network, SimSocket, SiteSpec, V4Access};

/// A simulated socket that reports its host's address, so a test contact
/// carries a usable candidate rather than the wildcard bind address.
#[derive(Debug)]
struct Addressed {
    inner: Arc<SimSocket>,
    address: SocketAddr,
}

impl AsyncUdpSocket for Addressed {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // An IPv4 socket sees plain IPv4 addresses, not their mapped form.
        let polled = self.inner.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(count)) = &polled {
            for metadata in meta.iter_mut().take(*count) {
                metadata.addr = SocketAddr::new(metadata.addr.ip().to_canonical(), metadata.addr.port());
                metadata.dst_ip = metadata.dst_ip.map(|ip| ip.to_canonical());
            }
        }
        polled
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.address)
    }
}

#[test]
fn a_peer_that_left_the_network_is_judged_gone_and_a_present_one_is_not() -> Result<(), Box<dyn std::error::Error>> {
    transport::build_runtime()?.block_on(async {
        let network = Network::new(31);
        let site = network.add_site(SiteSpec {
            v4: Some(V4Access::Public {
                first: Ipv4Addr::new(9, 9, 9, 10),
            }),
            v6: None,
        })?;
        let first_host = network.add_host(Some(site))?;
        let second_host = network.add_host(Some(site))?;
        let second_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 11)), 44_330);
        let root = RootIdentity::generate()?;
        let key = root.verifying_key();
        let first = Peer::new(
            &root,
            1,
            Arc::new(Addressed {
                inner: network.bind(first_host, 44_330)?,
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 10)), 44_330),
            }),
        )?;
        let second = Peer::new(
            &root,
            2,
            Arc::new(Addressed {
                inner: network.bind(second_host, 44_330)?,
                address: second_address,
            }),
        )?;
        let authentication = first.authentication(&key);
        let targets = [second_address];
        let (dialed, accepted) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(
                dial_addresses(&first.endpoint, &authentication, &second.contact, &targets),
                second.accept(&key),
            )
        })
        .await?;
        let (_, connection) = dialed.ok_or("dial failed")?;
        let _inbound = accepted?;

        assert!(crate::service::liveness::is_live(&connection).await);

        network.move_host(second_host, None)?;
        let started = tokio::time::Instant::now();
        assert!(!crate::service::liveness::is_live(&connection).await);
        assert!(
            started.elapsed() <= Duration::from_secs(6),
            "probe took {:?}",
            started.elapsed()
        );

        first.endpoint.close(0_u8.into(), b"test complete");
        second.endpoint.close(0_u8.into(), b"test complete");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
