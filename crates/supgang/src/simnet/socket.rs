//! A simulated dual-stack UDP socket that quinn drives like an OS socket.

use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};

use super::{HostId, Network};

/// A UDP socket bound to `[::]:port` on one simulated host.
#[derive(Debug)]
pub struct SimSocket {
    network: Arc<Network>,
    host: HostId,
    port: u16,
}

impl SimSocket {
    pub(super) const fn new(network: Arc<Network>, host: HostId, port: u16) -> Self {
        Self { network, host, port }
    }

    pub const fn host(&self) -> HostId {
        self.host
    }

    /// Sends one datagram without QUIC, for calibrating a topology.
    pub fn send_raw(&self, destination: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        self.network.send(self.host, self.port, destination, bytes)
    }

    /// Takes the next queued datagram without waiting, for calibration.
    pub fn try_receive(&self) -> io::Result<Option<(SocketAddr, Vec<u8>)>> {
        let received = self
            .network
            .lock()?
            .hosts
            .get_mut(self.host.0)
            .and_then(|host| host.sockets.get_mut(&self.port))
            .ok_or_else(|| io::Error::other("simulated socket is closed"))?
            .take_ready(tokio::time::Instant::now());
        Ok(received.map(|received| (received.source, received.bytes)))
    }
}

impl Drop for SimSocket {
    fn drop(&mut self) {
        self.network.unbind(self.host, self.port);
    }
}

#[derive(Debug)]
struct Writable;

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The form a dual-stack socket reports an IPv4 address in.
fn dual_stack(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(v4) => IpAddr::V6(v4.to_ipv6_mapped()),
        IpAddr::V6(_) => address,
    }
}

impl AsyncUdpSocket for SimSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::other("simulated sockets do not segment"));
        }
        self.network
            .send(self.host, self.port, transmit.destination, transmit.contents)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.network.lock()?;
        let inbox = state
            .hosts
            .get_mut(self.host.0)
            .and_then(|host| host.sockets.get_mut(&self.port))
            .ok_or_else(|| io::Error::other("simulated socket is closed"))?;
        let now = tokio::time::Instant::now();
        let Some(received) = inbox.take_ready(now) else {
            inbox.reader = Some(cx.waker().clone());
            // Datagrams still crossing a delayed path wake the reader when the
            // earliest arrives; one pending wake covers every later one.
            inbox.timer = inbox.timer.filter(|timer| *timer > now);
            let earliest = inbox.queue.iter().map(|received| received.ready_at).min();
            if let Some(earliest) = earliest
                && inbox.timer.is_none_or(|timer| timer > earliest)
                && let Ok(runtime) = tokio::runtime::Handle::try_current()
            {
                inbox.timer = Some(earliest);
                let waker = cx.waker().clone();
                runtime.spawn(async move {
                    tokio::time::sleep_until(earliest).await;
                    waker.wake();
                });
            }
            return Poll::Pending;
        };
        drop(state);
        let buffer = bufs
            .first_mut()
            .ok_or_else(|| io::Error::other("missing receive buffer"))?;
        let metadata = meta
            .first_mut()
            .ok_or_else(|| io::Error::other("missing receive metadata"))?;
        let length = received.bytes.len();
        buffer
            .get_mut(..length)
            .ok_or_else(|| io::Error::other("receive buffer too small"))?
            .copy_from_slice(&received.bytes);
        *metadata = RecvMeta {
            addr: SocketAddr::new(dual_stack(received.source.ip()), received.source.port()),
            len: length,
            stride: length,
            ecn: None,
            dst_ip: Some(dual_stack(received.destination)),
        };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), self.port))
    }

    fn may_fragment(&self) -> bool {
        // The simulated network drops oversized datagrams rather than
        // fragmenting them, so Quinn can probe its path MTU.
        false
    }
}
