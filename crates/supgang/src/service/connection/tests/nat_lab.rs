//! In-memory UDP translation model, not a router or an extra protocol peer.
//! Real QUIC ciphertext and the production device proof cross this boundary.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};

#[derive(Clone, Copy, Debug)]
pub(super) enum Policy {
    /// Public socket: no translation, and unsolicited packets are permitted.
    Public,
    /// Stable endpoint-independent mapping with address-and-port filtering.
    Restricted,
    /// No UDP path, even when both endpoints send first.
    Blocked,
}

#[derive(Debug)]
struct Datagram {
    source: SocketAddr,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct Device {
    external: SocketAddr,
    policy: Policy,
    mapped: bool,
    permitted: BTreeSet<SocketAddr>,
    received: VecDeque<Datagram>,
    reader: Option<Waker>,
}

#[derive(Debug, Default)]
pub(super) struct NatLab {
    devices: Mutex<BTreeMap<SocketAddr, Device>>,
}

impl NatLab {
    pub(super) fn socket(
        self: &Arc<Self>,
        internal: SocketAddr,
        external: SocketAddr,
        policy: Policy,
    ) -> io::Result<Arc<NatSocket>> {
        let mut devices = self.devices.lock().map_err(|_| io::Error::other("lab poisoned"))?;
        if devices.len() >= 2
            || devices.contains_key(&internal)
            || devices.values().any(|device| device.external == external)
        {
            return Err(io::Error::other("lab accepts exactly two distinct devices"));
        }
        devices.insert(
            internal,
            Device {
                external,
                policy,
                mapped: matches!(policy, Policy::Public),
                permitted: BTreeSet::new(),
                received: VecDeque::new(),
                reader: None,
            },
        );
        drop(devices);
        Ok(Arc::new(NatSocket {
            lab: Arc::clone(self),
            internal,
        }))
    }

    fn send(&self, internal: SocketAddr, transmit: &Transmit) -> io::Result<()> {
        if transmit.contents.len() > 65_535 || transmit.segment_size.is_some() {
            return Err(io::Error::other("lab datagram limit"));
        }
        let destination = crate::candidate::canonical_socket_address(transmit.destination);
        let mut devices = self.devices.lock().map_err(|_| io::Error::other("lab poisoned"))?;
        let sender = devices
            .get_mut(&internal)
            .ok_or_else(|| io::Error::other("missing sender"))?;
        if sender.external.is_ipv4() != destination.is_ipv4() || matches!(sender.policy, Policy::Blocked) {
            return Ok(());
        }
        if sender.permitted.len() >= 32 && !sender.permitted.contains(&destination) {
            return Err(io::Error::other("lab destination limit"));
        }
        sender.permitted.insert(destination);
        sender.mapped = true;
        let source = sender.external;
        let Some(receiver) = devices.values_mut().find(|device| device.external == destination) else {
            return Ok(());
        };
        if !receiver.mapped
            || matches!(receiver.policy, Policy::Blocked)
            || (matches!(receiver.policy, Policy::Restricted) && !receiver.permitted.contains(&source))
        {
            return Ok(());
        }
        if receiver.received.len() >= 256 {
            return Err(io::Error::other("lab receive queue limit"));
        }
        receiver.received.push_back(Datagram {
            source,
            bytes: transmit.contents.to_vec(),
        });
        let reader = receiver.reader.take();
        drop(devices);
        if let Some(reader) = reader {
            reader.wake();
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct NatSocket {
    lab: Arc<NatLab>,
    internal: SocketAddr,
}

#[derive(Debug)]
struct Writable;

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for NatSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.lab.send(self.internal, transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut devices = self.lab.devices.lock().map_err(|_| io::Error::other("lab poisoned"))?;
        let receiver = devices
            .get_mut(&self.internal)
            .ok_or_else(|| io::Error::other("missing receiver"))?;
        let Some(packet) = receiver.received.pop_front() else {
            receiver.reader = Some(cx.waker().clone());
            return Poll::Pending;
        };
        drop(devices);
        let buffer = bufs
            .first_mut()
            .ok_or_else(|| io::Error::other("missing receive buffer"))?;
        let metadata = meta
            .first_mut()
            .ok_or_else(|| io::Error::other("missing receive metadata"))?;
        let bytes = packet.bytes.len();
        buffer
            .get_mut(..bytes)
            .ok_or_else(|| io::Error::other("receive buffer too small"))?
            .copy_from_slice(&packet.bytes);
        // A dual-stack OS socket receives IPv4 in its IPv4-mapped IPv6 form.
        let source = match (self.internal, packet.source) {
            (SocketAddr::V6(_), SocketAddr::V4(address)) => {
                SocketAddr::from((address.ip().to_ipv6_mapped(), address.port()))
            }
            (_, source) => source,
        };
        *metadata = RecvMeta {
            addr: source,
            len: bytes,
            stride: bytes,
            ecn: None,
            dst_ip: Some(self.internal.ip()),
        };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.internal)
    }
}
