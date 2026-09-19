//! Test-only endpoint-dependent UDP firewall. No third protocol participant.

use std::{
    collections::BTreeSet,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use quinn::{
    AsyncUdpSocket, Runtime, UdpPoller,
    udp::{RecvMeta, Transmit},
};

#[derive(Debug)]
pub(super) struct FilteredSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    permitted: Mutex<BTreeSet<SocketAddr>>,
    dropped: AtomicUsize,
}

impl FilteredSocket {
    pub(super) fn new() -> io::Result<Arc<Self>> {
        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        Ok(Arc::new(Self {
            inner: quinn::TokioRuntime.wrap_udp_socket(socket)?,
            permitted: Mutex::new(BTreeSet::new()),
            dropped: AtomicUsize::new(0),
        }))
    }

    pub(super) fn dropped(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl AsyncUdpSocket for FilteredSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let mut permitted = self
            .permitted
            .lock()
            .map_err(|_| io::Error::other("test filter poisoned"))?;
        if permitted.len() >= 16 && !permitted.contains(&transmit.destination) {
            return Err(io::Error::other("test filter destination budget"));
        }
        self.inner.try_send(transmit)?;
        permitted.insert(transmit.destination);
        drop(permitted);
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(buffer) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let Some(metadata) = meta.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        for _ in 0..8 {
            let count = match self
                .inner
                .poll_recv(cx, core::slice::from_mut(buffer), core::slice::from_mut(metadata))
            {
                Poll::Ready(Ok(count)) => count,
                other => return other,
            };
            if count == 0 {
                return Poll::Ready(Ok(0));
            }
            let allowed = self
                .permitted
                .lock()
                .map_err(|_| io::Error::other("test filter poisoned"))?
                .contains(&metadata.addr);
            if allowed {
                return Poll::Ready(Ok(1));
            }
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}
