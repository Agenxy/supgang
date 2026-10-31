//! Bounded messages returned from authenticated peer actors to the state owner.

use std::net::SocketAddr;

use crate::{ids::NodeId, sync::SyncPage};

pub(super) enum PeerEvent {
    Contacts {
        peer: NodeId,
        connection_id: usize,
        page: SyncPage,
    },
    Revocations {
        peer: NodeId,
        connection_id: usize,
        revocations: crate::revocation::SignedRevocationList,
    },
    RendezvousRequest {
        peer: NodeId,
        connection_id: usize,
        rendezvous_id: [u8; crate::rendezvous::RENDEZVOUS_ID_BYTES],
        target: NodeId,
    },
    RendezvousOffer {
        peer: NodeId,
        connection_id: usize,
        rendezvous_id: [u8; crate::rendezvous::RENDEZVOUS_ID_BYTES],
        target: NodeId,
        address: SocketAddr,
    },
    Closed {
        peer: NodeId,
        connection_id: usize,
    },
}

impl PeerEvent {
    pub(super) const fn source(&self) -> Option<(NodeId, usize)> {
        match self {
            Self::Contacts {
                peer, connection_id, ..
            }
            | Self::Revocations {
                peer, connection_id, ..
            }
            | Self::RendezvousRequest {
                peer, connection_id, ..
            }
            | Self::RendezvousOffer {
                peer, connection_id, ..
            } => Some((*peer, *connection_id)),
            Self::Closed { .. } => None,
        }
    }
}

use super::ServiceError;
use quinn::Endpoint;
use std::time::Duration;

pub(super) async fn stop_if_requested(receiver: &mut tokio::sync::mpsc::Receiver<()>, endpoint: &Endpoint) -> bool {
    if receiver.try_recv().is_err() {
        return false;
    }
    endpoint.close(0_u8.into(), b"service shutdown");
    let _idle = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
    true
}

pub(super) fn shutdown_receiver() -> Result<tokio::sync::mpsc::Receiver<()>, ServiceError> {
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(ServiceError::Signal)?;
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    let interrupt_sender = sender.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _sent = interrupt_sender.send(()).await;
        }
    });
    tokio::spawn(async move {
        if terminate.recv().await.is_some() {
            let _sent = sender.send(()).await;
        }
    });
    Ok(receiver)
}
