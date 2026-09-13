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
