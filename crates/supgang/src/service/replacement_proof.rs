//! A bounded application-level Sync exchange proves the peer accepted a
//! candidate before its established session is retired.

use std::{collections::VecDeque, time::Duration};

use ed25519_dalek::VerifyingKey;
use quinn::{Connection, RecvStream, SendStream};

use crate::{ids::NodeId, sync::SyncPage};

use super::SESSION_TIMEOUT_SECONDS;

const MAX_PROOF_LIMIT: Duration = Duration::from_mins(2);
const MAX_DEFERRED_STREAMS: usize = 8;

pub(super) type DeferredStream = (crate::peer_stream::StreamKind, SendStream, RecvStream);

pub(super) async fn prove(
    connection: &Connection,
    local: NodeId,
    peer: NodeId,
    page: &SyncPage,
    root: &VerifyingKey,
    retry_interval: Duration,
) -> Option<VecDeque<DeferredStream>> {
    let proof = async {
        let mut deferred = VecDeque::new();
        let received = if local < peer {
            let (mut send, mut receive) = crate::peer_stream::open(connection, crate::peer_stream::StreamKind::Sync)
                .await
                .map_err(|_| ())?;
            crate::sync::exchange_outbound_stream(&mut send, &mut receive, page)
                .await
                .map_err(|_| ())?
        } else {
            let (mut send, mut receive) = loop {
                let (kind, send, receive) = crate::peer_stream::accept(connection).await.map_err(|_| ())?;
                if kind == crate::peer_stream::StreamKind::Sync {
                    break (send, receive);
                }
                // The other peer may already be running its actor. Preserve
                // its earlier service/update streams for admission after the
                // candidate proves Sync, within a fixed queue bound.
                if deferred.len() >= MAX_DEFERRED_STREAMS {
                    return Err(());
                }
                deferred.push_back((kind, send, receive));
            };
            crate::sync::exchange_inbound_stream(&mut send, &mut receive, page)
                .await
                .map_err(|_| ())?
        };
        received.revocations.verify(root).map_err(|_| ())?;
        Ok::<VecDeque<DeferredStream>, ()>(deferred)
    };
    // The canonical initiator may wait one retry interval before its first
    // post-authentication sync. Keep this bounded even for a custom interval.
    let limit = retry_interval
        .saturating_mul(2)
        .saturating_add(Duration::from_secs(SESSION_TIMEOUT_SECONDS))
        .clamp(Duration::from_secs(15), MAX_PROOF_LIMIT);
    tokio::time::timeout(limit, proof).await.ok().and_then(Result::ok)
}
