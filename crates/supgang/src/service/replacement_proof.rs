//! A bounded application-level Sync exchange proves the peer accepted a
//! candidate before its established session is retired.

use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use quinn::Connection;

use crate::{ids::NodeId, sync::SyncPage};

use super::SESSION_TIMEOUT_SECONDS;

const MAX_PROOF_LIMIT: Duration = Duration::from_mins(2);

pub(super) async fn prove(
    connection: &Connection,
    local: NodeId,
    peer: NodeId,
    page: &SyncPage,
    root: &VerifyingKey,
    retry_interval: Duration,
) -> bool {
    let proof = async {
        let received = if local < peer {
            let (mut send, mut receive) = crate::peer_stream::open(connection, crate::peer_stream::StreamKind::Sync)
                .await
                .map_err(|_| ())?;
            crate::sync::exchange_outbound_stream(&mut send, &mut receive, page)
                .await
                .map_err(|_| ())?
        } else {
            let (kind, mut send, mut receive) = crate::peer_stream::accept(connection).await.map_err(|_| ())?;
            if kind != crate::peer_stream::StreamKind::Sync {
                return Err(());
            }
            crate::sync::exchange_inbound_stream(&mut send, &mut receive, page)
                .await
                .map_err(|_| ())?
        };
        received.revocations.verify(root).map_err(|_| ())?;
        Ok::<(), ()>(())
    };
    // The canonical initiator may wait one retry interval before its first
    // post-authentication sync. Keep this bounded even for a custom interval.
    let limit = retry_interval
        .saturating_mul(2)
        .saturating_add(Duration::from_secs(SESSION_TIMEOUT_SECONDS))
        .clamp(Duration::from_secs(15), MAX_PROOF_LIMIT);
    tokio::time::timeout(limit, proof)
        .await
        .is_ok_and(|result| result.is_ok())
}
