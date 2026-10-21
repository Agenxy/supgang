//! At most one bounded old tunnel-bearing connection per peer during handover.

use std::{collections::BTreeMap, time::Duration};

use tokio::time::Instant;

use super::{MAX_ANCHOR_PEERS, active::ActiveConnection};
use crate::{ids::NodeId, revocation::SignedRevocationList};

const DRAIN_LIMIT: Duration = Duration::from_mins(10);
const REAP_INTERVAL: Duration = Duration::from_secs(1);

struct Drain {
    connection: ActiveConnection,
    started: Instant,
}

#[derive(Default)]
pub(super) struct DrainingConnections {
    slots: BTreeMap<NodeId, Drain>,
}

impl DrainingConnections {
    pub(super) fn contains(&self, peer: NodeId) -> bool {
        self.slots.contains_key(&peer)
    }

    pub(super) fn begin(&mut self, peer: NodeId, connection: ActiveConnection, now: Instant) {
        connection.begin_draining();
        if let Some(previous) = self.slots.remove(&peer) {
            previous.connection.invalidate(b"newer tunnel drain replaced old drain");
        }
        if !connection.has_tunnels() {
            connection.invalidate(b"superseded path has no tunnels");
            return;
        }
        if self.slots.len() >= MAX_ANCHOR_PEERS
            && let Some(oldest) = self
                .slots
                .iter()
                .min_by_key(|(_, drain)| drain.started)
                .map(|(peer, _)| *peer)
            && let Some(evicted) = self.slots.remove(&oldest)
        {
            evicted.connection.invalidate(b"tunnel drain capacity reached");
        }
        self.slots.insert(
            peer,
            Drain {
                connection,
                started: now,
            },
        );
    }

    pub(super) fn reap(&mut self, revocations: &SignedRevocationList, now: Instant) {
        self.slots.retain(|peer, drain| {
            let reason = if revocations.contains(peer) {
                Some(b"peer revoked".as_slice())
            } else if !drain.connection.has_tunnels() {
                Some(b"last tunnel drained".as_slice())
            } else if now.saturating_duration_since(drain.started) >= DRAIN_LIMIT {
                Some(b"tunnel drain deadline".as_slice())
            } else if drain.connection.close_reason().is_some() {
                Some(b"draining connection closed".as_slice())
            } else {
                None
            };
            if let Some(reason) = reason {
                drain.connection.invalidate(reason);
                false
            } else {
                true
            }
        });
    }

    pub(super) fn invalidate_revoked(&mut self, revocations: &SignedRevocationList) {
        self.slots.retain(|peer, drain| {
            if revocations.contains(peer) {
                drain.connection.invalidate(b"peer revoked");
                false
            } else {
                true
            }
        });
    }

    pub(super) fn invalidate_all(&mut self, reason: &'static [u8]) {
        for drain in self.slots.values() {
            drain.connection.invalidate(reason);
        }
        self.slots.clear();
    }

    pub(super) fn bound_wait(&self, wait: Duration) -> Duration {
        if self.slots.is_empty() {
            wait
        } else {
            wait.min(REAP_INTERVAL)
        }
    }
}
