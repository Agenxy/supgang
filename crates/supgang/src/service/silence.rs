//! Retires a connection whose path went silent without any local sign.
//!
//! Leaving a network usually changes this computer's interfaces, and
//! `active::retire_unroutable` acts on that at once. A network can also be
//! left with nothing locally visible: a hotel that reuses the home subnet and
//! issues the laptop its home address leaves every interface identical, so the
//! connection over the departed LAN would be reported live, and redialing
//! suppressed, until QUIC's idle timeout. Keepalives guarantee that a live
//! peer is heard from at least every keepalive interval, so a connection that
//! has received nothing for longer than that is probed (`liveness`), and
//! retired only if the probe confirms it is gone. A starved or briefly lossy
//! connection that still answers is kept.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use tokio::{task::JoinSet, time::Instant};

use super::{active::ActiveConnection, liveness};
use crate::ids::NodeId;

/// Received nothing for this long: two missed keepalive acknowledgements plus
/// scheduling slack (`transport::KEEP_ALIVE_SECONDS`).
const SILENCE: Duration = Duration::from_secs(2 * crate::transport::KEEP_ALIVE_SECONDS + 2);

struct Heard {
    connection: usize,
    datagrams: u64,
    at: Instant,
}

/// Tracks when each active connection last received a datagram, and the
/// probes in flight for the silent ones. Bounded by the active set.
#[derive(Default)]
pub(super) struct SilenceWatch {
    heard: BTreeMap<NodeId, Heard>,
    probes: JoinSet<(NodeId, usize, bool)>,
    probing: BTreeMap<NodeId, usize>,
}

impl SilenceWatch {
    pub(super) fn retire_departed_and_schedule(
        &mut self,
        active: &mut BTreeMap<NodeId, ActiveConnection>,
        noncanonical_outbound: &mut BTreeSet<NodeId>,
        next_dial: &mut Instant,
        now: Instant,
    ) {
        if self.retire_departed(active) {
            noncanonical_outbound.retain(|peer| active.contains_key(peer));
            *next_dial = now;
        }
    }

    /// Starts a probe for each connection silent beyond the bound.
    pub(super) fn observe(&mut self, active: &BTreeMap<NodeId, ActiveConnection>) {
        let now = Instant::now();
        self.heard.retain(|peer, _| active.contains_key(peer));
        for (peer, connection) in active {
            let id = connection.stable_id();
            let datagrams = connection.connection().stats().udp_rx.datagrams;
            let heard = self.heard.entry(*peer).or_insert(Heard {
                connection: id,
                datagrams,
                at: now,
            });
            if heard.connection != id || heard.datagrams != datagrams {
                *heard = Heard {
                    connection: id,
                    datagrams,
                    at: now,
                };
                continue;
            }
            if now.saturating_duration_since(heard.at) < SILENCE || self.probing.get(peer) == Some(&id) {
                continue;
            }
            self.probing.insert(*peer, id);
            let probed = connection.connection().clone();
            let peer = *peer;
            self.probes
                .spawn(async move { (peer, id, liveness::is_live(&probed).await) });
        }
    }

    /// Retires each probed connection that did not answer and is still the
    /// registered one. Returns whether any was retired.
    pub(super) fn retire_departed(&mut self, active: &mut BTreeMap<NodeId, ActiveConnection>) -> bool {
        let mut retired = false;
        while let Some(finished) = self.probes.try_join_next() {
            let Ok((peer, id, live)) = finished else {
                continue;
            };
            if self.probing.get(&peer) == Some(&id) {
                self.probing.remove(&peer);
            }
            if live {
                // It answered: restart the silence clock from now.
                self.heard.remove(&peer);
                continue;
            }
            if active.get(&peer).is_some_and(|connection| connection.stable_id() == id)
                && let Some(connection) = active.remove(&peer)
            {
                connection.invalidate(b"path went silent");
                retired = true;
            }
        }
        retired
    }
}

#[cfg(test)]
mod tests {
    use super::SILENCE;

    #[test]
    fn silence_outlasts_two_keepalives() {
        let keepalive = std::time::Duration::from_secs(crate::transport::KEEP_ALIVE_SECONDS);
        assert!(SILENCE > keepalive * 2);
        assert!(SILENCE < std::time::Duration::from_secs(crate::transport::MAX_IDLE_SECONDS));
    }
}
