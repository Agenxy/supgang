//! Authenticated-session release-identity gossip and advisory notice tracking.

use std::{collections::BTreeMap, io::Write, time::Duration};

use quinn::Connection;

use crate::{
    ids::NodeId,
    peer_directory::PeerDirectory,
    release::{self, PeerReleaseObservation, ReleaseIdentity, ReleaseNoticeLog, UpdateNotice},
};

use super::{active::ActiveConnection, local_control::connection_event_is_current};

/// Rate limit for periodic release-identity datagram refreshes on a live session.
pub(super) const RELEASE_GOSSIP_INTERVAL: Duration = Duration::from_mins(5);

/// Sends this process's release identity once on connect and then at most once
/// every `RELEASE_GOSSIP_INTERVAL` while the session remains live.
///
/// Errors are ignored and this future never returns, so advisory gossip can
/// never disrupt or close an authenticated peer session.
pub(super) async fn announce_loop(connection: Connection, local: ReleaseIdentity) {
    let _sent = release::send(&connection, &local);
    loop {
        tokio::time::sleep(RELEASE_GOSSIP_INTERVAL).await;
        if connection.close_reason().is_some() {
            std::future::pending::<()>().await;
        }
        let _sent = release::send(&connection, &local);
    }
}

/// Records a peer-reported release identity on the peer's active connection
/// (in memory only) and emits one concise stderr log line per newly seen
/// strictly newer semantic version.
pub(super) fn record_peer_release(
    active: &mut BTreeMap<NodeId, ActiveConnection>,
    directory: &PeerDirectory,
    local: &ReleaseIdentity,
    log: &mut ReleaseNoticeLog,
    peer: NodeId,
    connection_id: usize,
    identity: ReleaseIdentity,
) {
    if !connection_event_is_current(active.get(&peer).map(|current| current.stable_id()), connection_id) {
        return;
    }
    if let Some(connection) = active.get_mut(&peer) {
        connection.set_peer_release(identity);
    }
    let Some(reported) = active.get(&peer).and_then(ActiveConnection::peer_release) else {
        return;
    };
    let name = peer_display_name(directory, peer);
    let observation = PeerReleaseObservation {
        node_id: peer,
        name: &name,
        release: reported,
    };
    if let Some(line) = log.record_if_new(local, &observation) {
        let mut stderr = std::io::stderr();
        let _written = writeln!(stderr, "{line}");
    }
}

/// Computes the current fleet-wide advisory update notice from live,
/// authorized, connected gang peers.
pub(super) fn current_update_notice(
    local: &ReleaseIdentity,
    active: &BTreeMap<NodeId, ActiveConnection>,
    directory: &PeerDirectory,
    now: u64,
) -> Option<UpdateNotice> {
    let rows: Vec<(NodeId, String, &ReleaseIdentity)> = active
        .iter()
        .filter(|(_, connection)| connection.close_reason().is_none() && connection.authorization().is_current(now))
        .filter_map(|(peer, connection)| {
            connection
                .peer_release()
                .map(|release| (*peer, peer_display_name(directory, *peer), release))
        })
        .collect();
    let observations: Vec<PeerReleaseObservation<'_>> = rows
        .iter()
        .map(|(node_id, name, release)| PeerReleaseObservation {
            node_id: *node_id,
            name,
            release,
        })
        .collect();
    release::compute_update_notice(local, &observations)
}

fn peer_display_name(directory: &PeerDirectory, peer: NodeId) -> String {
    directory
        .entries()
        .get(&peer)
        .and_then(|entry| entry.current().endpoint.record.display_name.as_ref())
        .map_or_else(
            || format!("computer-{}", peer.to_string().chars().take(8).collect::<String>()),
            ToString::to_string,
        )
}
