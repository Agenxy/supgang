//! Owner-authorized update queue admission.

use super::super::unix_time;
use crate::{control::ControlReply, ids::NodeId, state::LocalState};

pub(super) fn queue_update(
    state_directory: &std::path::Path,
    delivery_queue: &mut super::super::update_delivery::UpdateDeliveryQueue,
    local_state: &LocalState,
    target: NodeId,
    digest: [u8; 32],
) -> (ControlReply, bool) {
    let result = (|| {
        let _root = local_state
            .identity()
            .root
            .as_ref()
            .ok_or("this computer does not hold the hive root needed to authorize a remote update")?;
        if target == local_state.identity().device.node_id() || local_state.revocations().contains(&target) {
            return Err("the selected peer is not eligible for an update");
        }
        let queued = crate::update::queue_peer_delivery(
            state_directory,
            target,
            digest,
            unix_time().map_err(|_| "the system clock is invalid")?,
        )
        .map_err(|_| "the prepared update could not be queued safely")?;
        delivery_queue.enqueue(queued);
        Ok::<(), &str>(())
    })();
    match result {
        Ok(()) => (
            ControlReply::UpdateQueued {
                node_id: target.to_string(),
                digest: hex::encode(digest),
            },
            false,
        ),
        Err(message) => (
            ControlReply::Error {
                message: message.to_owned(),
            },
            false,
        ),
    }
}
