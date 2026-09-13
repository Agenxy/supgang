//! Signed memory-only reachability derived from an explicitly enabled gateway mapping.

use std::net::SocketAddr;

use crate::{
    ids::NodeId,
    peer_directory::{PeerDirectory, PeerDirectoryError},
    reachability::{ReachabilityClaim, ReachabilitySource},
    router_mapping::RouterMappingStatus,
    state::LocalState,
};

use super::{ServiceError, unix_time};

pub(super) fn replace_gateway_reachability(
    local_state: &LocalState,
    directory: &mut PeerDirectory,
    local_node: NodeId,
    status: RouterMappingStatus,
) -> Result<bool, ServiceError> {
    let claim = match status {
        RouterMappingStatus::Mapped(address) => {
            let membership = local_state
                .local_membership()
                .cloned()
                .ok_or(ServiceError::InvalidConfiguration)?;
            Some(
                ReachabilityClaim::sign(
                    membership,
                    &local_state.identity().device,
                    local_node,
                    SocketAddr::V4(address),
                    ReachabilitySource::Gateway,
                    unix_time()?,
                )
                .map_err(PeerDirectoryError::Reachability)?,
            )
        }
        RouterMappingStatus::Disabled | RouterMappingStatus::Checking | RouterMappingStatus::Unavailable => None,
    };
    directory
        .replace_local_gateway_reachability(claim, unix_time()?)
        .map_err(Into::into)
}
