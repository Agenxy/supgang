//! Owner-only tunnel admission, exposure and mapped endpoint publication.

use super::super::{active::ActiveConnection, tunnel::TunnelRuntime, unix_time};
use crate::{
    control::{self, ControlReply},
    ids::NodeId,
    state::LocalState,
};
use std::{collections::BTreeMap, net::SocketAddr};

pub(super) async fn connect(
    mut stream: tokio::net::UnixStream,
    target: NodeId,
    name: [u8; 16],
    local_state: &LocalState,
    active: &BTreeMap<NodeId, ActiveConnection>,
    tunnels: &TunnelRuntime,
    tunnel_tasks: &mut tokio::task::JoinSet<()>,
) {
    let admitted = admit(target, local_state, active, tunnels, tunnel_tasks);
    let refusal = match (admitted, crate::tunnel_policy::decoded_name(name)) {
        (Ok((connection, global, peer)), Ok(name)) => {
            tunnel_tasks.spawn(super::super::tunnel::outgoing(
                stream,
                connection,
                name,
                tunnels.clone(),
                global,
                peer,
            ));
            return;
        }
        (Err(refusal), _) => refusal,
        (Ok(_), Err(_)) => Refusal::InvalidName,
    };
    let _reply = control::write_reply(
        &mut stream,
        &ControlReply::Error {
            message: refusal.message().to_owned(),
        },
    )
    .await;
}

/// Why a tunnel request was refused, each with what the owner can do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Refusal {
    Revoked,
    NotConnected,
    Unauthorized,
    RuntimeFull,
    PeerFull,
    InvalidName,
}

impl Refusal {
    pub(super) const fn message(self) -> &'static str {
        match self {
            Self::Revoked => "the peer is revoked; tunnels to it are refused",
            Self::NotConnected => {
                "the peer is not connected right now; Supgang keeps reconnecting on its own. Retry shortly, or check `supgang peers`"
            }
            Self::Unauthorized => {
                "the peer's session authorization has lapsed; Supgang renews it on its next contact. Retry shortly, or check `supgang peers`"
            }
            Self::RuntimeFull => {
                "every tunnel this computer allows is in use; close idle sessions or raise the total with `supgang tunnel-limits`"
            }
            Self::PeerFull => {
                "every tunnel allowed to this peer is in use; close idle sessions or raise the per-peer limit with `supgang tunnel-limits`"
            }
            Self::InvalidName => "the service name is invalid",
        }
    }
}

type Admission = (
    ActiveConnection,
    tokio::sync::OwnedSemaphorePermit,
    tokio::sync::OwnedSemaphorePermit,
);

pub(super) fn admit(
    target: NodeId,
    local_state: &LocalState,
    active: &BTreeMap<NodeId, ActiveConnection>,
    tunnels: &TunnelRuntime,
    tunnel_tasks: &tokio::task::JoinSet<()>,
) -> Result<Admission, Refusal> {
    if local_state.revocations().contains(&target) {
        return Err(Refusal::Revoked);
    }
    let connection = active
        .get(&target)
        .filter(|connection| connection.close_reason().is_none())
        .ok_or(Refusal::NotConnected)?;
    if !connection.authorization().is_current(unix_time().unwrap_or(u64::MAX)) {
        return Err(Refusal::Unauthorized);
    }
    if tunnel_tasks.len() >= tunnels.policy.borrow().total {
        return Err(Refusal::RuntimeFull);
    }
    let global = tunnels
        .admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| Refusal::RuntimeFull)?;
    let peer = connection
        .tunnel_admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| Refusal::PeerFull)?;
    Ok((connection.clone(), global, peer))
}

pub(super) fn expose(
    tunnels: &TunnelRuntime,
    state_directory: &std::path::Path,
    name: [u8; 16],
    port: u16,
    active: &BTreeMap<NodeId, ActiveConnection>,
) -> ControlReply {
    let result = crate::tunnel_policy::decoded_name(name)
        .map_err(str::to_owned)
        .and_then(|name| tunnels.expose(state_directory, name, port));
    match result {
        Ok(()) => {
            // End existing session authority before acknowledging a policy
            // change. No transfer can retain a removed loopback grant.
            for connection in active.values() {
                connection.invalidate(b"local tunnel policy changed");
            }
            ControlReply::ExposureChanged
        }
        Err(message) => ControlReply::Error { message },
    }
}

pub(super) fn add_mapped_endpoint(
    tunnels: &super::super::tunnel::TunnelRuntime,
    directory: &std::path::Path,
    address: SocketAddr,
    config: &mut super::super::ServiceConfig,
    state: &mut LocalState,
    identity: &crate::transport::TransportIdentity,
    contact: &mut crate::contact::PeerContact,
) -> Result<bool, PublicationError> {
    let mut policy = tunnels.policy.borrow().clone();
    if policy.mapped.contains(&address) {
        return Ok(false);
    }
    policy.mapped.push(address);
    policy
        .validate()
        .map_err(|message| PublicationError::Policy(message.to_owned()))?;
    let replacement = config.clone().with_mapped_addresses(&[address]).map_err(|_| {
        PublicationError::Policy("mapped endpoint exceeds the candidate budget or is invalid".to_owned())
    })?;
    // Local owner authorization is established by IPC peer credentials. Check
    // current membership before committing this durable publication policy.
    super::super::contact_state::require_live_membership(state, unix_time().map_err(PublicationError::Authority)?)
        .map_err(|_| PublicationError::Policy("membership must be renewed before endpoint publication".to_owned()))?;
    crate::tunnel_policy::save(directory, &policy).map_err(PublicationError::Policy)?;
    *config = replacement;
    *contact = super::super::make_local_contact(state, identity, config).map_err(PublicationError::Authority)?;
    tunnels.policy.send_replace(policy);
    Ok(true)
}

pub(super) enum PublicationError {
    Policy(String),
    Authority(super::super::ServiceError),
}
