//! Bounded owner-socket dispatch for authenticated remote key creation.

use std::collections::BTreeMap;

use crate::{
    agent_keygen_protocol::{KeygenReply, KeygenRequest, MAX_REQUEST_BYTES},
    control::{self, ControlReply},
    ids::NodeId,
    state::LocalState,
};

use super::super::{active::ActiveConnection, agent_keygen, unix_time};

pub(super) async fn handle(
    mut stream: tokio::net::UnixStream,
    target: NodeId,
    request: Box<[u8; MAX_REQUEST_BYTES]>,
    length: u16,
    local_state: &LocalState,
    active: &BTreeMap<NodeId, ActiveConnection>,
    sign_tasks: &mut tokio::task::JoinSet<()>,
) {
    let refusal = if sign_tasks.len() >= 4 {
        "too many member signing or key creation requests are in progress"
    } else if local_state.revocations().contains(&target) {
        "the key creation peer is revoked"
    } else if let Some(connection) = active.get(&target) {
        if connection.close_reason().is_some()
            || !connection.authorization().is_current(unix_time().unwrap_or(u64::MAX))
        {
            "the key creation peer is not currently authorized"
        } else if let Some(payload) = request.get(..usize::from(length))
            && let Ok(decoded) = KeygenRequest::decode(payload)
        {
            let transport = connection.connection().clone();
            let authorization = connection.authorization().clone();
            let hive = local_state.identity().hive_id;
            let local = local_state.identity().device.node_id();
            sign_tasks.spawn(async move {
                let result = agent_keygen::outgoing(transport, authorization, hive, local, target, decoded).await;
                let reply = match result {
                    Ok(KeygenReply::Created { nonce, public_key }) => ControlReply::AgentKeyCreated {
                        nonce: hex::encode(nonce),
                        public_key: hex::encode(public_key),
                    },
                    Ok(KeygenReply::Refused { .. }) => ControlReply::Error {
                        code: None,
                        message: "the key creation peer refused the request".to_owned(),
                    },
                    Err(message) => ControlReply::Error {
                        code: None,
                        message: message.to_owned(),
                    },
                };
                let _sent = control::write_reply(&mut stream, &reply).await;
            });
            return;
        } else {
            "member key creation request is invalid"
        }
    } else {
        control::PEER_NOT_CONNECTED
    };
    let _sent = control::write_reply(
        &mut stream,
        &ControlReply::Error {
            code: None,
            message: refusal.to_owned(),
        },
    )
    .await;
}
