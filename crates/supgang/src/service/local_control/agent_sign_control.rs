//! Bounded owner-socket dispatch to an authenticated member session.

use std::collections::BTreeMap;

use crate::{
    agent_sign_protocol::{MAX_REQUEST_BYTES, SignReply, SignRequest},
    control::{self, ControlReply},
    ids::NodeId,
    state::LocalState,
};

use super::super::{active::ActiveConnection, agent_sign, unix_time};

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
        "too many member signing requests are in progress"
    } else if local_state.revocations().contains(&target) {
        "the signing peer is revoked"
    } else if let Some(connection) = active.get(&target) {
        if connection.close_reason().is_some()
            || !connection.authorization().is_current(unix_time().unwrap_or(u64::MAX))
        {
            "the signing peer is not currently authorized"
        } else if let Some(payload) = request.get(..usize::from(length))
            && let Ok(decoded) = SignRequest::decode(payload)
        {
            let transport = connection.connection().clone();
            let authorization = connection.authorization().clone();
            let hive = local_state.identity().hive_id;
            let local = local_state.identity().device.node_id();
            sign_tasks.spawn(async move {
                let result = agent_sign::outgoing(transport, authorization, hive, local, target, decoded).await;
                let reply = match result {
                    Ok(SignReply::Signed {
                        nonce,
                        public_key,
                        signature,
                    }) => ControlReply::AgentSigned {
                        nonce: hex::encode(nonce),
                        public_key: hex::encode(public_key),
                        signature: hex::encode(signature),
                    },
                    Ok(SignReply::Refused { .. }) => ControlReply::Error {
                        code: None,
                        message: "the signing peer refused the request".to_owned(),
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
            "member signing request is invalid"
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
