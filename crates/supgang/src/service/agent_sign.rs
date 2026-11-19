//! Member-only, exporter-bound request processing on an existing hive session.

use std::{sync::Arc, time::Duration};

use quinn::{Connection, RecvStream, SendStream};

use crate::{
    agent_sign_protocol::{self, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MacBinding, SignReply, SignRequest},
    ids::{HiveId, NodeId},
    peer_stream::{self, StreamKind},
    vault::{self, SecureEnclave},
};

use super::{active::SessionAuthorization, peer_actor::PeerUpdateContext};

const EXPORTER_LABEL: &[u8] = b"supgang/agent-sign/exporter/v1";
const EXPORTER_CONTEXT: &[u8] = b"";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) fn spawn(
    tasks: &mut tokio::task::JoinSet<()>,
    context: Option<&PeerUpdateContext>,
    connection: &Connection,
    send: SendStream,
    receive: RecvStream,
    requester: NodeId,
    authorization: &SessionAuthorization,
) {
    if let Some(context) = context
        && tasks.len() < 4
    {
        tasks.spawn(incoming(
            connection.clone(),
            send,
            receive,
            requester,
            authorization.clone(),
            context.clone(),
        ));
    }
}

pub(super) async fn incoming(
    connection: Connection,
    mut send: SendStream,
    mut receive: RecvStream,
    requester: NodeId,
    authorization: SessionAuthorization,
    context: PeerUpdateContext,
) {
    let Ok(permit) = Arc::clone(&context.sign_admission).try_acquire_owned() else {
        return;
    };
    let _result = tokio::time::timeout(
        REQUEST_TIMEOUT,
        process(
            &connection,
            &mut send,
            &mut receive,
            requester,
            &authorization,
            &context,
            permit,
        ),
    )
    .await;
}

async fn process(
    connection: &Connection,
    send: &mut SendStream,
    receive: &mut RecvStream,
    requester: NodeId,
    authorization: &SessionAuthorization,
    context: &PeerUpdateContext,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<(), ()> {
    if !authorization.is_current(now()?) || connection.close_reason().is_some() {
        return Err(());
    }
    let mut exporter = [0_u8; 32];
    connection
        .export_keying_material(&mut exporter, EXPORTER_LABEL, EXPORTER_CONTEXT)
        .map_err(|_| ())?;
    let binding = MacBinding {
        hive: context.hive_id,
        requester,
        signer: context.local_node,
        stream: u64::from(send.id()),
    };
    let mut length = [0_u8; 2];
    receive.read_exact(&mut length).await.map_err(|_| ())?;
    let size = usize::from(u16::from_be_bytes(length));
    if size == 0 || size > MAX_REQUEST_BYTES {
        return Err(());
    }
    let mut bytes = vec![0_u8; size];
    receive.read_exact(&mut bytes).await.map_err(|_| ())?;
    let mut tag = [0_u8; 32];
    receive.read_exact(&mut tag).await.map_err(|_| ())?;
    if !receive.read_to_end(1).await.map_err(|_| ())?.is_empty() {
        return Err(());
    }
    agent_sign_protocol::verify_request_tag(&exporter, &binding, &bytes, &tag).map_err(|_| ())?;
    let request = SignRequest::decode(&bytes).map_err(|_| ())?;
    request.validate(now()?).map_err(|_| ())?;
    if !authorization.is_current(now()?) || connection.close_reason().is_some() {
        return Err(());
    }
    let nonce = request.nonce;
    let expires_at = request.expires_at;
    let state_directory = Arc::clone(&context.state_directory);
    let authorization_for_sign = authorization.clone();
    let connection_for_sign = connection.clone();
    let signing = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        vault::sign_member(&state_directory, &SecureEnclave, requester, &request, || {
            now().is_ok_and(|time| authorization_for_sign.is_current(time))
                && connection_for_sign.close_reason().is_none()
        })
    })
    .await
    .map_err(|_| ())?;
    if !authorization.is_current(now()?) || now()? > expires_at || connection.close_reason().is_some() {
        return Err(());
    }
    let reply = match signing {
        Ok(signed) => SignReply::Signed {
            nonce,
            public_key: signed.identity.public_key,
            signature: signed.signature,
        },
        Err(_) => SignReply::Refused { nonce },
    };
    let bytes = reply.encode().map_err(|_| ())?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(());
    }
    let tag = agent_sign_protocol::response_tag(&exporter, &binding, &bytes).map_err(|_| ())?;
    send.write_all(&u16::try_from(bytes.len()).map_err(|_| ())?.to_be_bytes())
        .await
        .map_err(|_| ())?;
    send.write_all(&bytes).await.map_err(|_| ())?;
    send.write_all(&tag).await.map_err(|_| ())?;
    send.finish().map_err(|_| ())?;
    Ok(())
}

fn now() -> Result<u64, ()> {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ())
}

pub(super) async fn outgoing(
    connection: Connection,
    authorization: SessionAuthorization,
    hive: HiveId,
    requester: NodeId,
    signer: NodeId,
    request: SignRequest,
) -> Result<SignReply, &'static str> {
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        if !authorization.is_current(now()?) || connection.close_reason().is_some() {
            return Err(());
        }
        request.validate(now()?).map_err(|_| ())?;
        let (mut send, mut receive) = peer_stream::open(&connection, StreamKind::AgentSign)
            .await
            .map_err(|_| ())?;
        let mut exporter = [0_u8; 32];
        connection
            .export_keying_material(&mut exporter, EXPORTER_LABEL, EXPORTER_CONTEXT)
            .map_err(|_| ())?;
        let binding = MacBinding {
            hive,
            requester,
            signer,
            stream: u64::from(send.id()),
        };
        let bytes = request.encode().map_err(|_| ())?;
        let tag = agent_sign_protocol::request_tag(&exporter, &binding, &bytes).map_err(|_| ())?;
        send.write_all(&u16::try_from(bytes.len()).map_err(|_| ())?.to_be_bytes())
            .await
            .map_err(|_| ())?;
        send.write_all(&bytes).await.map_err(|_| ())?;
        send.write_all(&tag).await.map_err(|_| ())?;
        send.finish().map_err(|_| ())?;
        let mut length = [0_u8; 2];
        receive.read_exact(&mut length).await.map_err(|_| ())?;
        let size = usize::from(u16::from_be_bytes(length));
        if size == 0 || size > MAX_RESPONSE_BYTES {
            return Err(());
        }
        let mut reply_bytes = vec![0_u8; size];
        receive.read_exact(&mut reply_bytes).await.map_err(|_| ())?;
        let mut reply_tag = [0_u8; 32];
        receive.read_exact(&mut reply_tag).await.map_err(|_| ())?;
        if !receive.read_to_end(1).await.map_err(|_| ())?.is_empty() {
            return Err(());
        }
        agent_sign_protocol::verify_response_tag(&exporter, &binding, &reply_bytes, &reply_tag).map_err(|_| ())?;
        let reply = SignReply::decode(&reply_bytes).map_err(|_| ())?;
        if reply.nonce() != &request.nonce
            || !authorization.is_current(now()?)
            || request.validate(now()?).is_err()
            || connection.close_reason().is_some()
        {
            return Err(());
        }
        Ok(reply)
    })
    .await
    .map_err(|_| "member signing timed out")?
    .map_err(|()| "member signing failed or was refused")
}
