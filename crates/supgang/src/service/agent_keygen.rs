//! Authenticated member creation of an immutable agent-purpose vault key.

use std::{sync::Arc, time::Duration};

use quinn::{Connection, RecvStream, SendStream};

use crate::{
    agent_keygen_protocol::{self, KeygenReply, KeygenRequest, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES},
    agent_sign_protocol::MacBinding,
    ids::{HiveId, NodeId},
    peer_stream::{self, StreamKind},
    vault::{self, SecureEnclave},
};

use super::{PeerEvent, active::SessionAuthorization, peer_actor::PeerUpdateContext};

const EXPORTER_LABEL: &[u8] = b"supgang/agent-keygen/exporter/v1";
// Creating the first vault agreement key may take up to one minute.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(90);

pub(super) fn spawn(
    tasks: &mut tokio::task::JoinSet<()>,
    context: Option<&PeerUpdateContext>,
    connection: &Connection,
    streams: (SendStream, RecvStream),
    requester: NodeId,
    authorization: &SessionAuthorization,
    events: &tokio::sync::mpsc::Sender<PeerEvent>,
) {
    while tasks.try_join_next().is_some() {}
    if let Some(context) = context
        && tasks.len() < 4
    {
        tasks.spawn(incoming(
            connection.clone(),
            streams.0,
            streams.1,
            requester,
            authorization.clone(),
            context.clone(),
            events.clone(),
        ));
    }
}

async fn incoming(
    connection: Connection,
    mut send: SendStream,
    mut receive: RecvStream,
    requester: NodeId,
    authorization: SessionAuthorization,
    context: PeerUpdateContext,
    events: tokio::sync::mpsc::Sender<PeerEvent>,
) {
    let Ok(permit) = Arc::clone(&context.sign_admission).try_acquire_owned() else {
        return;
    };
    let _result = tokio::time::timeout(
        REQUEST_TIMEOUT,
        process(
            &connection,
            (&mut send, &mut receive),
            requester,
            &authorization,
            &context,
            &events,
            permit,
        ),
    )
    .await;
}

async fn process(
    connection: &Connection,
    streams: (&mut SendStream, &mut RecvStream),
    requester: NodeId,
    authorization: &SessionAuthorization,
    context: &PeerUpdateContext,
    events: &tokio::sync::mpsc::Sender<PeerEvent>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<(), ()> {
    let (send, receive) = streams;
    if !authorization.is_current(now()?) || connection.close_reason().is_some() {
        return Err(());
    }
    let mut exporter = [0_u8; 32];
    connection
        .export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
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
    agent_keygen_protocol::verify_request_tag(&exporter, &binding, &bytes, &tag).map_err(|_| ())?;
    let request = KeygenRequest::decode(&bytes).map_err(|_| ())?;
    request.validate(now()?).map_err(|_| ())?;
    if !authorization.is_current(now()?) || connection.close_reason().is_some() {
        return Err(());
    }
    let nonce = request.nonce;
    let directory = Arc::clone(&context.state_directory);
    let preparation_request = request.clone();
    let preparation_authorization = authorization.clone();
    let preparation_connection = connection.clone();
    let (prepared, permit) = tokio::task::spawn_blocking(move || {
        let prepared = vault::prepare_member_vault(&directory, &SecureEnclave, requester, &preparation_request, || {
            now().is_ok_and(|time| preparation_authorization.is_current(time))
                && preparation_connection.close_reason().is_none()
        })
        .ok();
        (prepared, permit)
    })
    .await
    .map_err(|_| ())?;
    let Some(prepared) = prepared else {
        return Err(());
    };
    if !authorization.is_current(now()?) || connection.close_reason().is_some() {
        return Err(());
    }
    let (reply_sender, reply_receiver) = tokio::sync::oneshot::channel();
    events
        .send(PeerEvent::AgentKeygen {
            peer: requester,
            connection_id: connection.stable_id(),
            request,
            prepared,
            reply: reply_sender,
            permit,
        })
        .await
        .map_err(|_| ())?;
    let creation = reply_receiver.await.map_err(|_| ())?;
    // A committed activation is a historical result even if the session or
    // request deadline changes while its final audit fsync is completing.
    let reply = creation.map_or(KeygenReply::Refused { nonce }, |public_key| KeygenReply::Created {
        nonce,
        public_key,
    });
    let bytes = reply.encode().map_err(|_| ())?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(());
    }
    let tag = agent_keygen_protocol::response_tag(&exporter, &binding, &bytes).map_err(|_| ())?;
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
    request: KeygenRequest,
) -> Result<KeygenReply, &'static str> {
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        if !authorization.is_current(now()?) || connection.close_reason().is_some() {
            return Err(());
        }
        request.validate(now()?).map_err(|_| ())?;
        let (mut send, mut receive) = peer_stream::open(&connection, StreamKind::AgentKeygen)
            .await
            .map_err(|_| ())?;
        let mut exporter = [0_u8; 32];
        connection
            .export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
            .map_err(|_| ())?;
        let binding = MacBinding {
            hive,
            requester,
            signer,
            stream: u64::from(send.id()),
        };
        let bytes = request.encode().map_err(|_| ())?;
        let tag = agent_keygen_protocol::request_tag(&exporter, &binding, &bytes).map_err(|_| ())?;
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
        let mut bytes = vec![0_u8; size];
        receive.read_exact(&mut bytes).await.map_err(|_| ())?;
        let mut tag = [0_u8; 32];
        receive.read_exact(&mut tag).await.map_err(|_| ())?;
        if !receive.read_to_end(1).await.map_err(|_| ())?.is_empty() {
            return Err(());
        }
        agent_keygen_protocol::verify_response_tag(&exporter, &binding, &bytes, &tag).map_err(|_| ())?;
        let reply = KeygenReply::decode(&bytes).map_err(|_| ())?;
        if reply.nonce() != &request.nonce {
            return Err(());
        }
        Ok(reply)
    })
    .await
    .map_err(|_| "member key creation timed out")?
    .map_err(|()| "member key creation failed or was refused")
}
