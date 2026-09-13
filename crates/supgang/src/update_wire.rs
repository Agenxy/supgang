//! Root-authorized, TUF-verified update carriage over an authenticated peer stream.

use std::{
    fs::File,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime},
};

use ed25519_dalek::VerifyingKey;
use quinn::{Connection, RecvStream, SendStream};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    ids::{HiveId, NodeId},
    peer_stream::{self, StreamKind},
    service::SessionAuthorization,
    update::{
        MAX_UPDATE_BUNDLE_BYTES, UpdateAuthorization, UpdateError, decode_authorization, encode_authorization,
        incoming_bundle,
    },
};

const REPLY_ACCEPTED: u8 = 1;
const REPLY_REJECTED: u8 = 2;
const REPLY_RETRY_LATER: u8 = 3;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const REPLY_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const EARLY_REJECTION_GRACE: Duration = Duration::from_secs(2);
const PREFACE_TIMEOUT: Duration = Duration::from_secs(2);
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_TRANSFER_TIMEOUT: Duration = Duration::from_mins(3);

#[derive(Clone, Copy)]
pub struct ReceiveContext<'a> {
    pub(crate) state_directory: &'a Path,
    pub(crate) root_key: &'a VerifyingKey,
    pub(crate) hive_id: HiveId,
    pub(crate) local_node: NodeId,
    pub(crate) authenticated_peer: NodeId,
    pub(crate) authorization: &'a SessionAuthorization,
    pub(crate) admission: &'a Arc<tokio::sync::Semaphore>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum UpdateWireError {
    #[error("peer update carriage failed")]
    Failed,
    #[error("peer rejected the proposed signed update")]
    Rejected,
    #[error("peer is not ready to receive the proposed signed update")]
    RetryLater,
    #[error("peer update authorization preface is invalid or stalled")]
    InvalidPreface,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reply {
    Accepted,
    Rejected,
    RetryLater,
}

pub async fn send(
    connection: &Connection,
    authorization: &UpdateAuthorization,
    file: File,
) -> Result<(), UpdateWireError> {
    let length = file.metadata().map_err(|_| UpdateWireError::Failed)?.len();
    if !(1..=MAX_UPDATE_BUNDLE_BYTES).contains(&length) || length != authorization.bundle_length {
        return Err(UpdateWireError::Failed);
    }
    let authorization = encode_authorization(authorization).map_err(|_| UpdateWireError::Failed)?;
    let (mut send, mut receive) = peer_stream::open(connection, StreamKind::Update)
        .await
        .map_err(|_| UpdateWireError::Failed)?;
    let auth_length = u16::try_from(authorization.len()).map_err(|_| UpdateWireError::Failed)?;
    send.write_all(&auth_length.to_be_bytes())
        .await
        .map_err(|_| UpdateWireError::Failed)?;
    send.write_all(&authorization)
        .await
        .map_err(|_| UpdateWireError::Failed)?;
    send.write_all(&length.to_be_bytes())
        .await
        .map_err(|_| UpdateWireError::Failed)?;
    let mut source = tokio::fs::File::from_std(file);
    let upload = async move {
        let mut remaining = length;
        let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
        while remaining > 0 {
            let wanted =
                usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64)).map_err(|_| UpdateWireError::Failed)?;
            let count = source
                .read(buffer.get_mut(..wanted).ok_or(UpdateWireError::Failed)?)
                .await
                .map_err(|_| UpdateWireError::Failed)?;
            if count == 0 {
                return Err(UpdateWireError::Failed);
            }
            send.write_all(buffer.get(..count).ok_or(UpdateWireError::Failed)?)
                .await
                .map_err(|_| UpdateWireError::Failed)?;
            remaining = remaining
                .checked_sub(u64::try_from(count).map_err(|_| UpdateWireError::Failed)?)
                .ok_or(UpdateWireError::Failed)?;
        }
        send.finish().map_err(|_| UpdateWireError::Failed)
    };
    let reply = read_reply(&mut receive);
    tokio::pin!(upload);
    tokio::pin!(reply);
    let upload_result = tokio::select! {
        biased;
        early_reply = &mut reply => {
            return match early_reply? {
                Reply::Accepted => Err(UpdateWireError::Failed),
                Reply::Rejected => Err(UpdateWireError::Rejected),
                Reply::RetryLater => Err(UpdateWireError::RetryLater),
            };
        }
        upload_result = &mut upload => upload_result,
    };
    if let Err(error) = upload_result {
        return match tokio::time::timeout(EARLY_REJECTION_GRACE, &mut reply).await {
            Ok(Ok(Reply::Rejected)) => Err(UpdateWireError::Rejected),
            Ok(Ok(Reply::RetryLater)) => Err(UpdateWireError::RetryLater),
            Ok(Ok(Reply::Accepted) | Err(_)) | Err(_) => Err(error),
        };
    }
    match reply.await? {
        Reply::Accepted => Ok(()),
        Reply::Rejected => Err(UpdateWireError::Rejected),
        Reply::RetryLater => Err(UpdateWireError::RetryLater),
    }
}

async fn read_reply(receive: &mut RecvStream) -> Result<Reply, UpdateWireError> {
    let mut reply = [0_u8; 1];
    receive
        .read_exact(&mut reply)
        .await
        .map_err(|_| UpdateWireError::Failed)?;
    let mut trailing = [0_u8; 1];
    if receive
        .read(&mut trailing)
        .await
        .map_err(|_| UpdateWireError::Failed)?
        .is_some()
    {
        return Err(UpdateWireError::Failed);
    }
    match reply[0] {
        REPLY_ACCEPTED => Ok(Reply::Accepted),
        REPLY_REJECTED => Ok(Reply::Rejected),
        REPLY_RETRY_LATER => Ok(Reply::RetryLater),
        _ => Err(UpdateWireError::Failed),
    }
}

pub async fn receive(
    send: SendStream,
    mut receive: RecvStream,
    context: ReceiveContext<'_>,
) -> Result<Option<[u8; 32]>, UpdateWireError> {
    let result = receive_inner(&mut receive, context).await;
    let (accepted, reply) = match result {
        Ok(digest) => (Some(digest), REPLY_ACCEPTED),
        Err(UpdateWireError::RetryLater | UpdateWireError::Failed | UpdateWireError::InvalidPreface) => {
            (None, REPLY_RETRY_LATER)
        }
        Err(UpdateWireError::Rejected) => (None, REPLY_REJECTED),
    };
    if write_reply(send, reply).await.is_err() {
        return Err(UpdateWireError::Failed);
    }
    match result {
        Ok(_) => Ok(accepted),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
pub async fn retry_later(send: SendStream) -> Result<(), UpdateWireError> {
    write_reply(send, REPLY_RETRY_LATER).await
}

async fn write_reply(mut send: SendStream, reply: u8) -> Result<(), UpdateWireError> {
    send.write_all(&[reply]).await.map_err(|_| UpdateWireError::Failed)?;
    send.finish().map_err(|_| UpdateWireError::Failed)?;
    let _drained = tokio::time::timeout(REPLY_DRAIN_TIMEOUT, send.stopped()).await;
    Ok(())
}

async fn receive_inner(receive: &mut RecvStream, context: ReceiveContext<'_>) -> Result<[u8; 32], UpdateWireError> {
    let authorization = tokio::time::timeout(PREFACE_TIMEOUT, read_authorization(receive))
        .await
        .map_err(|_| UpdateWireError::InvalidPreface)??;
    let now = current_time().map_err(|_| UpdateWireError::RetryLater)?;
    if !context.authorization.is_current(now) {
        return Err(UpdateWireError::Rejected);
    }
    authorization
        .verify(
            context.root_key,
            context.hive_id,
            context.authenticated_peer,
            context.local_node,
            now,
        )
        .map_err(|_| UpdateWireError::InvalidPreface)?;
    let _admission = tokio::time::timeout(ADMISSION_TIMEOUT, Arc::clone(context.admission).acquire_owned())
        .await
        .map_err(|_| UpdateWireError::RetryLater)?
        .map_err(|_| UpdateWireError::RetryLater)?;
    let reservation_lock =
        crate::update::UpdateLock::acquire(context.state_directory).map_err(|error| map_update_error(&error))?;
    crate::update::reserve_authorization(context.state_directory, &authorization, now, &reservation_lock)
        .map_err(|error| map_update_error(&error))?;
    drop(reservation_lock);
    receive_authorized_body(receive, context, &authorization).await
}

async fn read_authorization(receive: &mut RecvStream) -> Result<UpdateAuthorization, UpdateWireError> {
    let mut auth_length = [0_u8; 2];
    receive
        .read_exact(&mut auth_length)
        .await
        .map_err(|_| UpdateWireError::InvalidPreface)?;
    let auth_length = usize::from(u16::from_be_bytes(auth_length));
    if !(1..=256).contains(&auth_length) {
        return Err(UpdateWireError::InvalidPreface);
    }
    let mut auth_bytes = vec![0_u8; auth_length];
    receive
        .read_exact(&mut auth_bytes)
        .await
        .map_err(|_| UpdateWireError::InvalidPreface)?;
    decode_authorization(&auth_bytes).map_err(|_| UpdateWireError::InvalidPreface)
}

async fn receive_authorized_body(
    receive: &mut RecvStream,
    context: ReceiveContext<'_>,
    authorization: &UpdateAuthorization,
) -> Result<[u8; 32], UpdateWireError> {
    let mut length = [0_u8; 8];
    receive
        .read_exact(&mut length)
        .await
        .map_err(|_| UpdateWireError::Failed)?;
    let length = u64::from_be_bytes(length);
    if !(1..=MAX_UPDATE_BUNDLE_BYTES).contains(&length) || length != authorization.bundle_length {
        return Err(UpdateWireError::Rejected);
    }
    let incoming = incoming_bundle(context.state_directory).map_err(|error| map_update_error(&error))?;
    let path = incoming.path.clone();
    let mut destination = tokio::fs::File::from_std(incoming.file);
    let mut remaining = length;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let transfer: Result<(), UpdateWireError> = tokio::time::timeout(BODY_TRANSFER_TIMEOUT, async {
        while remaining > 0 {
            let wanted =
                usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64)).map_err(|_| UpdateWireError::Failed)?;
            receive
                .read_exact(buffer.get_mut(..wanted).ok_or(UpdateWireError::Failed)?)
                .await
                .map_err(|_| UpdateWireError::Failed)?;
            let bytes = buffer.get(..wanted).ok_or(UpdateWireError::Failed)?;
            destination
                .write_all(bytes)
                .await
                .map_err(|_| UpdateWireError::Failed)?;
            hasher.update(bytes);
            remaining = remaining
                .checked_sub(u64::try_from(wanted).map_err(|_| UpdateWireError::Failed)?)
                .ok_or(UpdateWireError::Failed)?;
        }
        let mut trailing = [0_u8; 1];
        if receive
            .read(&mut trailing)
            .await
            .map_err(|_| UpdateWireError::Failed)?
            .is_some()
        {
            return Err(UpdateWireError::Rejected);
        }
        destination.sync_all().await.map_err(|_| UpdateWireError::Failed)?;
        Ok(())
    })
    .await
    .map_err(|_| UpdateWireError::RetryLater)?;
    drop(destination);
    if let Err(error) = transfer {
        let _removed = tokio::fs::remove_file(&path).await;
        return Err(error);
    }
    if hasher.finalize().as_slice() != authorization.bundle_digest {
        let _removed = tokio::fs::remove_file(&path).await;
        return Err(UpdateWireError::Rejected);
    }
    let digest = authorization.bundle_digest;
    let verify_now = current_time().map_err(|_| UpdateWireError::RetryLater)?;
    if !context.authorization.is_current(verify_now) {
        let _removed = tokio::fs::remove_file(&path).await;
        return Err(UpdateWireError::Rejected);
    }
    let update_lock =
        crate::update::UpdateLock::acquire(context.state_directory).map_err(|error| map_update_error(&error))?;
    let verified = crate::update::verify_and_stage_locked(context.state_directory, &path, update_lock).await;
    let _removed = tokio::fs::remove_file(&path).await;
    verified.map_err(|error| map_update_error(&error))?;
    Ok(digest)
}

fn current_time() -> Result<u64, std::time::SystemTimeError> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
}

const fn map_update_error(error: &UpdateError) -> UpdateWireError {
    match error {
        UpdateError::InvalidBundle
        | UpdateError::TrustAlreadyPinned
        | UpdateError::InvalidTrustRoot
        | UpdateError::Tuf
        | UpdateError::WrongPlatform
        | UpdateError::InvalidTargetName
        | UpdateError::Rollback
        | UpdateError::InvalidExecutable
        | UpdateError::IncompatibleCodeIdentity
        | UpdateError::ReplayedAuthorization => UpdateWireError::Rejected,
        UpdateError::Storage(_)
        | UpdateError::Io(_)
        | UpdateError::Artifact(_)
        | UpdateError::MissingTrustRoot
        | UpdateError::Busy
        | UpdateError::Capacity => UpdateWireError::RetryLater,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        net::SocketAddr,
        os::unix::fs::PermissionsExt,
        time::Duration,
    };

    use super::{UpdateWireError, map_update_error};

    #[test]
    fn local_readiness_failures_retry_but_invalid_releases_are_terminal() {
        assert_eq!(
            map_update_error(&crate::update::UpdateError::Busy),
            UpdateWireError::RetryLater,
        );
        assert_eq!(
            map_update_error(&crate::update::UpdateError::MissingTrustRoot),
            UpdateWireError::RetryLater,
        );
        assert_eq!(
            map_update_error(&crate::update::UpdateError::Tuf),
            UpdateWireError::Rejected
        );
        assert_eq!(
            map_update_error(&crate::update::UpdateError::Rollback),
            UpdateWireError::Rejected,
        );
    }

    #[test]
    fn an_early_retry_interrupts_a_flow_control_blocked_upload_without_losing_the_delivery()
    -> Result<(), Box<dyn std::error::Error>> {
        crate::transport::build_runtime()?.block_on(async {
            let temporary = tempfile::tempdir()?;
            let bundle = temporary.path().join("bundle");
            fs::write(&bundle, vec![7_u8; 2 * 1024 * 1024])?;
            fs::set_permissions(&bundle, fs::Permissions::from_mode(0o600))?;
            let root = crate::identity::RootIdentity::generate()?;
            let issuer = crate::identity::DeviceIdentity::generate()?.node_id();
            let target = crate::identity::DeviceIdentity::generate()?.node_id();
            let authorization =
                crate::update::UpdateAuthorization::sign(&root, issuer, target, [9; 32], 2 * 1024 * 1024, 100)?;

            let server_identity = crate::transport::TransportIdentity::generate()?;
            let server =
                quinn::Endpoint::server(server_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let client_identity = crate::transport::TransportIdentity::generate()?;
            let client =
                quinn::Endpoint::server(client_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let accepting = server.clone();
            let accepted = tokio::spawn(async move {
                accepting
                    .accept()
                    .await
                    .ok_or("server endpoint closed")?
                    .await
                    .map_err(|error| error.to_string())
            });
            let client_connection = tokio::time::timeout(
                Duration::from_secs(5),
                client.connect_with(
                    crate::transport::pinned_client_config(server_identity.key_id())?,
                    server.local_addr()?,
                    "supgang.invalid",
                )?,
            )
            .await??;
            let server_connection = accepted.await??;
            let receiver = tokio::spawn(async move {
                let (kind, send, _receive) = crate::peer_stream::accept(&server_connection)
                    .await
                    .map_err(|error| error.to_string())?;
                if kind != crate::peer_stream::StreamKind::Update {
                    return Err("unexpected stream kind".to_owned());
                }
                super::retry_later(send).await.map_err(|error| error.to_string())
            });
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                super::send(&client_connection, &authorization, File::open(bundle)?),
            )
            .await?;
            assert_eq!(result, Err(UpdateWireError::RetryLater));
            receiver.await??;
            server.close(0_u8.into(), b"test complete");
            client.close(0_u8.into(), b"test complete");
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn stalled_authorization_preface_never_holds_update_admission() -> Result<(), Box<dyn std::error::Error>> {
        crate::transport::build_runtime()?.block_on(async {
            let temporary = tempfile::tempdir()?;
            let state = temporary.path().join("state");
            let local = crate::state::initialize(&state)?;
            let root = crate::identity::RootIdentity::generate()?;
            let issuer = crate::identity::DeviceIdentity::generate()?.node_id();
            let target = local.identity().device.node_id();
            let server_identity = crate::transport::TransportIdentity::generate()?;
            let server =
                quinn::Endpoint::server(server_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let client_identity = crate::transport::TransportIdentity::generate()?;
            let client =
                quinn::Endpoint::server(client_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let accepting = server.clone();
            let accepted = tokio::spawn(async move {
                accepting
                    .accept()
                    .await
                    .ok_or("server endpoint closed")?
                    .await
                    .map_err(|error| error.to_string())
            });
            let client_connection = client
                .connect_with(
                    crate::transport::pinned_client_config(server_identity.key_id())?,
                    server.local_addr()?,
                    "supgang.invalid",
                )?
                .await?;
            let server_connection = accepted.await??;
            let (_client_send, mut client_receive) =
                crate::peer_stream::open(&client_connection, crate::peer_stream::StreamKind::Update).await?;
            let (kind, send, receive) = crate::peer_stream::accept(&server_connection).await?;
            assert_eq!(kind, crate::peer_stream::StreamKind::Update);
            let session =
                crate::service::SessionAuthorization::new(u64::MAX, 0).ok_or("session authorization rejected")?;
            let admission = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
            let receiver_admission = std::sync::Arc::clone(&admission);
            let receiver_state = state.clone();
            let root_key = root.verifying_key();
            let receiver = tokio::spawn(async move {
                super::receive(
                    send,
                    receive,
                    super::ReceiveContext {
                        state_directory: &receiver_state,
                        root_key: &root_key,
                        hive_id: root.hive_id(),
                        local_node: target,
                        authenticated_peer: issuer,
                        authorization: &session,
                        admission: &receiver_admission,
                    },
                )
                .await
            });
            tokio::time::sleep(Duration::from_millis(250)).await;
            let permit = admission.try_acquire()?;
            drop(permit);
            let mut reply = [0_u8; 1];
            tokio::time::timeout(Duration::from_secs(3), client_receive.read_exact(&mut reply)).await??;
            assert_eq!(reply[0], super::REPLY_RETRY_LATER);
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), receiver).await??,
                Err(UpdateWireError::InvalidPreface)
            );
            server.close(0_u8.into(), b"test complete");
            client.close(0_u8.into(), b"test complete");
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }
}
