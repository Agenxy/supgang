//! Session-authorized, bounded transport to explicit loopback services.

use std::{path::Path, sync::Arc, time::Duration};

use quinn::{RecvStream, SendStream};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Semaphore, watch},
};

use crate::{
    peer_stream::{self, StreamKind},
    record::ServiceName,
    tunnel_policy::{self, ExposureSnapshot, TunnelPolicy},
};

use super::{
    active::{ActiveConnection, SessionAuthorization},
    unix_time,
};

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(super) struct TunnelRuntime {
    pub(super) policy: watch::Sender<TunnelPolicy>,
    pub(super) admission: Arc<Semaphore>,
    pub(super) admission_total: usize,
}

impl TunnelRuntime {
    pub(super) fn new(directory: &Path) -> Result<Self, String> {
        let policy = tunnel_policy::load(directory)?;
        let admission_total = policy.total;
        let admission = Arc::new(Semaphore::new(policy.total));
        let (policy, _) = watch::channel(policy);
        Ok(Self {
            policy,
            admission,
            admission_total,
        })
    }

    pub(super) fn exposure_reply(&self) -> crate::control::ControlReply {
        crate::control::ControlReply::Exposures {
            value: ExposureSnapshot::from_policy(&self.policy.borrow(), Some(self.admission_total)),
        }
    }

    /// Saves new tunnel limits while the service runs. New connections take
    /// the per-peer and idle limits at once; the runtime-wide admission budget
    /// is sized at start, so a raised total applies after the next restart.
    /// Active tunnels are unaffected: only a changed exposure ends them.
    pub(super) fn save_limits(
        &self,
        directory: &Path,
        per_peer: usize,
        total: usize,
        idle_seconds: u64,
    ) -> Result<(), String> {
        let mut policy = self.policy.borrow().clone();
        policy.per_peer = per_peer;
        policy.total = total;
        policy.idle_seconds = idle_seconds;
        tunnel_policy::save(directory, &policy)?;
        self.policy.send_replace(policy);
        Ok(())
    }

    pub(super) fn expose(&self, directory: &Path, name: ServiceName, port: u16) -> Result<(), String> {
        let mut policy = self.policy.borrow().clone();
        policy.set(name, port)?;
        tunnel_policy::save(directory, &policy)?;
        self.policy.send_replace(policy);
        Ok(())
    }
}

pub(super) async fn incoming(
    mut send: SendStream,
    mut receive: RecvStream,
    runtime: TunnelRuntime,
    authorization: SessionAuthorization,
    peer_admission: Arc<Semaphore>,
) {
    let Ok(_global) = runtime.admission.clone().try_acquire_owned() else {
        return;
    };
    let Ok(_peer) = peer_admission.try_acquire_owned() else {
        return;
    };
    let mut policy = runtime.policy.subscribe();
    let setup = async {
        if !authorization.is_current(unix_time().map_err(|_| ())?) {
            return Err(());
        }
        let mut bytes = [0; 16];
        receive.read_exact(&mut bytes).await.map_err(|_| ())?;
        let name = tunnel_policy::decoded_name(bytes).map_err(|_| ())?;
        let port = policy.borrow().port(&name).ok_or(())?;
        if !authorization.is_current(unix_time().map_err(|_| ())?) {
            return Err(());
        }
        let socket = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(|_| ())?;
        if !authorization.is_current(unix_time().map_err(|_| ())?) {
            return Err(());
        }
        send.write_all(&[1]).await.map_err(|_| ())?;
        Ok((socket, name, port))
    };
    let setup = tokio::select! {
        result = tokio::time::timeout(SETUP_TIMEOUT, setup) => result,
        () = authorization.wait_until_invalid(unix_time().unwrap_or(u64::MAX)) => return,
    };
    let Ok(Ok((socket, name, port))) = setup else {
        return;
    };
    let idle = Duration::from_secs(policy.borrow().idle_seconds);
    let (read, write) = socket.into_split();
    let transfer = bridge(read, write, send, receive, idle);
    let cancellation = async {
        while policy.borrow().port(&name) == Some(port) {
            if policy.changed().await.is_err() {
                break;
            }
        }
    };
    tokio::select! {
        _result = transfer => {}
        () = authorization.wait_until_invalid(unix_time().unwrap_or(u64::MAX)) => {}
        () = cancellation => {}
    }
}

pub(super) async fn outgoing(
    mut local: tokio::net::UnixStream,
    active: ActiveConnection,
    name: ServiceName,
    runtime: TunnelRuntime,
    global: tokio::sync::OwnedSemaphorePermit,
    peer: tokio::sync::OwnedSemaphorePermit,
) {
    let _admission = (global, peer);
    let setup = async {
        let (mut send, mut receive) = peer_stream::open(active.connection(), StreamKind::Service)
            .await
            .map_err(|_| ())?;
        send.write_all(&tunnel_policy::encoded_name(&name))
            .await
            .map_err(|_| ())?;
        let mut accepted = [0];
        receive.read_exact(&mut accepted).await.map_err(|_| ())?;
        if accepted != [1] {
            return Err(());
        }
        Ok((send, receive))
    };
    let setup = tokio::select! {
        result = tokio::time::timeout(SETUP_TIMEOUT, setup) => result,
        () = active.authorization().wait_until_invalid(unix_time().unwrap_or(u64::MAX)) => return,
    };
    let Ok(Ok((send, receive))) = setup else {
        let _reply = crate::control::write_reply(
            &mut local,
            &crate::control::ControlReply::Error {
                message:
                    "peer refused the service or service setup timed out; check target exposure and runtime version"
                        .to_owned(),
            },
        )
        .await;
        return;
    };
    if crate::control::write_reply_open(&mut local, &crate::control::ControlReply::Connected)
        .await
        .is_err()
    {
        return;
    }
    let idle = Duration::from_secs(runtime.policy.borrow().idle_seconds);
    let (read, write) = local.into_split();
    tokio::select! {
        _result = bridge(read, write, send, receive, idle) => {}
        () = active.authorization().wait_until_invalid(unix_time().unwrap_or(u64::MAX)) => {}
    }
}

async fn bridge<R, W>(read: R, write: W, send: SendStream, receive: RecvStream, idle: Duration) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (activity, mut observed) = watch::channel(tokio::time::Instant::now());
    let transfer = async {
        tokio::try_join!(copy(read, send, &activity), copy(receive, write, &activity))?;
        Ok(())
    };
    let idle_deadline = async {
        loop {
            let deadline = *observed.borrow() + idle;
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => return,
                result = observed.changed() => { if result.is_err() { return; } }
            }
        }
    };
    tokio::select! {
        result = transfer => result,
        () = idle_deadline => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "service tunnel was idle")),
    }
}

async fn copy<R, W>(mut read: R, mut write: W, activity: &watch::Sender<tokio::time::Instant>) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut bytes = vec![0; 16 * 1_024];
    loop {
        let count = read.read(&mut bytes).await?;
        if count == 0 {
            return write.shutdown().await;
        }
        activity.send_replace(tokio::time::Instant::now());
        write
            .write_all(
                bytes
                    .get(..count)
                    .ok_or_else(|| std::io::Error::other("copy length invalid"))?,
            )
            .await?;
        activity.send_replace(tokio::time::Instant::now());
    }
}
