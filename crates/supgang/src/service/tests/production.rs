//! Exercise the production scheduler, directory, admission and actor registry.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use super::super::{ServiceConfig, ServiceError, make_local_contact, service_loop, unix_time};
use crate::{
    contact::PeerContact,
    control::{self, ControlListener, ControlReply, ControlRequest},
    ids::NodeId,
    invitation::JoinBundle,
    membership::MembershipRoles,
    peer_directory::PeerDirectory,
    profile::PeerName,
    state::{self, LocalState},
    transport::TransportIdentity,
    transport_storage,
};

struct Peer {
    path: PathBuf,
    state: LocalState,
    directory: PeerDirectory,
    identity: TransportIdentity,
    endpoint: quinn::Endpoint,
    config: ServiceConfig,
    contact: PeerContact,
}

impl Peer {
    fn new(
        path: &Path,
        mut state: LocalState,
        listen: std::net::SocketAddr,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let identity = transport_storage::load_or_create(path)?;
        let endpoint = quinn::Endpoint::server(identity.server_config()?, listen)?;
        let listen = endpoint.local_addr()?;
        let config = ServiceConfig::new(PeerName::new("Production Test")?, listen, &[listen], &[])?
            .with_intervals(Duration::from_secs(1), Duration::from_hours(1))?;
        let contact = make_local_contact(&mut state, &identity, &config)?;
        let directory = PeerDirectory::open(
            path,
            state.identity().root_verifying_key,
            state.identity().device.node_id(),
            state.revocations(),
        )?;
        Ok(Self {
            path: path.to_path_buf(),
            state,
            directory,
            identity,
            endpoint,
            config,
            contact,
        })
    }

    fn start(mut self) -> Result<tokio::task::JoinHandle<Result<(), ServiceError>>, control::ControlError> {
        // Match production readiness: bind and protect the socket before clients poll it.
        let control = ControlListener::bind(&self.path)?;
        Ok(tokio::spawn(async move {
            service_loop(
                self.endpoint,
                self.identity,
                &control,
                &self.path,
                &mut self.state,
                &mut self.directory,
                self.config,
            )
            .await
        }))
    }
}

async fn connected(path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let path = path.to_path_buf();
    let reply = tokio::task::spawn_blocking(move || control::request(&path, ControlRequest::Peers)).await??;
    Ok(
        matches!(reply, Some(ControlReply::Peers { value }) if value.peers.len() == 1
        && value.peers.iter().all(|peer| peer.status == "fresh" && peer.connected == Some(true)
            && peer.connection.as_ref().is_some_and(|connection| connection.received_datagrams > 0))),
    )
}

async fn wait_connected(paths: &[&Path]) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let mut ready = true;
            for path in paths {
                ready &= connected(path).await?;
            }
            if ready {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn two_fresh_local_only_services_connect_and_reconnect_after_restart() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let left_path = temporary.path().join("left");
    let right_path = temporary.path().join("right");
    let mut founder = state::initialize(&left_path)?;
    let request = state::create_join_request(&right_path)?;
    let now = unix_time()?;
    let member = founder.authorize_join_request(
        &request,
        NodeId::from_verifying_key(&request.device_verifying_key),
        MembershipRoles::DEVICE,
        now,
        now + 86_400,
    )?;
    let bundle = JoinBundle::new(
        founder.identity().root.as_ref().ok_or("root")?,
        member,
        founder.revocations().clone(),
        now,
    )?;
    let joined = state::install_join_bundle(&right_path, &bundle, founder.identity().hive_id)?;
    let mut left = Peer::new(&left_path, founder, "127.0.0.1:0".parse()?)?;
    let mut right = Peer::new(&right_path, joined, "127.0.0.1:0".parse()?)?;
    left.directory.import(right.contact.clone(), now)?;
    right.directory.import(left.contact.clone(), now)?;
    let listen = left.endpoint.local_addr()?;
    let left_endpoint = left.endpoint.clone();
    let left_task = left.start()?;
    let right_task = right.start()?;
    let initial = wait_connected(&[&left_path, &right_path]).await;
    if initial.is_err() {
        left_task.abort();
        right_task.abort();
        return initial;
    }
    left_endpoint.close(0_u8.into(), b"test service restart");
    left_task.abort();
    assert!(left_task.await.is_err_and(|error| error.is_cancelled()));
    tokio::time::timeout(Duration::from_secs(5), left_endpoint.wait_idle()).await?;
    drop(left_endpoint);
    tokio::task::yield_now().await;
    let restarted = Peer::new(&left_path, state::open(&left_path)?, listen)?.start()?;
    let recovered = wait_connected(&[&left_path, &right_path]).await;
    restarted.abort();
    right_task.abort();
    let _left = restarted.await;
    let _right = right_task.await;
    recovered
}
