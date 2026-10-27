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
        let advertised = if listen.ip().is_unspecified() {
            std::net::SocketAddr::from(([127, 0, 0, 1], listen.port()))
        } else {
            listen
        };
        let config = ServiceConfig::new(PeerName::new("Production Test")?, listen, &[advertised], &[])?
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
async fn named_tunnel_is_default_deny_and_preserves_bytes_and_half_close() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        founder.identity().root.as_ref().ok_or("root missing")?,
        member,
        founder.revocations().clone(),
        now,
    )?;
    let joined = state::install_join_bundle(&right_path, &bundle, founder.identity().hive_id)?;
    let target = joined.identity().device.node_id();
    let mut left = Peer::new(&left_path, founder, "127.0.0.1:0".parse()?)?;
    let mut right = Peer::new(&right_path, joined, "0.0.0.0:0".parse()?)?;
    left.directory.import(right.contact.clone(), now)?;
    right.directory.import(left.contact.clone(), now)?;
    let left_task = left.start()?;
    let right_task = right.start()?;
    let outcome = async {
        wait_connected(&[&left_path, &right_path]).await?;
        let path = right_path.clone();
        let mapped: std::net::SocketAddrV4 = "9.9.9.9:44330".parse()?;
        assert!(matches!(tokio::task::spawn_blocking(move || control::request(&path,
            ControlRequest::AddMapped { address: mapped })).await??, Some(ControlReply::EndpointChanged)));
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let path = left_path.clone();
                let reply = tokio::task::spawn_blocking(move || control::request(&path, ControlRequest::Resolve(target))).await??;
                if matches!(reply, Some(ControlReply::Resolve { value }) if value.candidates.iter().any(|candidate| candidate.address == mapped.to_string())) {
                    return Ok::<(), Box<dyn std::error::Error>>(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await??;
        let name = crate::tunnel_policy::encoded_name(&crate::record::ServiceName::new("ssh")?);
        let path = left_path.clone();
        assert!(
            tokio::task::spawn_blocking(move || control::connect_service(&path, target, name))
                .await?
                .is_err()
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let path = right_path.clone();
        assert!(matches!(
            tokio::task::spawn_blocking(move || { control::request(&path, ControlRequest::Expose { name, port }) })
                .await??,
            Some(ControlReply::ExposureChanged)
        ));
        wait_connected(&[&left_path, &right_path]).await?;
        let path = left_path.clone();
        let local = tokio::task::spawn_blocking(move || control::connect_service(&path, target, name)).await??;
        let mut local = tokio::net::UnixStream::from_std(local)?;
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await??;
        // Exceed a QUIC stream window to exercise backpressure. Reply only
        // after EOF so a premature full-close loses the response and fails.
        let payload = vec![0xa5; 96 * 1_024];
        let expected = payload.clone();
        let echo = tokio::spawn(async move {
            let mut bytes = Vec::new();
            (&mut socket).take(128 * 1_024).read_to_end(&mut bytes).await?;
            assert_eq!(bytes, expected);
            socket.write_all(&bytes).await?;
            socket.shutdown().await
        });
        local.write_all(&payload).await?;
        local.shutdown().await?;
        let mut received = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            (&mut local).take(128 * 1_024).read_to_end(&mut received),
        )
        .await??;
        assert_eq!(received, payload);
        echo.await??;
        let mut held = Vec::new();
        let mut targets = Vec::new();
        for _ in 0..4 {
            let path = left_path.clone();
            let socket = tokio::task::spawn_blocking(move || control::connect_service(&path, target, name)).await??;
            held.push(tokio::net::UnixStream::from_std(socket)?);
            targets.push(
                tokio::time::timeout(Duration::from_secs(2), listener.accept())
                    .await??
                    .0,
            );
        }
        let path = left_path.clone();
        assert!(
            tokio::task::spawn_blocking(move || control::connect_service(&path, target, name))
                .await?
                .is_err()
        );
        let path = right_path.clone();
        assert!(matches!(
            tokio::task::spawn_blocking(move || { control::request(&path, ControlRequest::Expose { name, port: 0 }) })
                .await??,
            Some(ControlReply::ExposureChanged)
        ));
        for socket in &mut held {
            let mut byte = [0];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), socket.read(&mut byte)).await??,
                0
            );
        }
        for socket in &mut targets {
            let mut byte = [0];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), socket.read(&mut byte)).await??,
                0
            );
        }
        wait_connected(&[&left_path, &right_path]).await?;
        let path = left_path.clone();
        assert!(
            tokio::task::spawn_blocking(move || control::connect_service(&path, target, name))
                .await?
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        let path = right_path.clone();
        assert!(matches!(
            tokio::task::spawn_blocking(move || control::request(&path, ControlRequest::Expose { name, port }))
                .await??,
            Some(ControlReply::ExposureChanged)
        ));
        wait_connected(&[&left_path, &right_path]).await?;
        let path = left_path.clone();
        let socket = tokio::task::spawn_blocking(move || control::connect_service(&path, target, name)).await??;
        let mut socket = tokio::net::UnixStream::from_std(socket)?;
        let (mut served, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await??;
        let path = left_path.clone();
        assert!(matches!(
            tokio::task::spawn_blocking(move || control::request(&path, ControlRequest::Revoke(target))).await??,
            Some(ControlReply::Revoked { .. })
        ));
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), socket.read(&mut byte)).await??,
            0
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), served.read(&mut byte)).await??,
            0
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    left_task.abort();
    right_task.abort();
    outcome
}

#[tokio::test]
async fn pending_activation_does_not_starve_control_or_peer_restart() -> Result<(), Box<dyn std::error::Error>> {
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
    let target = joined.identity().device.node_id();
    let executable = temporary.path().join("test-supgang");
    // A small signed platform executable keeps the update probe realistic
    // without making test-binary hashing dominate this timing regression.
    std::fs::copy("/usr/bin/true", &executable)?;
    std::fs::set_permissions(&executable, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    crate::update::initialize_installed(&left_path, &executable)?;
    // Keep a valid pending marker while exercising the service without its supervisor.
    std::fs::copy(
        left_path.join("updates/active.json"),
        left_path.join("updates/pending.json"),
    )?;
    let mut left = Peer::new(&left_path, founder, "127.0.0.1:0".parse()?)?;
    let mut right = Peer::new(&right_path, joined, "127.0.0.1:0".parse()?)?;
    left.directory.import(right.contact.clone(), now)?;
    right.directory.import(left.contact.clone(), now)?;
    let listen = left.endpoint.local_addr()?;
    let left_endpoint = left.endpoint.clone();
    let left_task = left.start()?;
    let right_task = right.start()?;
    let status_path = left_path.clone();
    let status = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || control::probe(&status_path, ControlRequest::Status)),
    )
    .await???;
    assert!(matches!(status, Some(ControlReply::Status { .. })));
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
    let bundle_source = temporary.path().join("queued-update");
    std::fs::write(&bundle_source, b"queued while activation is pending")?;
    std::fs::set_permissions(&bundle_source, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    let digest = crate::update::prepare_outbound(&left_path, &bundle_source)?;
    let _queued = crate::update::queue_peer_delivery(&left_path, target, digest, unix_time()?)?;
    let restarted = Peer::new(&left_path, state::open(&left_path)?, listen)?.start()?;
    let status_path = left_path.clone();
    let status = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || control::probe(&status_path, ControlRequest::Status)),
    )
    .await???;
    assert!(matches!(status, Some(ControlReply::Status { .. })));
    let recovered = wait_connected(&[&left_path, &right_path]).await;
    assert_eq!(
        crate::update::load_peer_deliveries(&left_path, unix_time()?)?
            .deliveries
            .len(),
        1
    );
    restarted.abort();
    right_task.abort();
    let _left = restarted.await;
    let _right = right_task.await;
    recovered
}
