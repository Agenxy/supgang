//! Runs the production service on simulated computers.
//!
//! Each computer has its own state directory, its own thread and current-thread
//! runtime (as the real service has its own process), the production
//! `service_loop`, a simulated UDP socket, and a thread-local view of its
//! simulated interfaces and routes. The test drives each computer through its
//! real control socket, exactly as the command-line client does. Only the
//! packet network and the operating system's interface and route answers are
//! simulated; identity, admission, scheduling, gossip and tunnels are real.

use std::{
    io::{Read as _, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering, mpsc},
    thread,
    time::{Duration, Instant},
};

use super::super::{ServiceConfig, make_local_contact, service_loop, unix_time};
use crate::{
    control::{self, ControlListener, ControlReply, ControlRequest},
    endpoint_config::EndpointConfig,
    ids::NodeId,
    invitation::JoinBundle,
    membership::MembershipRoles,
    network::simulated,
    peer_directory::PeerDirectory,
    profile::PeerName,
    simnet::{HostId, HostView, Network},
    state, transport, transport_storage,
};

pub(super) type Error = Box<dyn std::error::Error + Send + Sync>;

/// The UDP port every simulated computer listens on, as installed services do.
pub(super) const PORT: u16 = 44_330;
/// How long a simulated computer is given to bind its control socket.
const START_TIMEOUT: Duration = Duration::from_secs(10);

struct Running {
    stop: tokio::sync::oneshot::Sender<()>,
    thread: thread::JoinHandle<Result<(), String>>,
}

/// One simulated computer: a hive member's state on disk and, while started,
/// its running service.
pub(super) struct Computer {
    pub path: PathBuf,
    pub host: HostId,
    pub node: NodeId,
    controls: Arc<super::super::test_controls::SimControls>,
    running: Option<Running>,
}

/// A hive of computers paired the way an owner pairs them: on one network,
/// with each computer's signed contact carried to the others.
pub(super) struct Fleet {
    pub network: Arc<Network>,
    pub computers: Vec<Computer>,
    _temporary: tempfile::TempDir,
}

/// Builds the configuration the installed service builds in automatic mode,
/// from the interfaces the current thread's view reports.
fn automatic_config() -> Result<ServiceConfig, Error> {
    let endpoints = EndpointConfig::automatic(PORT)?;
    Ok(ServiceConfig::new(
        PeerName::new("Simulated")?,
        endpoints.listen(),
        endpoints.local(),
        endpoints.direct(),
    )?
    .with_intervals(Duration::from_secs(1), Duration::from_hours(1))?
    .with_automatic_interface_refresh(true))
}

fn open_directory(path: &Path, local: &state::LocalState) -> Result<PeerDirectory, Error> {
    Ok(PeerDirectory::open(
        path,
        local.identity().root_verifying_key,
        local.identity().device.node_id(),
        local.revocations(),
    )?)
}

impl Fleet {
    /// Creates a hive on `hosts`; the first is its founder. Each computer signs
    /// its first contact from the interfaces its host has now, and every other
    /// computer remembers it.
    pub(super) fn pair(network: Arc<Network>, hosts: &[HostId]) -> Result<Self, Error> {
        let temporary = tempfile::tempdir()?;
        let mut computers = Vec::new();
        let (first, rest) = hosts.split_first().ok_or("a hive needs a founder")?;
        let founder_path = temporary.path().join("c0");
        let mut founder = state::initialize(&founder_path)?;
        // After initialization, whose revocation list must not postdate a bundle.
        let now = unix_time()?;
        computers.push(Computer {
            node: founder.identity().device.node_id(),
            path: founder_path,
            host: *first,
            controls: Arc::new(super::super::test_controls::SimControls::default()),
            running: None,
        });
        for (index, host) in rest.iter().enumerate() {
            let path = temporary.path().join(format!("c{}", index + 1));
            let request = state::create_join_request(&path)?;
            let node = NodeId::from_verifying_key(&request.device_verifying_key);
            let member = founder.authorize_join_request(&request, node, MembershipRoles::DEVICE, now, now + 86_400)?;
            let root = founder.identity().root.as_ref().ok_or("founder holds no root")?;
            let bundle = JoinBundle::new(root, member, founder.revocations().clone(), now)?;
            drop(state::install_join_bundle(&path, &bundle, founder.identity().hive_id)?);
            computers.push(Computer {
                path,
                host: *host,
                controls: Arc::new(super::super::test_controls::SimControls::default()),
                node,
                running: None,
            });
        }
        drop(founder);
        let mut contacts = Vec::new();
        for computer in &computers {
            let _view = simulated::install(Arc::new(HostView::new(Arc::clone(&network), computer.host)));
            let mut local = state::open(&computer.path)?;
            let identity = transport_storage::load_or_create(&computer.path)?;
            contacts.push(make_local_contact(&mut local, &identity, &automatic_config()?)?);
        }
        for (index, computer) in computers.iter().enumerate() {
            let local = state::open(&computer.path)?;
            let mut directory = open_directory(&computer.path, &local)?;
            for (other, contact) in contacts.iter().enumerate() {
                if other != index {
                    directory.import(contact.clone(), now)?;
                }
            }
        }
        Ok(Self {
            network,
            computers,
            _temporary: temporary,
        })
    }

    pub(super) fn computer(&self, index: usize) -> Result<&Computer, Error> {
        self.computers.get(index).ok_or_else(|| "no such computer".into())
    }

    /// Makes one peer model a lower local RTT estimate and reject duplicate
    /// admission while its counterpart considers a new path better.
    pub(super) fn keep_old_rtt_view(&self, index: usize, drain_after: Duration) -> Result<(), Error> {
        let controls = &self.computer(index)?.controls;
        controls.suppress_rtt_replacement.store(true, Ordering::Relaxed);
        controls.suppress_quality_dial.store(true, Ordering::Relaxed);
        controls.reject_duplicate.store(true, Ordering::Relaxed);
        controls
            .drain_limit_seconds
            .store(drain_after.as_secs(), Ordering::Relaxed);
        Ok(())
    }

    pub(super) fn shorten_drain(&self, index: usize, drain_after: Duration) -> Result<(), Error> {
        self.computer(index)?
            .controls
            .drain_limit_seconds
            .store(drain_after.as_secs(), Ordering::Relaxed);
        Ok(())
    }

    pub(super) fn replacement_attempts(&self, index: usize) -> Result<u64, Error> {
        Ok(self
            .computer(index)?
            .controls
            .replacement_attempts
            .load(Ordering::Relaxed))
    }

    pub(super) fn quality_dials(&self, index: usize) -> Result<u64, Error> {
        Ok(self.computer(index)?.controls.quality_dials.load(Ordering::Relaxed))
    }

    pub(super) fn interface_changes(&self, index: usize) -> Result<u64, Error> {
        Ok(self.computer(index)?.controls.interface_changes.load(Ordering::Relaxed))
    }

    pub(super) fn recovery_events(
        &self,
        index: usize,
    ) -> Result<[u64; super::super::test_controls::RecoveryEvent::COUNT], Error> {
        let controls = &self.computer(index)?.controls;
        Ok(std::array::from_fn(|index| {
            controls
                .recovery_events
                .get(index)
                .map_or(0, |counter| counter.load(Ordering::Relaxed))
        }))
    }

    pub(super) fn recovery_snapshot(
        &self,
        index: usize,
        peer: NodeId,
    ) -> Result<Option<super::super::test_controls::RecoverySnapshot>, Error> {
        Ok(self
            .computer(index)?
            .controls
            .recovery
            .lock()
            .map_err(|_| std::io::Error::other("recovery snapshot poisoned"))?
            .get(&peer)
            .copied())
    }

    /// Starts every computer's service.
    pub(super) fn start_all(&mut self) -> Result<(), Error> {
        for index in 0..self.computers.len() {
            self.start(index)?;
        }
        Ok(())
    }

    /// Starts one computer's service from its state on disk.
    pub(super) fn start(&mut self, index: usize) -> Result<(), Error> {
        let network = Arc::clone(&self.network);
        let computer = self.computers.get_mut(index).ok_or("no such computer")?;
        if computer.running.is_some() {
            return Err("already running".into());
        }
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (ready, readiness) = mpsc::channel();
        let path = computer.path.clone();
        let host = computer.host;
        let controls = Arc::clone(&computer.controls);
        let thread = thread::Builder::new()
            .name(format!("simulated-{index}"))
            .spawn(move || {
                run_computer(&network, host, &path, controls, stopped, &ready).map_err(|error| error.to_string())
            })?;
        if readiness.recv_timeout(START_TIMEOUT).is_ok() {
            computer.running = Some(Running { stop, thread });
            return Ok(());
        }
        let outcome = thread.join().map_err(|_| "simulated computer panicked")?;
        Err(format!("simulated computer did not start: {outcome:?}").into())
    }

    /// Saves tunnel limits through a running computer's control socket, as
    /// `supgang tunnel-limits` does for a boot service that cannot be stopped.
    pub(super) fn set_tunnel_limits(&self, index: usize, per_peer: u16, total: u16) -> Result<(), Error> {
        let request = ControlRequest::TunnelLimits {
            per_peer,
            total,
            idle_seconds: 86_400,
        };
        match self::request(&self.computer(index)?.path, request)? {
            Some(ControlReply::LimitsSaved) => Ok(()),
            other => Err(format!("tunnel limits refused: {other:?}").into()),
        }
    }

    /// Stops one computer's service and waits for its thread to finish.
    pub(super) fn stop(&mut self, index: usize) -> Result<(), Error> {
        let computer = self.computers.get_mut(index).ok_or("no such computer")?;
        let running = computer.running.take().ok_or("not running")?;
        let _ignored = running.stop.send(());
        running.thread.join().map_err(|_| "simulated computer panicked")??;
        Ok(())
    }
}

impl Drop for Fleet {
    fn drop(&mut self) {
        for computer in &mut self.computers {
            if let Some(running) = computer.running.take() {
                let _ignored = running.stop.send(());
                let _ignored = running.thread.join();
            }
        }
    }
}

/// The body of one simulated computer's thread, following `run_with_ready`
/// except for the socket and the interface view.
fn run_computer(
    network: &Arc<Network>,
    host: HostId,
    path: &Path,
    controls: Arc<super::super::test_controls::SimControls>,
    stopped: tokio::sync::oneshot::Receiver<()>,
    ready: &mpsc::Sender<()>,
) -> Result<(), Error> {
    let _view = simulated::install(Arc::new(HostView::new(Arc::clone(network), host)));
    let _controls = super::super::test_controls::install(controls);
    let config = automatic_config()?;
    let mut local = state::open(path)?;
    let identity = transport_storage::load_or_create(path)?;
    let mut directory = PeerDirectory::open_with_history_limit(
        path,
        local.identity().root_verifying_key,
        local.identity().device.node_id(),
        local.revocations(),
        config.address_history,
    )?;
    let runtime = transport::build_runtime()?;
    let control_listener = {
        let _runtime_guard = runtime.enter();
        ControlListener::bind(path)?
    };
    runtime.block_on(async {
        let socket = network.bind(host, PORT)?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(identity.server_config()?),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        ready.send(())?;
        tokio::select! {
            result = service_loop(endpoint, identity, &control_listener, path, &mut local, &mut directory, config) => {
                result.map_err(Error::from)
            }
            _ = stopped => Ok(()),
        }
    })
}

fn request(path: &Path, request: ControlRequest) -> Result<Option<ControlReply>, Error> {
    Ok(control::request(path, request)?)
}

/// The authenticated connection a computer reports to `peer`, if any.
pub(super) fn connection(computer: &Computer, peer: NodeId) -> Result<Option<SocketAddr>, Error> {
    let Some(ControlReply::Peers { value }) = request(&computer.path, ControlRequest::Peers)? else {
        return Ok(None);
    };
    let peer = peer.to_string();
    Ok(value
        .peers
        .into_iter()
        .find(|row| row.node_id == peer && row.connected == Some(true))
        .and_then(|row| row.connection)
        .and_then(|connection| connection.remote_address.parse().ok()))
}

/// Polls until `check` returns a value or `limit` passes.
pub(super) fn eventually<T>(
    limit: Duration,
    mut check: impl FnMut() -> Result<Option<T>, Error>,
) -> Result<Option<T>, Error> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(value) = check()? {
            return Ok(Some(value));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Waits for both computers to report an authenticated connection to each
/// other, returning the remote address `from` uses.
pub(super) fn wait_connected(
    fleet: &Fleet,
    from: usize,
    to: usize,
    limit: Duration,
) -> Result<Option<SocketAddr>, Error> {
    let source = fleet.computer(from)?;
    let target = fleet.computer(to)?;
    eventually(limit, || {
        let forward = connection(source, target.node)?;
        let reverse = connection(target, source.node)?;
        Ok(forward.filter(|_| reverse.is_some()))
    })
}

pub(super) fn add_mapped(computer: &Computer, address: std::net::SocketAddrV4) -> Result<(), Error> {
    match request(&computer.path, ControlRequest::AddMapped { address })? {
        Some(ControlReply::EndpointChanged) => Ok(()),
        other => Err(format!("mapped endpoint refused: {other:?}").into()),
    }
}

/// Wait until the peer's signed record contains a newly published mapping.
pub(super) fn wait_mapped(fleet: &Fleet, from: usize, to: usize, address: std::net::SocketAddrV4) -> Result<(), Error> {
    let source = fleet.computer(from)?;
    let target = fleet.computer(to)?;
    eventually(Duration::from_secs(30), || {
        let reply = request(&source.path, ControlRequest::Resolve(target.node))?;
        Ok(match reply {
            Some(ControlReply::Resolve { value })
                if value
                    .candidates
                    .iter()
                    .any(|candidate| candidate.address == address.to_string()) =>
            {
                Some(())
            }
            _ => None,
        })
    })?
    .ok_or_else(|| "the peer never received the mapped address".into())
}

/// Exposes `name` on `computer`, served by a one-shot loopback echo server.
pub(super) fn expose_echo(computer: &Computer, name: &str) -> Result<thread::JoinHandle<Result<(), String>>, Error> {
    expose_echo_with_timeout(computer, name, Duration::from_secs(20))
}

pub(super) fn expose_echo_with_timeout(
    computer: &Computer,
    name: &str,
    read_timeout: Duration,
) -> Result<thread::JoinHandle<Result<(), String>>, Error> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let echo = thread::spawn(move || {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(read_timeout))
            .map_err(|error| error.to_string())?;
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).map_err(|error| error.to_string())?;
        stream.write_all(&bytes).map_err(|error| error.to_string())?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|error| error.to_string())
    });
    let name = crate::tunnel_policy::encoded_name(&crate::record::ServiceName::new(name)?);
    match request(&computer.path, ControlRequest::Expose { name, port })? {
        Some(ControlReply::ExposureChanged) => Ok(echo),
        other => Err(format!("exposure refused: {other:?}").into()),
    }
}

/// Exposes `name` on `computer`, served by a loopback echo server that
/// answers up to `connections` concurrent connections, each after end of input.
pub(super) fn expose_echoes(
    computer: &Computer,
    name: &str,
    connections: usize,
) -> Result<thread::JoinHandle<Result<(), String>>, Error> {
    expose_echoes_with_timeout(computer, name, connections, Duration::from_mins(1))
}

pub(super) fn expose_echoes_with_timeout(
    computer: &Computer,
    name: &str,
    connections: usize,
    read_timeout: Duration,
) -> Result<thread::JoinHandle<Result<(), String>>, Error> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let echo = thread::spawn(move || {
        let mut handlers = Vec::new();
        for _ in 0..connections {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            handlers.push(thread::spawn(move || {
                stream
                    .set_read_timeout(Some(read_timeout))
                    .map_err(|error| error.to_string())?;
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).map_err(|error| error.to_string())?;
                stream.write_all(&bytes).map_err(|error| error.to_string())?;
                stream
                    .shutdown(std::net::Shutdown::Write)
                    .map_err(|error| error.to_string())
            }));
        }
        for handler in handlers {
            handler.join().map_err(|_| "echo handler panicked".to_owned())??;
        }
        Ok(())
    });
    let name = crate::tunnel_policy::encoded_name(&crate::record::ServiceName::new(name)?);
    match request(&computer.path, ControlRequest::Expose { name, port })? {
        Some(ControlReply::ExposureChanged) => Ok(echo),
        other => Err(format!("exposure refused: {other:?}").into()),
    }
}

/// Opens a tunnel from `computer` to `target`'s named service.
pub(super) fn open_tunnel(
    computer: &Computer,
    target: NodeId,
    name: &str,
) -> Result<std::os::unix::net::UnixStream, Error> {
    let name = crate::tunnel_policy::encoded_name(&crate::record::ServiceName::new(name)?);
    let stream = control::connect_service(&computer.path, target, name)?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_mins(1)))?;
    Ok(stream)
}

/// Carries `payload` through `supgang connect` from `computer` to `target`'s
/// named service and returns what came back after end of input.
pub(super) fn tunnel_round_trip(
    computer: &Computer,
    target: NodeId,
    name: &str,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let name = crate::tunnel_policy::encoded_name(&crate::record::ServiceName::new(name)?);
    let mut stream = control::connect_service(&computer.path, target, name)?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.write_all(payload)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut received = Vec::new();
    stream.read_to_end(&mut received)?;
    Ok(received)
}
