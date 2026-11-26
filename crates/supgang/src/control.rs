//! Owner-authenticated, bounded local control protocol for a running service.

use std::{
    fs, io,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixStream as BlockingUnixStream,
    },
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

use crate::{cli_peer, ids::NodeId, storage, tunnel_policy::ExposureSnapshot};

/// Filename of the private local-control socket inside protected state.
pub const CONTROL_SOCKET_FILE_NAME: &str = "control.sock";
pub const STARTUP_ID_ENV: &str = "SUPGANG_STARTUP_ID";
/// Tunnel refusals that end on their own once the service reconnects the peer.
pub const PEER_NOT_CONNECTED: &str = "the peer is not connected right now; Supgang keeps reconnecting on its own. Retry shortly, or check `supgang peers`";
pub const PEER_AUTHORIZATION_LAPSED: &str = "the peer's session authorization has lapsed; Supgang renews it on its next contact. Retry shortly, or check `supgang peers`";
pub const PEER_SESSION_FAILED: &str = "the session to the peer failed during tunnel setup; Supgang reconnects on its own. Retry shortly, or check `supgang peers`";
/// Immediate refusal when the remote peer has no free per-peer or total tunnel slot.
pub const PEER_AT_CAPACITY: &str =
    "the peer has reached its tunnel limit; close idle sessions or raise its limit with `supgang tunnel-limits`";
/// Older services send this ambiguous reply for both refusal and setup timeout; current services do not emit it.
pub const LEGACY_SETUP_FAILED: &str =
    "peer refused the service or service setup timed out; check target exposure and runtime version";

pub fn startup_id() -> String {
    std::env::var(STARTUP_ID_ENV)
        .ok()
        .filter(|value| value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or_default()
}

const REQUEST_MAGIC: &[u8; 8] = b"SUPGIPC1";
const REQUEST_STATUS: u8 = 1;
const REQUEST_PEERS: u8 = 2;
const REQUEST_RESOLVE: u8 = 3;
const REQUEST_REVOKE: u8 = 4;
const REQUEST_UPDATE: u8 = 5;
const REQUEST_RESTART: u8 = 6;
const REQUEST_CONNECT: u8 = 7;
const REQUEST_EXPOSE: u8 = 8;
const REQUEST_ADD_MAPPED: u8 = 9;
const REQUEST_TUNNEL_LIMITS: u8 = 10;
const REQUEST_EXPOSURES: u8 = 11;
const REQUEST_AGENT_SIGN: u8 = 12;
const REQUEST_AGENT_KEYGEN: u8 = 13;
const MAX_REQUEST_BYTES: usize = 4700;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// One bounded local request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlRequest {
    /// Publish an explicit owner-managed public IPv4 UDP endpoint.
    AddMapped { address: std::net::SocketAddrV4 },
    /// Open byte transport to a named service on an exact authenticated peer.
    Connect { target: NodeId, name: [u8; 16] },
    /// Ask one authenticated member to sign a canonical bounded request.
    AgentSign {
        target: NodeId,
        request: Box<[u8; crate::agent_sign_protocol::MAX_REQUEST_BYTES]>,
        length: u16,
    },
    /// Ask one authenticated member to create a sealed agent-purpose key.
    AgentKeygen {
        /// Exact certified target member.
        target: NodeId,
        /// Canonical creation request, zero-padded in a fixed-size buffer.
        request: Box<[u8; crate::agent_keygen_protocol::MAX_REQUEST_BYTES]>,
        /// Number of populated request bytes.
        length: u16,
    },
    /// Change an owner-approved loopback service; port zero removes exposure.
    Expose { name: [u8; 16], port: u16 },
    /// Save tunnel admission and idle limits for the next start of the
    /// service, which the running service owns and would otherwise overwrite.
    TunnelLimits {
        per_peer: u16,
        total: u16,
        idle_seconds: u32,
    },
    /// Read the running exposure policy and effective admission ceiling.
    Exposures,
    /// Restart an installed supervisor payload, available only to the local owner.
    Restart,
    /// Return non-secret service and identity status.
    Status,
    /// Return known peers with their signed addresses.
    Peers,
    /// Return fresh signed candidates for exactly one peer.
    Resolve(NodeId),
    /// Root-revoke exactly one stable peer identity.
    Revoke(NodeId),
    /// Root-authorize delivery of one exact prepared update bundle to one peer.
    Update {
        /// Exact authenticated receiver.
        target: NodeId,
        /// SHA-256 identity of the protected local bundle.
        digest: [u8; 32],
    },
}

/// Non-secret status returned by a running service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlStatus {
    /// Version compiled into the running executable.
    #[serde(default)]
    pub version: String,
    /// Source commit compiled into the running executable (40 hex or `"unknown"`).
    #[serde(default)]
    pub commit: String,
    /// Operating-system process serving this response.
    #[serde(default)]
    pub process_id: u32,
    /// Supervisor challenge for this specific child startup; not a credential.
    #[serde(default)]
    pub startup_id: String,
    /// Random identifier for this running process, used to observe a completed restart.
    #[serde(default)]
    pub instance_id: String,
    /// Whether a supervisor will restore this payload after a local restart request.
    #[serde(default)]
    pub restart_supported: bool,
    /// Device-signed human label.
    pub name: String,
    /// Hive identifier.
    pub hive_id: String,
    /// This device's stable identifier.
    pub node_id: String,
    /// Actual bound QUIC socket.
    pub listen: String,
    /// Number of currently authenticated neighbors.
    pub active_peers: usize,
    /// Number of cryptographically known peer records.
    pub known_peers: usize,
    /// Current local-gateway mapping state.
    pub router_mapping: String,
    /// Honest summary of this computer's advertised Internet path.
    pub internet_reachability: String,
    /// Automatic connection recovery methods available in this runtime.
    #[serde(default = "legacy_connection_recovery")]
    pub connection_recovery: String,
    /// Runtime role selected by the local owner.
    #[serde(default = "device_mode")]
    pub mode: String,
    /// Number of root-authorized hive members.
    pub member_count: usize,
    /// Number of verified authoritative state events.
    pub event_count: usize,
    /// The most recent connections made and ended, oldest first; bounded.
    #[serde(default)]
    pub recent_connections: Vec<ConnectionEvent>,
    /// Advisory release awareness from live authenticated peers; never triggers an update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_notice: Option<crate::release::UpdateNotice>,
}

/// One connection made or ended. It names the path's kind, never its address.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectionEvent {
    /// Unix seconds.
    pub at: u64,
    /// The peer's short fingerprint.
    pub peer: String,
    /// `connected` or `ended`.
    pub event: String,
    /// `private-ipv4`, `private-ipv6`, `internet-ipv4` or `internet-ipv6`.
    pub path: String,
    /// Why it ended; empty for a connection made.
    pub reason: String,
}

fn legacy_connection_recovery() -> String {
    "remembered-addresses-only".to_owned()
}

fn device_mode() -> String {
    "device".to_owned()
}

/// Versioned response from the local service.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "response", rename_all = "kebab-case")]
pub enum ControlReply {
    /// Authenticated member signing result, still requiring a consumer key pin.
    AgentSigned {
        nonce: String,
        public_key: String,
        signature: String,
    },
    /// Created key's public material; no private key crosses the socket.
    AgentKeyCreated {
        /// Exact request nonce, lowercase hex.
        nonce: String,
        /// Raw Ed25519 public key, lowercase hex.
        public_key: String,
    },
    /// The local socket now carries only application bytes.
    Connected,
    /// The runtime committed the owner's exposure policy.
    ExposureChanged,
    /// The runtime saved tunnel limits that apply when it next starts.
    LimitsSaved,
    /// Read-only exposure and limit summary without mapped addresses.
    Exposures { value: ExposureSnapshot },
    /// The runtime signed and queued publication of an owner-mapped endpoint.
    EndpointChanged,
    /// The local supervisor payload has accepted a restart request.
    Restarting {
        /// Instance that is shutting down; readiness requires a different instance.
        instance_id: String,
    },
    /// Service status response.
    Status {
        /// Non-secret service status.
        value: ControlStatus,
    },
    /// Human-oriented peer and address summary.
    Peers {
        /// Stable CLI peer result.
        value: cli_peer::PeersOutput,
    },
    /// Explicit address resolution.
    Resolve {
        /// Stable CLI resolution result.
        value: cli_peer::ResolveOutput,
    },
    /// Root revocation result.
    Revoked {
        /// Revoked stable device identity.
        node_id: String,
        /// Current root revocation serial.
        serial: u64,
        /// Whether this request advanced the root snapshot.
        changed: bool,
    },
    /// A root-authorized update delivery was durably queued for its peer.
    UpdateQueued {
        /// Exact receiver node identity.
        node_id: String,
        /// Exact carried bundle digest.
        digest: String,
    },
    /// Safe request failure.
    Error {
        /// Human-readable failure with no secret material.
        message: String,
    },
}

/// Local-control validation or I/O failure.
#[derive(Debug, Error)]
pub enum ControlError {
    /// Protected state-directory validation failed.
    #[error("local control state directory failed validation")]
    Storage(#[from] storage::StorageError),
    /// Socket filesystem or stream operation failed.
    #[error("local control socket operation failed")]
    Io(#[from] io::Error),
    /// The service accepted the request but did not answer in time.
    #[error(
        "the local Supgang service did not answer within {seconds} s; this computer may be heavily loaded. Retry, or run `supgang service status`"
    )]
    Unresponsive {
        /// The bound the client waited.
        seconds: u64,
    },
    /// An existing path is not a safely replaceable owner socket.
    #[error("local control socket path is unsafe or already occupied")]
    UnsafeSocketPath,
    /// Socket permissions are not owner-only.
    #[error("local control socket permissions must be 0600")]
    InsecurePermissions,
    /// The connected process is owned by another operating-system user.
    #[error("local control peer belongs to another user")]
    WrongPeer,
    /// Request bytes are malformed, non-canonical, or outside fixed bounds.
    #[error("local control request is invalid")]
    InvalidRequest,
    /// A response exceeded its fixed bound or failed decoding.
    #[error(
        "local control response is invalid or incompatible with this client; check `supgang service status` and run `supgang service refresh` for an older service"
    )]
    InvalidResponse,
}

/// Bound private socket whose path is removed only if it is still this socket.
pub struct ControlListener {
    inner: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl core::fmt::Debug for ControlListener {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ControlListener")
            .field("path", &self.path)
            .field("socket", &"<owner-only>")
            .finish_non_exhaustive()
    }
}

impl ControlListener {
    /// Binds the service control socket inside an already protected state directory.
    ///
    /// # Errors
    ///
    /// Rejects symlinks, non-sockets, foreign-owned stale sockets, permissive
    /// modes, invalid state directories, and operating-system failures.
    pub fn bind(state_directory: &Path) -> Result<Self, ControlError> {
        let directory = storage::validate_directory(state_directory)?;
        let path = directory.join(CONTROL_SOCKET_FILE_NAME);
        remove_stale_owner_socket(&path)?;
        let inner = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let metadata = validate_socket_metadata(&path)?;
        Ok(Self {
            inner,
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    /// Accepts a connection only from the same operating-system user.
    ///
    /// # Errors
    ///
    /// Returns an I/O or peer-credential failure without exposing service state.
    pub async fn accept(&self) -> Result<UnixStream, ControlError> {
        let (stream, _address) = self.inner.accept().await?;
        validate_peer(&stream)?;
        Ok(stream)
    }
}

impl Drop for ControlListener {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && metadata.uid() == rustix::process::getuid().as_raw()
        {
            let _remove_result = fs::remove_file(&self.path);
        }
    }
}

/// Reads one request with a length prefix and fixed upper bound.
///
/// # Errors
///
/// Rejects truncated, oversized, unknown, and non-canonical requests.
pub async fn read_request(stream: &mut UnixStream) -> Result<ControlRequest, ControlError> {
    let length = read_async_length(stream, MAX_REQUEST_BYTES).await?;
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes).await?;
    decode_request(&bytes)
}

/// Writes one bounded JSON response.
///
/// # Errors
///
/// Rejects an unexpectedly large response and returns serialization or I/O failures.
pub async fn write_reply(stream: &mut UnixStream, reply: &ControlReply) -> Result<(), ControlError> {
    write_reply_open(stream, reply).await?;
    stream.shutdown().await?;
    Ok(())
}

pub async fn write_reply_open(stream: &mut UnixStream, reply: &ControlReply) -> Result<(), ControlError> {
    let bytes = serde_json::to_vec(reply).map_err(|_| ControlError::InvalidResponse)?;
    if bytes.is_empty() || bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ControlError::InvalidResponse);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| ControlError::InvalidResponse)?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

mod codec;
use codec::{decode_request, encode_request};

async fn read_async_length(stream: &mut UnixStream, maximum: usize) -> Result<usize, ControlError> {
    let mut length_bytes = [0_u8; 4];
    stream.read_exact(&mut length_bytes).await?;
    bounded_length(length_bytes, maximum, ControlError::InvalidRequest)
}

fn bounded_length(length_bytes: [u8; 4], maximum: usize, error: ControlError) -> Result<usize, ControlError> {
    let length = usize::try_from(u32::from_be_bytes(length_bytes)).map_err(|_| ControlError::InvalidResponse)?;
    if length == 0 || length > maximum {
        return Err(error);
    }
    Ok(length)
}

fn remove_stale_owner_socket(path: &Path) -> Result<(), ControlError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() || metadata.uid() != rustix::process::getuid().as_raw() {
                return Err(ControlError::UnsafeSocketPath);
            }
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_socket_metadata(path: &Path) -> Result<fs::Metadata, ControlError> {
    let metadata = fs::symlink_metadata(path)?;
    validate_existing_socket_metadata(&metadata)?;
    Ok(metadata)
}

fn validate_existing_socket_metadata(metadata: &fs::Metadata) -> Result<(), ControlError> {
    if !metadata.file_type().is_socket() || metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(ControlError::UnsafeSocketPath);
    }
    if metadata.mode() & 0o777 != 0o600 {
        return Err(ControlError::InsecurePermissions);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_peer(stream: &UnixStream) -> Result<(), ControlError> {
    let credentials =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials).map_err(io::Error::other)?;
    if credentials.uid() == rustix::process::getuid().as_raw() {
        Ok(())
    } else {
        Err(ControlError::WrongPeer)
    }
}

#[cfg(target_os = "linux")]
fn validate_peer_blocking(stream: &BlockingUnixStream) -> Result<(), ControlError> {
    let credentials =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials).map_err(io::Error::other)?;
    if credentials.uid() == rustix::process::getuid().as_raw() {
        Ok(())
    } else {
        Err(ControlError::WrongPeer)
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
fn validate_peer(stream: &UnixStream) -> Result<(), ControlError> {
    let (uid, _gid) = nix::unistd::getpeereid(stream).map_err(io::Error::other)?;
    if uid.as_raw() == rustix::process::getuid().as_raw() {
        Ok(())
    } else {
        Err(ControlError::WrongPeer)
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
fn validate_peer_blocking(stream: &BlockingUnixStream) -> Result<(), ControlError> {
    let (uid, _gid) = nix::unistd::getpeereid(stream).map_err(io::Error::other)?;
    if uid.as_raw() == rustix::process::getuid().as_raw() {
        Ok(())
    } else {
        Err(ControlError::WrongPeer)
    }
}

mod client;

#[cfg(test)]
use client::request_within;
pub use client::{connect_service, connect_service_by, probe, request, request_keygen, request_observed, request_sign};

#[cfg(test)]
mod tests;
