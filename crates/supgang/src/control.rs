//! Owner-authenticated, bounded local control protocol for a running service.

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixStream as BlockingUnixStream,
    },
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

use crate::{cli_peer, ids::NodeId, storage};

/// Filename of the private local-control socket inside protected state.
pub const CONTROL_SOCKET_FILE_NAME: &str = "control.sock";

const REQUEST_MAGIC: &[u8; 8] = b"SUPGIPC1";
const REQUEST_STATUS: u8 = 1;
const REQUEST_PEERS: u8 = 2;
const REQUEST_RESOLVE: u8 = 3;
const REQUEST_REVOKE: u8 = 4;
const MAX_REQUEST_BYTES: usize = 64;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(2);

/// One bounded local request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlRequest {
    /// Return non-secret service and identity status.
    Status,
    /// Return known peers without addresses.
    Peers,
    /// Return fresh signed candidates for exactly one peer.
    Resolve(NodeId),
    /// Root-revoke exactly one stable peer identity.
    Revoke(NodeId),
}

/// Non-secret status returned by a running service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlStatus {
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
    /// Number of root-authorized hive members.
    pub member_count: usize,
    /// Number of verified authoritative state events.
    pub event_count: usize,
}

/// Versioned response from the local service.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "response", rename_all = "kebab-case")]
pub enum ControlReply {
    /// Service status response.
    Status {
        /// Non-secret service status.
        value: ControlStatus,
    },
    /// Address-redacted peer summary.
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
    #[error("local control response is invalid")]
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
    let bytes = serde_json::to_vec(reply).map_err(|_| ControlError::InvalidResponse)?;
    if bytes.is_empty() || bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ControlError::InvalidResponse);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| ControlError::InvalidResponse)?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.shutdown().await?;
    Ok(())
}

/// Sends a bounded request to a running local service.
///
/// `Ok(None)` means no control socket exists and the caller may safely try
/// direct state access. An existing but invalid socket always fails closed.
///
/// # Errors
///
/// Rejects unsafe socket metadata, foreign peers, malformed responses, timeouts,
/// and I/O failures.
pub fn request(state_directory: &Path, request: ControlRequest) -> Result<Option<ControlReply>, ControlError> {
    let directory = storage::validate_directory(state_directory)?;
    let path = directory.join(CONTROL_SOCKET_FILE_NAME);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_existing_socket_metadata(&metadata)?;
    let mut stream = BlockingUnixStream::connect(path)?;
    stream.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    stream.set_write_timeout(Some(CLIENT_TIMEOUT))?;
    validate_peer_blocking(&stream)?;
    let bytes = encode_request(request);
    write_blocking_frame(&mut stream, &bytes, MAX_REQUEST_BYTES)?;
    let response = read_blocking_frame(&mut stream, MAX_RESPONSE_BYTES)?;
    let reply = serde_json::from_slice(&response).map_err(|_| ControlError::InvalidResponse)?;
    Ok(Some(reply))
}

fn encode_request(request: ControlRequest) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(REQUEST_MAGIC.len() + 1 + 32);
    bytes.extend_from_slice(REQUEST_MAGIC);
    match request {
        ControlRequest::Status => bytes.push(REQUEST_STATUS),
        ControlRequest::Peers => bytes.push(REQUEST_PEERS),
        ControlRequest::Resolve(node_id) => {
            bytes.push(REQUEST_RESOLVE);
            bytes.extend_from_slice(node_id.as_bytes());
        }
        ControlRequest::Revoke(node_id) => {
            bytes.push(REQUEST_REVOKE);
            bytes.extend_from_slice(node_id.as_bytes());
        }
    }
    bytes
}

fn decode_request(bytes: &[u8]) -> Result<ControlRequest, ControlError> {
    if bytes.get(..REQUEST_MAGIC.len()) != Some(REQUEST_MAGIC) {
        return Err(ControlError::InvalidRequest);
    }
    let command = bytes
        .get(REQUEST_MAGIC.len())
        .copied()
        .ok_or(ControlError::InvalidRequest)?;
    match command {
        REQUEST_STATUS if bytes.len() == REQUEST_MAGIC.len() + 1 => Ok(ControlRequest::Status),
        REQUEST_PEERS if bytes.len() == REQUEST_MAGIC.len() + 1 => Ok(ControlRequest::Peers),
        REQUEST_RESOLVE if bytes.len() == REQUEST_MAGIC.len() + 1 + 32 => {
            let raw = bytes
                .get(REQUEST_MAGIC.len() + 1..)
                .ok_or(ControlError::InvalidRequest)?
                .try_into()
                .map_err(|_| ControlError::InvalidRequest)?;
            Ok(ControlRequest::Resolve(NodeId::from_bytes(raw)))
        }
        REQUEST_REVOKE if bytes.len() == REQUEST_MAGIC.len() + 1 + 32 => {
            let raw = bytes
                .get(REQUEST_MAGIC.len() + 1..)
                .ok_or(ControlError::InvalidRequest)?
                .try_into()
                .map_err(|_| ControlError::InvalidRequest)?;
            Ok(ControlRequest::Revoke(NodeId::from_bytes(raw)))
        }
        _ => Err(ControlError::InvalidRequest),
    }
}

async fn read_async_length(stream: &mut UnixStream, maximum: usize) -> Result<usize, ControlError> {
    let mut length_bytes = [0_u8; 4];
    stream.read_exact(&mut length_bytes).await?;
    bounded_length(length_bytes, maximum, ControlError::InvalidRequest)
}

fn write_blocking_frame(stream: &mut BlockingUnixStream, bytes: &[u8], maximum: usize) -> Result<(), ControlError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ControlError::InvalidRequest);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| ControlError::InvalidRequest)?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}

fn read_blocking_frame(stream: &mut BlockingUnixStream, maximum: usize) -> Result<Vec<u8>, ControlError> {
    let mut length_bytes = [0_u8; 4];
    stream.read_exact(&mut length_bytes)?;
    let length = bounded_length(length_bytes, maximum, ControlError::InvalidResponse)?;
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
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

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use super::{ControlError, ControlListener, ControlRequest, decode_request, encode_request};
    use crate::ids::NodeId;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn request_encoding_is_canonical_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
        for request in [
            ControlRequest::Status,
            ControlRequest::Peers,
            ControlRequest::Resolve(NodeId::from_bytes([7_u8; 32])),
            ControlRequest::Revoke(NodeId::from_bytes([8_u8; 32])),
        ] {
            let encoded = encode_request(request);
            assert_eq!(decode_request(&encoded)?, request);
        }
        assert!(matches!(decode_request(b""), Err(ControlError::InvalidRequest)));
        let mut trailing = encode_request(ControlRequest::Status);
        trailing.push(0);
        assert!(matches!(decode_request(&trailing), Err(ControlError::InvalidRequest)));
        Ok(())
    }

    #[test]
    fn listener_rejects_symlink_and_cleans_only_its_socket() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state_directory = temporary.path().join("state");
        fs::create_dir(&state_directory)?;
        fs::set_permissions(&state_directory, fs::Permissions::from_mode(0o700))?;
        let socket = state_directory.join(super::CONTROL_SOCKET_FILE_NAME);
        let target = temporary.path().join("target");
        fs::write(&target, b"protected")?;
        symlink(&target, &socket)?;
        assert!(matches!(
            ControlListener::bind(&state_directory),
            Err(ControlError::UnsafeSocketPath)
        ));
        fs::remove_file(&socket)?;
        let runtime = crate::transport::build_runtime()?;
        let _runtime_guard = runtime.enter();
        let listener = ControlListener::bind(&state_directory)?;
        assert!(socket.exists());
        drop(listener);
        assert!(!socket.exists());
        assert_eq!(fs::read(target)?, b"protected");
        Ok(())
    }
}
