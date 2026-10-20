//! The blocking client side of the local control protocol: owner commands,
//! health probes and tunnel setup, each bounded in how long it waits.

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::net::UnixStream as BlockingUnixStream,
    path::Path,
    time::Duration,
};

use super::{
    CONTROL_SOCKET_FILE_NAME, ControlError, ControlReply, ControlRequest, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    bounded_length, encode_request, validate_existing_socket_metadata, validate_peer_blocking,
};
use crate::{ids::NodeId, storage};

/// How long an owner's command waits for the service. A loaded computer can
/// leave the service's single thread unscheduled for seconds; an owner's
/// command should wait that out rather than fail.
const OWNER_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a health or readiness probe waits; its caller retries.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a tunnel request waits for the service to admit the stream.
const TUNNEL_SETUP_TIMEOUT: Duration = Duration::from_secs(10);

pub fn connect_service(state_directory: &Path, target: NodeId, name: [u8; 16]) -> Result<BlockingUnixStream, String> {
    let directory = storage::validate_directory(state_directory).map_err(|_| "local service state is unsafe")?;
    let path = directory.join(CONTROL_SOCKET_FILE_NAME);
    let metadata = fs::symlink_metadata(&path).map_err(|_| "start the local Supgang service before connecting")?;
    validate_existing_socket_metadata(&metadata).map_err(|_| "local service socket is unsafe")?;
    let mut stream = BlockingUnixStream::connect(path).map_err(|_| "local Supgang service is unavailable")?;
    stream
        .set_read_timeout(Some(TUNNEL_SETUP_TIMEOUT))
        .map_err(|_| "local tunnel timeout setup failed")?;
    stream
        .set_write_timeout(Some(TUNNEL_SETUP_TIMEOUT))
        .map_err(|_| "local tunnel timeout setup failed")?;
    validate_peer_blocking(&stream).map_err(|_| "local service belongs to another user")?;
    let failed = |error, fallback: &str| match timed_out(error, TUNNEL_SETUP_TIMEOUT) {
        unresponsive @ ControlError::Unresponsive { .. } => unresponsive.to_string(),
        _ => fallback.to_owned(),
    };
    write_blocking_frame(
        &mut stream,
        &encode_request(ControlRequest::Connect { target, name }),
        MAX_REQUEST_BYTES,
    )
    .map_err(|error| failed(error, "local tunnel request failed"))?;
    let bytes = read_blocking_frame(&mut stream, MAX_RESPONSE_BYTES)
        .map_err(|error| failed(error, "local tunnel setup failed"))?;
    match serde_json::from_slice::<ControlReply>(&bytes).map_err(|_| "local tunnel reply is invalid")? {
        ControlReply::Connected => {}
        ControlReply::Error { message } => return Err(message),
        _ => return Err("local runtime does not support service tunnels; refresh its installed artifact".to_owned()),
    }
    stream
        .set_read_timeout(None)
        .map_err(|_| "local tunnel timeout removal failed")?;
    stream
        .set_write_timeout(None)
        .map_err(|_| "local tunnel timeout removal failed")?;
    stream
        .set_nonblocking(true)
        .map_err(|_| "local tunnel nonblocking setup failed")?;
    Ok(stream)
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
    request_within(state_directory, request, OWNER_TIMEOUT).map(|reply| reply.map(|(reply, _pid)| reply))
}

/// Sends a health or readiness request that fails fast so its caller can retry.
///
/// # Errors
///
/// As [`request`], with a shorter wait for the reply.
pub fn probe(state_directory: &Path, request: ControlRequest) -> Result<Option<ControlReply>, ControlError> {
    request_within(state_directory, request, PROBE_TIMEOUT).map(|reply| reply.map(|(reply, _pid)| reply))
}

/// Requests status with the socket peer PID obtained from the operating system.
///
/// # Errors
///
/// As [`request`].
pub fn request_observed(
    state_directory: &Path,
    request: ControlRequest,
) -> Result<Option<(ControlReply, u32)>, ControlError> {
    request_within(state_directory, request, OWNER_TIMEOUT)
}

pub(super) fn request_within(
    state_directory: &Path,
    request: ControlRequest,
    timeout: Duration,
) -> Result<Option<(ControlReply, u32)>, ControlError> {
    let directory = storage::validate_directory(state_directory)?;
    let path = directory.join(CONTROL_SOCKET_FILE_NAME);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_existing_socket_metadata(&metadata)?;
    let mut stream = match BlockingUnixStream::connect(path) {
        Ok(stream) => stream,
        Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound) => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    validate_peer_blocking(&stream)?;
    let pid = peer_pid(&stream)?;
    let bytes = encode_request(request);
    let unresponsive = |error| timed_out(error, timeout);
    write_blocking_frame(&mut stream, &bytes, MAX_REQUEST_BYTES).map_err(unresponsive)?;
    let response = read_blocking_frame(&mut stream, MAX_RESPONSE_BYTES).map_err(unresponsive)?;
    let reply = serde_json::from_slice(&response).map_err(|_| ControlError::InvalidResponse)?;
    Ok(Some((reply, pid)))
}

/// Names a socket timeout as the service not answering, which is what the
/// owner can act on; other failures keep their own meaning.
fn timed_out(error: ControlError, timeout: Duration) -> ControlError {
    match error {
        ControlError::Io(io) if matches!(io.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
            ControlError::Unresponsive {
                seconds: timeout.as_secs(),
            }
        }
        other => other,
    }
}

fn peer_pid(stream: &BlockingUnixStream) -> Result<u32, ControlError> {
    #[cfg(target_os = "macos")]
    let pid =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerPid).map_err(io::Error::other)?;
    #[cfg(target_os = "linux")]
    let pid = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(io::Error::other)?
        .pid();
    u32::try_from(pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or(ControlError::WrongPeer)
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
