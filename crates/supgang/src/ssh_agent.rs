//! Owner-only, bounded OpenSSH agent for SSH-kind vault entries.

use std::{
    fs,
    future::Future,
    io,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixListener as BlockingListener,
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
};

use crate::{
    storage,
    vault::{self, Enclave},
};

/// Maximum SSH-agent message body, matching OpenSSH's agent cap.
pub const MAX_MESSAGE_BYTES: usize = 256 * 1024;
/// Maximum named keys exposed by one agent process.
pub const MAX_AGENT_KEYS: usize = 16;
const MAX_CONNECTIONS: usize = 8;
const MAX_REQUESTS_PER_CONNECTION: usize = 256;
const MAX_REQUESTS_PER_SECOND: usize = 32;
const FRAME_DEADLINE: Duration = Duration::from_secs(5);
const CONNECTION_DEADLINE: Duration = Duration::from_secs(120);

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;

/// A local SSH-agent refusal; errors contain no key material or socket path.
#[derive(Debug, Error)]
pub enum AgentError {
    /// Socket parent is not an owner-only directory.
    #[error("the SSH agent socket needs an existing owner-only directory")]
    UnsafeDirectory,
    /// A socket path is already occupied.
    #[error("the SSH agent socket path already exists; verify the old agent has stopped before removing it")]
    SocketExists,
    /// Key selection is invalid.
    #[error("select at most 16 distinct ssh-ed25519 vault keys with --key")]
    InvalidKeys,
    /// A selected key is not available or of the wrong kind.
    #[error("a selected SSH key could not be opened; check its vault name and kind")]
    KeyUnavailable,
    /// Local socket I/O failed.
    #[error("the SSH agent socket could not be served")]
    Io(#[source] io::Error),
}

#[derive(Clone)]
struct ExposedKey {
    name: String,
    public: [u8; 32],
    blob: Vec<u8>,
    comment: Vec<u8>,
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && metadata.uid() == rustix::process::getuid().as_raw()
        {
            let _result = fs::remove_file(&self.path);
        }
    }
}

/// Serves selected SSH keys until `shutdown` completes. No request can add a key.
///
/// # Errors
/// Refuses unsafe paths, duplicate or non-SSH keys, and listener failures.
pub async fn serve_until<E, F>(
    state_directory: &Path,
    socket_path: &Path,
    key_names: &[String],
    enclave: Arc<E>,
    shutdown: F,
) -> Result<(), AgentError>
where
    E: Enclave + Send + Sync + 'static,
    F: Future<Output = ()>,
{
    let state = storage::validate_directory(state_directory).map_err(|_| AgentError::UnsafeDirectory)?;
    let keys = Arc::new(load_keys(&state, key_names, enclave.as_ref())?);
    let (listener, _guard) = bind(socket_path)?;
    let capacity = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        let accepted = tokio::select! {
            () = &mut shutdown => break,
            Some(_completed) = tasks.join_next(), if !tasks.is_empty() => continue,
            result = listener.accept() => result.map_err(AgentError::Io)?,
        };
        let (stream, _address) = accepted;
        if !same_user(&stream) {
            continue;
        }
        let Ok(permit) = capacity.clone().try_acquire_owned() else {
            continue;
        };
        let state = state.clone();
        let keys = keys.clone();
        let enclave = enclave.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let _result = tokio::time::timeout(
                CONNECTION_DEADLINE,
                serve_connection(stream, &state, &keys, enclave.as_ref()),
            )
            .await;
        });
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

fn load_keys(state: &Path, names: &[String], enclave: &dyn Enclave) -> Result<Vec<ExposedKey>, AgentError> {
    if names.len() > MAX_AGENT_KEYS {
        return Err(AgentError::InvalidKeys);
    }
    let mut keys = Vec::with_capacity(names.len());
    for name in names {
        if vault::validate_name(name).is_err() || keys.iter().any(|key: &ExposedKey| key.name == *name) {
            return Err(AgentError::InvalidKeys);
        }
        let identity = vault::ssh_public_key(state, enclave, name).map_err(|_| AgentError::KeyUnavailable)?;
        keys.push(ExposedKey {
            name: name.clone(),
            public: identity.public_key,
            blob: vault::ssh_key_blob(&identity.public_key),
            comment: format!("{name}@supgang").into_bytes(),
        });
    }
    Ok(keys)
}

fn bind(socket_path: &Path) -> Result<(UnixListener, SocketGuard), AgentError> {
    let parent = socket_path.parent().ok_or(AgentError::UnsafeDirectory)?;
    let directory = storage::validate_directory(parent).map_err(|_| AgentError::UnsafeDirectory)?;
    let name = socket_path.file_name().ok_or(AgentError::UnsafeDirectory)?;
    let path = directory.join(name);
    match fs::symlink_metadata(&path) {
        Ok(_) => return Err(AgentError::SocketExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(AgentError::Io(error)),
    }
    let listener = BlockingListener::bind(&path).map_err(AgentError::Io)?;
    let metadata = (|| {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unsafe socket"));
        }
        listener.set_nonblocking(true)?;
        Ok(metadata)
    })();
    let metadata = match metadata {
        Ok(metadata) => metadata,
        Err(error) => {
            let _result = fs::remove_file(&path);
            return Err(AgentError::Io(error));
        }
    };
    let guard = SocketGuard {
        path,
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let listener = UnixListener::from_std(listener).map_err(AgentError::Io)?;
    Ok((listener, guard))
}

#[cfg(target_os = "linux")]
fn same_user(stream: &UnixStream) -> bool {
    nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .is_ok_and(|credentials| credentials.uid() == rustix::process::getuid().as_raw())
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
fn same_user(stream: &UnixStream) -> bool {
    nix::unistd::getpeereid(stream).is_ok_and(|(uid, _gid)| uid.as_raw() == rustix::process::getuid().as_raw())
}

async fn serve_connection<E: Enclave>(mut stream: UnixStream, state: &Path, keys: &[ExposedKey], enclave: &E) {
    let mut window = Instant::now();
    let mut requests_in_window = 0;
    for _ in 0..MAX_REQUESTS_PER_CONNECTION {
        let payload = match read_frame(&mut stream).await {
            Ok(Some(payload)) => payload,
            Ok(None) | Err(ReadFrameError::Io) => break,
            Err(ReadFrameError::Oversized) => {
                let _result = write_frame(&mut stream, &[FAILURE]).await;
                break;
            }
        };
        if window.elapsed() >= Duration::from_secs(1) {
            window = Instant::now();
            requests_in_window = 0;
        }
        requests_in_window += 1;
        if requests_in_window > MAX_REQUESTS_PER_SECOND {
            let _result = write_frame(&mut stream, &[FAILURE]).await;
            break;
        }
        let reply = respond(&payload, state, keys, enclave);
        if write_frame(&mut stream, &reply).await.is_err() {
            break;
        }
    }
}

enum ReadFrameError {
    Io,
    Oversized,
}

async fn read_frame(stream: &mut UnixStream) -> Result<Option<Vec<u8>>, ReadFrameError> {
    let result = tokio::time::timeout(FRAME_DEADLINE, async {
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix).await?;
        let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(io::Error::other)?;
        if length == 0 || length > MAX_MESSAGE_BYTES {
            return Ok::<Result<Vec<u8>, ReadFrameError>, io::Error>(Err(ReadFrameError::Oversized));
        }
        let mut payload = vec![0_u8; length];
        stream.read_exact(&mut payload).await?;
        Ok::<Result<Vec<u8>, ReadFrameError>, io::Error>(Ok(payload))
    })
    .await;
    match result {
        Ok(Ok(Ok(payload))) => Ok(Some(payload)),
        Ok(Ok(Err(problem))) => Err(problem),
        Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Ok(Err(_)) | Err(_) => Err(ReadFrameError::Io),
    }
}

async fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
    let length = u32::try_from(payload.len()).map_err(io::Error::other)?;
    if payload.is_empty() || payload.len() > MAX_MESSAGE_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    tokio::time::timeout(FRAME_DEADLINE, async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(payload).await
    })
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?
}

fn respond<E: Enclave>(payload: &[u8], state: &Path, keys: &[ExposedKey], enclave: &E) -> Vec<u8> {
    let Some((&kind, body)) = payload.split_first() else {
        return vec![FAILURE];
    };
    match kind {
        REQUEST_IDENTITIES if body.is_empty() => identities_response(keys),
        SIGN_REQUEST => sign_response(body, state, keys, enclave).unwrap_or_else(|| vec![FAILURE]),
        _ => vec![FAILURE],
    }
}

fn identities_response(keys: &[ExposedKey]) -> Vec<u8> {
    let mut answer = Vec::with_capacity(1 + 4 + keys.len() * 140);
    answer.push(IDENTITIES_ANSWER);
    answer.extend_from_slice(&u32::try_from(keys.len()).unwrap_or(0).to_be_bytes());
    for key in keys {
        if !append_string(&mut answer, &key.blob) || !append_string(&mut answer, &key.comment) {
            return vec![FAILURE];
        }
    }
    answer
}

fn sign_response<E: Enclave>(body: &[u8], state: &Path, keys: &[ExposedKey], enclave: &E) -> Option<Vec<u8>> {
    let mut cursor = Cursor(body);
    let blob = cursor.string()?;
    let data = cursor.string()?;
    let flags = cursor.u32()?;
    if flags != 0 || !cursor.0.is_empty() {
        return None;
    }
    let key = keys.iter().find(|key| key.blob == blob)?;
    let signed = vault::ssh_sign(state, enclave, &key.name, data).ok()?;
    if signed.identity.public_key != key.public {
        return None;
    }
    let mut signature_blob = Vec::with_capacity(4 + 11 + 4 + 64);
    if !append_string(&mut signature_blob, b"ssh-ed25519") || !append_string(&mut signature_blob, &signed.signature) {
        return None;
    }
    let mut response = vec![SIGN_RESPONSE];
    if !append_string(&mut response, &signature_blob) {
        return None;
    }
    Some(response)
}

fn append_string(target: &mut Vec<u8>, value: &[u8]) -> bool {
    let Ok(length) = u32::try_from(value.len()) else {
        return false;
    };
    if target.len().saturating_add(4).saturating_add(value.len()) > MAX_MESSAGE_BYTES {
        return false;
    }
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    true
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let value = self.0.get(..count)?;
        self.0 = self.0.get(count..)?;
        Some(value)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let length = usize::try_from(self.u32()?).ok()?;
        self.take(length)
    }
}

#[cfg(test)]
mod tests;
