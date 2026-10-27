//! Nonblocking native stdio: no uncancellable blocking-stdin worker.
//!
//! Each standard stream is duplicated and handed to Tokio as an owned pipe end,
//! so its descriptor cannot be closed while it is registered.

use std::{
    fs::File,
    io,
    os::fd::{AsFd, OwnedFd},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::unix::pipe,
};

/// Restores a stream's original status flags when the bridge ends. A duplicate
/// shares its open file description, so the nonblocking flag set here would
/// otherwise outlive this process's use of the caller's stdio.
struct Restore {
    file: File,
    original: rustix::fs::OFlags,
}

impl Restore {
    /// Makes `fd` nonblocking and returns an owned duplicate for Tokio.
    fn nonblocking(fd: impl AsFd) -> io::Result<(Self, OwnedFd)> {
        let file = File::from(rustix::io::dup(&fd)?);
        let original = rustix::fs::fcntl_getfl(&file)?;
        rustix::fs::fcntl_setfl(&file, original | rustix::fs::OFlags::NONBLOCK)?;
        let owned = rustix::io::dup(&fd)?;
        Ok((Self { file, original }, owned))
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        let _restore = rustix::fs::fcntl_setfl(&self.file, self.original);
    }
}

/// The readable end; fields drop in order, so Tokio releases it before the
/// flags are restored.
struct Input {
    pipe: pipe::Receiver,
    _restore: Restore,
}

impl Input {
    fn new(fd: impl AsFd) -> io::Result<Self> {
        let (restore, owned) = Restore::nonblocking(fd)?;
        Ok(Self {
            pipe: pipe::Receiver::from_owned_fd_unchecked(owned)?,
            _restore: restore,
        })
    }
}

/// The writable end, released before its flags are restored.
struct Output {
    pipe: pipe::Sender,
    _restore: Restore,
}

impl Output {
    fn new(fd: impl AsFd) -> io::Result<Self> {
        let (restore, owned) = Restore::nonblocking(fd)?;
        Ok(Self {
            pipe: pipe::Sender::from_owned_fd_unchecked(owned)?,
            _restore: restore,
        })
    }
}

pub(super) async fn bridge(socket: tokio::net::UnixStream) -> io::Result<()> {
    let input = Input::new(std::io::stdin())?;
    let output = Output::new(std::io::stdout())?;
    bridge_io(socket, input, output).await
}

async fn bridge_io(socket: tokio::net::UnixStream, mut input: Input, mut output: Output) -> io::Result<()> {
    let (mut receive, mut send) = socket.into_split();
    let outgoing = async {
        let mut bytes = vec![0; 16 * 1_024];
        loop {
            let count = input.pipe.read(&mut bytes).await?;
            if count == 0 {
                return send.shutdown().await;
            }
            send.write_all(
                bytes
                    .get(..count)
                    .ok_or_else(|| io::Error::other("stdin length invalid"))?,
            )
            .await?;
        }
    };
    let incoming = async {
        let mut bytes = vec![0; 16 * 1_024];
        loop {
            let count = receive.read(&mut bytes).await?;
            if count == 0 {
                return Ok(());
            }
            output
                .pipe
                .write_all(
                    bytes
                        .get(..count)
                        .ok_or_else(|| io::Error::other("stdout length invalid"))?,
                )
                .await?;
        }
    };
    tokio::pin!(incoming);
    tokio::select! {
        result = outgoing => { result?; incoming.await }
        result = &mut incoming => result,
    }
}

#[cfg(test)]
mod tests;
