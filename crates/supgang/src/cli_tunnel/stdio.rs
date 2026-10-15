//! Nonblocking native stdio: no uncancellable blocking-stdin worker.

use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::{AsRawFd, RawFd},
};

use tokio::{io::AsyncReadExt, io::AsyncWriteExt, io::unix::AsyncFd};

struct Pipe {
    file: File,
    original: rustix::fs::OFlags,
}

impl Pipe {
    fn new(fd: impl std::os::fd::AsFd) -> io::Result<AsyncFd<Self>> {
        let file = File::from(rustix::io::dup(fd)?);
        let original = rustix::fs::fcntl_getfl(&file)?;
        rustix::fs::fcntl_setfl(&file, original | rustix::fs::OFlags::NONBLOCK)?;
        AsyncFd::new(Self { file, original })
    }
}

impl AsRawFd for Pipe {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        let _restore = rustix::fs::fcntl_setfl(&self.file, self.original);
    }
}

pub(super) async fn bridge(socket: tokio::net::UnixStream) -> io::Result<()> {
    let input = Pipe::new(std::io::stdin())?;
    let output = Pipe::new(std::io::stdout())?;
    bridge_io(socket, input, output).await
}

async fn bridge_io(socket: tokio::net::UnixStream, input: AsyncFd<Pipe>, output: AsyncFd<Pipe>) -> io::Result<()> {
    let (mut receive, mut send) = socket.into_split();
    let outgoing = async {
        let mut bytes = vec![0; 16 * 1_024];
        loop {
            let mut ready = input.readable().await?;
            let count = match ready.try_io(|descriptor| (&descriptor.get_ref().file).read(&mut bytes)) {
                Ok(result) => result?,
                Err(_) => continue,
            };
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
            let mut pending = bytes
                .get(..count)
                .ok_or_else(|| io::Error::other("stdout length invalid"))?;
            while !pending.is_empty() {
                let mut ready = output.writable().await?;
                let written = match ready.try_io(|descriptor| (&descriptor.get_ref().file).write(pending)) {
                    Ok(result) => result?,
                    Err(_) => continue,
                };
                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                pending = pending
                    .get(written..)
                    .ok_or_else(|| io::Error::other("stdout write length invalid"))?;
            }
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
