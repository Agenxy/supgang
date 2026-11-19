//! Bounded newline-delimited JSON transport for local MCP stdio.

use std::io;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Maximum bytes accepted in one MCP request, including its newline.
pub const MAX_MCP_REQUEST_BYTES: usize = 16 * 1024;
/// Maximum bytes emitted in one MCP response, excluding its newline.
pub const MAX_MCP_RESPONSE_BYTES: usize = 256 * 1024;

/// A fail-closed MCP transport whose input and output allocations have fixed ceilings.
pub struct BoundedStdio<R, W> {
    reader: BufReader<R>,
    line: Vec<u8>,
    writer: W,
}

impl<R, W> BoundedStdio<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Creates a bounded transport from asynchronous byte streams.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader),
            line: Vec::with_capacity(4 * 1024),
            writer,
        }
    }

    /// Reads one complete line, refusing oversized or unterminated requests before decoding.
    ///
    /// # Errors
    /// Returns an I/O or bounded-frame error.
    pub async fn read_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            self.line.clear();
            let limit = u64::try_from(MAX_MCP_REQUEST_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            let mut bounded = (&mut self.reader).take(limit);
            let read = bounded.read_until(b'\n', &mut self.line).await?;
            if read == 0 {
                return Ok(None);
            }
            if self.line.len() > MAX_MCP_REQUEST_BYTES || !self.line.ends_with(b"\n") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "MCP request exceeds the fixed size limit",
                ));
            }
            let line = self.line.strip_suffix(b"\n").unwrap_or(&self.line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if !line.is_empty() {
                return Ok(Some(line.to_vec()));
            }
        }
    }

    /// Writes one complete bounded JSON response.
    ///
    /// # Errors
    /// Returns an I/O or bounded-frame error.
    pub async fn write_line(&mut self, response: &[u8]) -> io::Result<()> {
        if response.len() > MAX_MCP_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP response exceeds the fixed size limit",
            ));
        }
        self.writer.write_all(response).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await
    }
}
