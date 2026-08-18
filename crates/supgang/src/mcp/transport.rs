//! Bounded newline-delimited JSON transport for local MCP stdio.

use std::{io, sync::Arc};

use rmcp::{
    ErrorData, RoleServer,
    model::RequestId,
    service::{RxJsonRpcMessage, TxJsonRpcMessage},
    transport::Transport,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::Mutex,
};

/// Maximum bytes accepted in one MCP request, including its newline.
pub const MAX_MCP_REQUEST_BYTES: usize = 16 * 1024;
/// Maximum bytes emitted in one MCP response, excluding its newline.
pub const MAX_MCP_RESPONSE_BYTES: usize = 256 * 1024;

/// A fail-closed MCP transport whose input and output allocations have fixed ceilings.
pub struct BoundedStdio<R, W> {
    reader: BufReader<R>,
    line: Vec<u8>,
    writer: Arc<Mutex<Option<W>>>,
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
            writer: Arc::new(Mutex::new(Some(writer))),
        }
    }
}

impl<R, W> Transport<RoleServer> for BoundedStdio<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Error = io::Error;

    fn send(
        &mut self,
        message: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let writer = Arc::clone(&self.writer);
        async move { write_message(&writer, &message).await }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        loop {
            self.line.clear();
            let limit = u64::try_from(MAX_MCP_REQUEST_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            let mut bounded = (&mut self.reader).take(limit);
            let read = bounded.read_until(b'\n', &mut self.line).await.ok()?;
            if read == 0 {
                return None;
            }
            if self.line.len() > MAX_MCP_REQUEST_BYTES || !self.line.ends_with(b"\n") {
                return None;
            }
            let line = self.line.strip_suffix(b"\n").unwrap_or(&self.line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() {
                continue;
            }
            let value = match serde_json::from_slice::<serde_json::Value>(line) {
                Ok(value) => value,
                Err(error) if error.is_data() || error.is_io() => {
                    if write_protocol_error(&self.writer, ErrorData::invalid_request("Invalid request", None), None)
                        .await
                        .is_err()
                    {
                        return None;
                    }
                    continue;
                }
                Err(_) => {
                    // Syntax errors have no trustworthy request ID. Ignoring them avoids
                    // response loops with peers that reflect malformed input.
                    continue;
                }
            };
            if let Some(id) = missing_modern_capabilities(&value) {
                let error = ErrorData::invalid_params("2026-07-28 requests require clientCapabilities metadata", None);
                if write_protocol_error(&self.writer, error, Some(id)).await.is_err() {
                    return None;
                }
                continue;
            }
            match serde_json::from_value(value) {
                Ok(message) => return Some(message),
                Err(_) => {
                    if write_protocol_error(&self.writer, ErrorData::invalid_request("Invalid request", None), None)
                        .await
                        .is_err()
                    {
                        return None;
                    }
                }
            }
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        let output = {
            let mut writer = self.writer.lock().await;
            writer.take()
        };
        if let Some(mut output) = output {
            output.shutdown().await?;
        }
        Ok(())
    }
}

fn missing_modern_capabilities(value: &serde_json::Value) -> Option<RequestId> {
    let metadata = value.get("params")?.get("_meta")?;
    let version = metadata.get("io.modelcontextprotocol/protocolVersion")?.as_str()?;
    if version != "2026-07-28"
        || metadata
            .get("io.modelcontextprotocol/clientCapabilities")
            .is_some_and(serde_json::Value::is_object)
    {
        return None;
    }
    value.get("id").and_then(|raw| serde_json::from_value(raw.clone()).ok())
}

async fn write_protocol_error<W>(
    writer: &Arc<Mutex<Option<W>>>,
    error: ErrorData,
    id: Option<RequestId>,
) -> Result<(), io::Error>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    write_message(writer, &TxJsonRpcMessage::<RoleServer>::error(error, id)).await
}

async fn write_message<W>(
    writer: &Arc<Mutex<Option<W>>>,
    message: &TxJsonRpcMessage<RoleServer>,
) -> Result<(), io::Error>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    let encoded = serde_json::to_vec(message).map_err(|_| io::Error::other("MCP response encoding failed"))?;
    if encoded.len() > MAX_MCP_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MCP response exceeds the fixed size limit",
        ));
    }
    let mut guard = writer.lock().await;
    let output = guard
        .as_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "MCP output is closed"))?;
    output.write_all(&encoded).await?;
    output.write_all(b"\n").await?;
    output.flush().await?;
    drop(guard);
    Ok(())
}
