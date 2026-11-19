//! Read-only Model Context Protocol access to the local Supgang fleet.

use std::{path::PathBuf, time::Duration};

use thiserror::Error;

mod data;
mod protocol;
mod transport;

#[cfg(test)]
mod tests;

use transport::BoundedStdio;

/// MCP server startup or transport failure.
#[derive(Debug, Error)]
pub enum McpServeError {
    /// The current-thread asynchronous runtime could not be created.
    #[error("MCP runtime initialization failed")]
    Runtime,
    /// The stdio service could not start or ended with a transport failure.
    #[error("MCP stdio service failed")]
    Service,
}

/// Runs the bounded local MCP server until its client or parent disconnects.
///
/// # Errors
/// Returns a non-sensitive startup or transport classification.
pub fn serve_stdio(state_directory: PathBuf) -> Result<(), McpServeError> {
    let parent = rustix::process::getppid();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .thread_name("supgang-mcp")
        .enable_all()
        .build()
        .map_err(|_| McpServeError::Runtime)?;
    runtime.block_on(async move {
        let transport = BoundedStdio::new(tokio::io::stdin(), tokio::io::stdout());
        tokio::select! {
            biased;
            () = parent_gone(parent) => Ok(()),
            result = protocol::serve(state_directory, transport) => match result {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                Err(_) => Err(McpServeError::Service),
            },
        }
    })
}

async fn parent_gone(parent: Option<rustix::process::Pid>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        if rustix::process::getppid() != parent {
            break;
        }
    }
}
