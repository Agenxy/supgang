//! Long-running local SSH-agent command.

use std::{io::Write, path::Path, process::ExitCode, sync::Arc, time::Duration};

use crate::{cli::render_error, ssh_agent, vault::SecureEnclave};

pub fn run(
    state_directory: &Path,
    socket: &Path,
    keys: &[String],
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
        return render_error(json, "the SSH agent runtime could not start", output, error);
    };
    let result = runtime.block_on(ssh_agent::serve_until(
        state_directory,
        socket,
        keys,
        Arc::new(SecureEnclave),
        shutdown(),
    ));
    runtime.shutdown_timeout(Duration::from_secs(1));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => render_error(json, &problem.to_string(), output, error),
    }
}

async fn shutdown() {
    let termination = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
    if let Ok(mut termination) = termination {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = termination.recv() => {},
        }
    } else {
        let _result = tokio::signal::ctrl_c().await;
    }
}
