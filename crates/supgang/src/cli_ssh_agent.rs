//! Long-running local SSH-agent command.

use std::{io::Write, path::Path, process::ExitCode, sync::Arc};

use crate::{cli::render_error, ssh_agent, vault::SecureEnclave};

pub(crate) fn run(
    state_directory: &Path,
    socket: &Path,
    keys: &[String],
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(_) => return render_error(json, "the SSH agent runtime could not start", output, error),
    };
    match runtime.block_on(ssh_agent::serve_until(
        state_directory,
        socket,
        keys,
        Arc::new(SecureEnclave),
        shutdown(),
    )) {
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
