use std::{path::Path, process::Stdio, time::Duration};

use thiserror::Error;
use tokio::process::{Child, Command};

use super::{UpdateError, lifecycle, lock::UpdateLock};
use crate::{control, transport};

#[path = "attempts.rs"]
mod attempts;

pub(super) fn reset_attempts(updates: &Path) -> Result<(), UpdateError> {
    attempts::reset(updates)
}

const START_TIMEOUT: Duration = Duration::from_secs(10);
const PROBATION: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const SUPERVISED_ENVIRONMENT: &str = "SUPGANG_SUPERVISED";

/// Stable arguments forwarded by the installed update supervisor.
#[derive(Clone, Copy, Debug)]
pub struct SupervisorOptions<'a> {
    /// Optional owner-controlled endpoint configuration.
    pub endpoints: Option<&'a Path>,
    /// Whether the payload runs as a higher-capacity anchor.
    pub anchor: bool,
    /// Whether the owner explicitly enabled local-gateway mapping at install.
    pub router_mapping: bool,
}

/// An installed supervisor startup, child, or update-state failure.
#[derive(Debug, Error)]
pub enum SupervisorError {
    /// Protected update state or a selected payload failed validation.
    #[error("update supervisor state failed validation")]
    Update(#[from] UpdateError),
    /// The asynchronous supervisor runtime could not start.
    #[error("update supervisor runtime failed")]
    Runtime(#[from] crate::transport::TransportError),
    /// The operating system rejected child process management.
    #[error("update supervisor process operation failed")]
    Io(#[from] std::io::Error),
    /// The selected known-good payload could not become healthy.
    #[error("the installed Supgang payload did not become healthy")]
    ActiveUnhealthy,
    /// The active payload exited without a verified replacement pending.
    #[error("the active Supgang payload stopped unexpectedly")]
    ActiveExited,
    /// Operating-system termination handling failed.
    #[error("update supervisor signal handling failed")]
    Signal,
}

/// Runs the stable A/B update supervisor until the service manager stops it.
///
/// A pending candidate must expose a healthy owner-only control socket for a
/// full probation window before it becomes active. Failure deletes only the
/// pending marker and immediately returns to the last known-good slot.
///
/// # Errors
///
/// Returns an error when protected state is unsafe, process management fails,
/// signal handling fails, or the installed known-good payload is unhealthy.
pub fn run_supervisor(state_directory: &Path, options: SupervisorOptions<'_>) -> Result<(), SupervisorError> {
    let runtime = transport::build_runtime()?;
    runtime.block_on(run_loop(state_directory, options))
}

async fn run_loop(state_directory: &Path, options: SupervisorOptions<'_>) -> Result<(), SupervisorError> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    loop {
        let mut update_lock = Some(UpdateLock::acquire(state_directory)?);
        let active = lifecycle::read_active(state_directory)?;
        let pending = lifecycle::read_pending(state_directory)?;
        if pending
            .as_ref()
            .is_some_and(|pending| pending.digest == active.digest && pending.version == active.version)
        {
            lifecycle::commit_pending(state_directory, &active)?;
            drop(update_lock.take());
            continue;
        }
        if pending.is_none() {
            drop(update_lock.take());
        }
        let selected = pending.as_ref().unwrap_or(&active);
        if pending.is_some() && !attempts::reserve(state_directory, selected)? {
            lifecycle::discard_pending(state_directory)?;
            continue;
        }
        super::executable::validate_compatible_identity(&active.executable, &selected.executable)?;
        let mut child = spawn_payload(state_directory, options, selected)?;
        if !wait_until_ready(state_directory, &mut child, START_TIMEOUT).await? {
            stop_child(&mut child).await;
            if pending.is_some() {
                lifecycle::discard_pending(state_directory)?;
                continue;
            }
            return Err(SupervisorError::ActiveUnhealthy);
        }
        if let Some(candidate) = pending.as_ref() {
            if !probation(state_directory, &mut child).await? {
                stop_child(&mut child).await;
                lifecycle::discard_pending(state_directory)?;
                continue;
            }
            lifecycle::commit_pending(state_directory, candidate)?;
            drop(update_lock.take());
        }
        let stopped = tokio::select! {
            status = child.wait() => {
                status?.success()
            }
            signal = terminate.recv() => {
                if signal.is_some() {
                    stop_child(&mut child).await;
                    return Ok(());
                }
                false
            }
            signal = interrupt.recv() => {
                if signal.is_some() {
                    stop_child(&mut child).await;
                    return Ok(());
                }
                false
            }
        };
        if stopped && lifecycle::read_pending(state_directory)?.is_some() {
            continue;
        }
        if stopped {
            // A local owner requested a clean restart. Let the manager re-exec
            // the installed supervisor too, so service refresh replaces its code.
            return Ok(());
        }
        return Err(SupervisorError::ActiveExited);
    }
}

fn spawn_payload(
    state_directory: &Path,
    options: SupervisorOptions<'_>,
    selected: &lifecycle::SlotRecord,
) -> Result<Child, SupervisorError> {
    let mut command = Command::new(&selected.executable);
    command
        .env_clear()
        .env(SUPERVISED_ENVIRONMENT, "1")
        .arg("--json")
        .arg("--state-dir")
        .arg(state_directory)
        .arg(if options.anchor { "anchor" } else { "run" })
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(endpoints) = options.endpoints {
        command.arg("--endpoints").arg(endpoints);
    }
    if options.router_mapping {
        command.arg("--router-mapping");
    }
    command.spawn().map_err(Into::into)
}

async fn wait_until_ready(
    state_directory: &Path,
    child: &mut Child,
    timeout: Duration,
) -> Result<bool, SupervisorError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(false);
        }
        if control::request(state_directory, control::ControlRequest::Status).is_ok_and(|reply| reply.is_some()) {
            return Ok(true);
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn probation(state_directory: &Path, child: &mut Child) -> Result<bool, SupervisorError> {
    let deadline = tokio::time::Instant::now() + PROBATION;
    while tokio::time::Instant::now() < deadline {
        if child.try_wait()?.is_some()
            || !control::request(state_directory, control::ControlRequest::Status).is_ok_and(|reply| reply.is_some())
        {
            return Ok(false);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    Ok(true)
}

async fn stop_child(child: &mut Child) {
    if let Some(pid) = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .and_then(rustix::process::Pid::from_raw)
    {
        let _terminated = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        if tokio::time::timeout(Duration::from_secs(5), child.wait()).await.is_ok() {
            return;
        }
    }
    let _started = child.start_kill();
    let _stopped = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
}
