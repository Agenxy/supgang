//! Bounded manager observations, distinct from the process answering control.

use std::{
    io::Read,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;

use super::{Report, ServiceError};
use crate::control::{self, ControlReply, ControlRequest};

const MAX_OUTPUT: u64 = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Observation {
    pub manager_pid: Option<u32>,
    pub socket_pid: Option<u32>,
    pub socket_parent_pid: Option<u32>,
    pub process_relationship: &'static str,
    pub manager_enablement: Option<String>,
    pub lingering: Option<bool>,
    pub client_version: &'static str,
    pub running_version: Option<String>,
    pub version_note: Option<&'static str>,
    pub control_error: Option<&'static str>,
    pub definition_path: Option<String>,
    pub installed_program: Option<String>,
    pub manager_program: Option<String>,
    pub service_identity: Option<String>,
    pub log_destination: &'static str,
}

impl Observation {
    pub const fn empty() -> Self {
        Self {
            manager_pid: None,
            socket_pid: None,
            socket_parent_pid: None,
            process_relationship: "not-observed",
            manager_enablement: None,
            lingering: None,
            client_version: crate::VERSION,
            running_version: None,
            version_note: None,
            control_error: None,
            definition_path: None,
            installed_program: None,
            manager_program: None,
            service_identity: None,
            log_destination: "/dev/null (standard output and error discarded)",
        }
    }
}

/// Checks a manager exit status without retaining its potentially large inventory.
pub(super) fn status(program: &Path, arguments: &[&str]) -> Result<bool, ServiceError> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = (|| {
        loop {
            if let Some(status) = child.try_wait()? {
                return checked_status(program, arguments, status);
            }
            if Instant::now() >= deadline {
                return Err(ServiceError::Manager);
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        let _killed = child.kill();
        let _waited = child.wait();
    }
    result
}

fn checked_status(program: &Path, arguments: &[&str], status: std::process::ExitStatus) -> Result<bool, ServiceError> {
    // Only ESRCH is evidence that a launchd print target is absent.
    if program == Path::new("/bin/launchctl")
        && arguments.first() == Some(&"print")
        && !status.success()
        && status.code() != Some(113)
    {
        return Err(ServiceError::Manager);
    }
    Ok(status.success())
}

pub(super) fn command(program: &Path, arguments: &[&str]) -> Result<(bool, String), ServiceError> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = child.stdout.take().ok_or(ServiceError::Manager)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let result = (|| {
        let flags = rustix::fs::fcntl_getfl(&stdout).map_err(std::io::Error::from)?;
        rustix::fs::fcntl_setfl(&stdout, flags | rustix::fs::OFlags::NONBLOCK).map_err(std::io::Error::from)?;
        loop {
            let eof = match stdout.read(&mut buffer) {
                Ok(0) => true,
                Ok(count) => {
                    bytes.extend_from_slice(buffer.get(..count).ok_or(ServiceError::Manager)?);
                    false
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
                Err(error) => return Err(ServiceError::Io(error)),
            };
            if bytes.len() > usize::try_from(MAX_OUTPUT).map_err(|_| ServiceError::Manager)? {
                return Err(ServiceError::Manager);
            }
            if let Some(status) = child.try_wait()?
                && eof
            {
                return checked_status(program, arguments, status);
            }
            if Instant::now() >= deadline {
                return Err(ServiceError::Manager);
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        let _killed = child.kill();
        let _waited = child.wait();
    }
    Ok((result?, String::from_utf8(bytes).map_err(|_| ServiceError::Manager)?))
}

// launchctl's child dictionaries may repeat pid, program and state. Only read
// the direct fields of the outer dictionary, never an inherited/nested field.
#[cfg(any(target_os = "macos", test))]
pub(super) fn launchd_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut depth = 0_usize;
    let mut found = None;
    for line in text.lines().map(str::trim) {
        if line == "}" {
            depth = depth.checked_sub(1)?;
        } else if line.ends_with(" = {") {
            depth = depth.checked_add(1)?;
        } else if depth == 1
            && let Some((name, value)) = line.split_once(" = ")
            && name == key
        {
            if found.is_some() {
                return None;
            }
            found = Some(value);
        }
    }
    if depth == 0 { found } else { None }
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn disabled_field(text: &str, label: &str) -> Result<bool, ServiceError> {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    if lines.next() != Some("disabled services = {") {
        return Err(ServiceError::Manager);
    }
    let expected = format!("\"{label}\"");
    let mut found = None;
    for line in lines.by_ref() {
        if line == "}" {
            if lines.next().is_some() {
                return Err(ServiceError::Manager);
            }
            return Ok(found.unwrap_or(false));
        }
        let (name, value) = line.split_once(" => ").ok_or(ServiceError::Manager)?;
        let disabled = match value {
            "true" | "disabled" => true,
            "false" | "enabled" => false,
            _ => return Err(ServiceError::Manager),
        };
        if name == expected {
            if found.is_some() {
                return Err(ServiceError::Manager);
            }
            found = Some(disabled);
        }
    }
    Err(ServiceError::Manager)
}

#[cfg(target_os = "macos")]
pub(super) fn launchd_disabled(domain: &str, label: &str) -> Result<bool, ServiceError> {
    let (success, text) = command(Path::new("/bin/launchctl"), &["print-disabled", domain])?;
    if !success {
        return Err(ServiceError::Manager);
    }
    disabled_field(&text, label)
}

#[cfg(target_os = "macos")]
pub(super) fn observe_launchd(
    report: &mut Report,
    state: &Path,
    definition: &Path,
    target: &str,
) -> Result<(), ServiceError> {
    let (domain, label) = target.rsplit_once('/').ok_or(ServiceError::Manager)?;
    let disabled = launchd_disabled(domain, label)?;
    let (loaded, text) = command(Path::new("/bin/launchctl"), &["print", target])?;
    report.observation.manager_pid = launchd_field(&text, "pid").and_then(nonzero_pid);
    report.observation.manager_program = launchd_field(&text, "program").map(str::to_owned);
    report.observation.manager_enablement = Some(if disabled { "disabled-by-owner" } else { "enabled" }.to_owned());
    report.observation.service_identity = Some(label.to_owned());
    observe_control(report, state, definition, loaded, disabled)
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn systemd_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut found = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix(key).and_then(|rest| rest.strip_prefix('=')) {
            if found.is_some() {
                return None;
            }
            found = Some(value);
        }
    }
    found
}

fn nonzero_pid(text: &str) -> Option<u32> {
    text.parse().ok().filter(|value| *value != 0)
}

#[cfg(target_os = "linux")]
pub(super) fn observe_systemd(report: &mut Report, state: &Path, definition: &Path) -> Result<(), ServiceError> {
    let (success, text) = command(
        Path::new("/usr/bin/systemctl"),
        &[
            "--user",
            "show",
            "supgang.service",
            "--property=MainPID,ActiveState,UnitFileState,FragmentPath",
        ],
    )?;
    if !success {
        return Err(ServiceError::Manager);
    }
    report.observation.manager_pid = systemd_field(&text, "MainPID").and_then(nonzero_pid);
    let enablement = systemd_field(&text, "UnitFileState").ok_or(ServiceError::Manager)?;
    let disabled = matches!(enablement, "disabled" | "masked" | "masked-runtime");
    report.observation.manager_enablement = Some(enablement.to_owned());
    report.observation.service_identity =
        Some("supgang.service; Supgang peer address discovery; journal: supgang".to_owned());
    let uid = rustix::process::getuid().as_raw().to_string();
    let linger = command(
        Path::new("/usr/bin/loginctl"),
        &["show-user", &uid, "--property=Linger"],
    );
    report.observation.lingering = if let Ok((true, linger)) = linger {
        match systemd_field(&linger, "Linger") {
            Some("yes") => Some(true),
            Some("no") => Some(false),
            _ => None,
        }
    } else {
        None
    };
    let loaded = matches!(
        systemd_field(&text, "ActiveState"),
        Some("active" | "activating" | "deactivating")
    );
    observe_control(report, state, definition, loaded, disabled)
}

fn observe_control(
    report: &mut Report,
    state: &Path,
    definition: &Path,
    loaded: bool,
    disabled: bool,
) -> Result<(), ServiceError> {
    report.observation.definition_path = Some(definition.display().to_string());
    if report.installed {
        report.observation.installed_program = Some(super::executable::validate_installed()?.display().to_string());
    }
    match control::request_observed(state, ControlRequest::Status) {
        Ok(Some((ControlReply::Status { value }, pid))) => {
            report.observation.socket_pid = Some(pid);
            let process = pid.to_string();
            if let Ok((true, parent)) = command(Path::new("/bin/ps"), &["-p", &process, "-o", "ppid="]) {
                report.observation.socket_parent_pid = nonzero_pid(parent.trim());
            }
            report.observation.version_note = version_note(&value.version);
            report.observation.running_version = Some(value.version);
        }
        Ok(None) => {}
        Ok(Some(_)) | Err(control::ControlError::InvalidResponse) => {
            report.observation.control_error = Some(
                "The local service response is unreadable or incompatible; run `supgang service refresh` after checking service status.",
            );
        }
        Err(_) => {
            report.observation.control_error = Some(
                "The local control socket could not be read or authenticated; readiness and running version are unverified.",
            );
        }
    }
    classify(report, loaded, disabled);
    Ok(())
}

pub fn version_note(version: &str) -> Option<&'static str> {
    (version != crate::VERSION).then_some("Client and running service versions differ (an empty service version means an older build); run `supgang service refresh`.")
}

pub(super) fn classify(report: &mut Report, loaded: bool, disabled: bool) {
    let evidence = &mut report.observation;
    evidence.process_relationship = match (evidence.manager_pid, evidence.socket_pid) {
        (Some(manager), Some(socket)) if manager == socket => "same-process",
        (Some(manager), Some(_)) if evidence.socket_parent_pid == Some(manager) => "supervisor-child",
        (Some(_), Some(_)) if evidence.socket_parent_pid.is_some() => "running-outside-manager",
        (None, Some(_)) if !loaded => "running-outside-manager",
        (Some(_), Some(_)) => "different-pids-ownership-unverified",
        _ => "not-observed",
    };
    report.running = evidence.socket_pid.is_some();
    report.state = if disabled {
        "disabled-by-owner"
    } else if evidence.process_relationship == "running-outside-manager" {
        "running-outside-manager"
    } else if report.running {
        "running"
    } else if loaded {
        "starting-or-unhealthy"
    } else if report.installed {
        "stopped"
    } else {
        "not-installed"
    };
}

#[cfg(test)]
mod tests;
