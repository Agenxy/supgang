//! Owner-controlled runtime under an administrator-installed macOS boot job.

use std::{
    fs::{self, OpenOptions},
    io::{self, Cursor, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    thread,
    time::Instant,
};

use plist::Value;

use super::{
    Action, Report, START_TIMEOUT, ServiceError, control_is_ready, executable, manager_status, owner_home, report,
    validate_state,
};
use crate::control::{self, ControlReply, ControlRequest, ControlStatus};

use super::boot_definition::{root_directory_is_safe, validate_value};

const LABEL: &str = "org.agenxy.supgang";
const DIRECTORY: &str = "/Library/LaunchDaemons";
const LAUNCHCTL: &str = "/bin/launchctl";

fn target() -> String {
    format!("system/{LABEL}.{}", rustix::process::getuid().as_raw())
}

pub(super) fn installed(state: &Path) -> Result<bool, ServiceError> {
    let uid = rustix::process::getuid().as_raw();
    let path = Path::new(DIRECTORY).join(format!("{LABEL}.{uid}.plist"));
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(flags.bits()).map_err(|_| ServiceError::UnsafeDefinition)?)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    for directory in ["/Library", DIRECTORY] {
        let metadata = fs::symlink_metadata(directory)?;
        let safe = root_directory_is_safe(metadata.uid(), metadata.mode(), directory == "/Library");
        if !metadata.is_dir() || !safe {
            return Err(ServiceError::UnsafeDefinition);
        }
    }
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o644
        || metadata.len() > 32 * 1024
        || supgang_acl::reject_non_owner_grants(&file).is_err()
    {
        return Err(ServiceError::UnsafeDefinition);
    }
    let value = Value::from_reader(Cursor::new({
        let mut bytes = Vec::new();
        file.take(32 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 32 * 1024 {
            return Err(ServiceError::UnsafeDefinition);
        }
        bytes
    }))
    .map_err(|_| ServiceError::UnsafeDefinition)?;
    let user = nix::unistd::User::from_uid(nix::unistd::getuid())
        .map_err(io::Error::other)?
        .ok_or(ServiceError::UnsafeDefinition)?;
    let home = owner_home()?;
    if user.uid.is_root() || user.dir != home {
        return Err(ServiceError::UnsafeDefinition);
    }
    let executable = executable::validate_installed()?;
    validate_value(&value, &executable, state, &home, &user.name, uid)?;
    Ok(true)
}

fn active() -> Result<bool, ServiceError> {
    manager_status(Path::new(LAUNCHCTL), &["print", &target()])
}

pub(super) fn preflight_restart(state: &Path) -> Result<(), ServiceError> {
    validate_state(state)?;
    if !installed(state)? || !active()? {
        return Err(ServiceError::BootApprovalRequired);
    }
    for domain in ["user", "gui"] {
        let target = format!("{domain}/{}/{LABEL}", rustix::process::getuid().as_raw());
        if manager_status(Path::new(LAUNCHCTL), &["print", &target])? {
            return Err(ServiceError::UnmanagedProcess);
        }
    }
    let status = running_status(state)?;
    if !status.restart_supported || status.instance_id.len() != 32 {
        return Err(ServiceError::BootApprovalRequired);
    }
    Ok(())
}

fn running_status(state: &Path) -> Result<ControlStatus, ServiceError> {
    match control::request(state, ControlRequest::Status) {
        Ok(Some(ControlReply::Status { value })) => Ok(value),
        _ => Err(ServiceError::NotReady),
    }
}

fn status(state: &Path) -> Result<Report, ServiceError> {
    let active = active()?;
    let mut result = report(
        "launchd",
        true,
        active,
        active && control_is_ready(state).unwrap_or(false),
    );
    result.startup = "system-boot";
    let definition = Path::new(DIRECTORY).join(format!("{LABEL}.{}.plist", rustix::process::getuid().as_raw()));
    super::observation::observe_launchd(&mut result, state, &definition, &target())?;
    Ok(result)
}

pub(super) fn perform(state: &Path, action: Action<'_>) -> Result<Report, ServiceError> {
    match action {
        Action::Status => status(state),
        Action::Start => {
            if !active()? {
                return Err(ServiceError::BootApprovalRequired);
            }
            super::wait_for_control(state, true, START_TIMEOUT)?;
            status(state)
        }
        Action::Refresh => {
            preflight_restart(state)?;
            let refreshed = super::refresh::install(state)?;
            let report = restart(state)?;
            super::refresh::settle(state, refreshed, report)
        }
        Action::Restart => restart(state),
        Action::Install { .. } | Action::Stop | Action::Uninstall => Err(ServiceError::BootApprovalRequired),
    }
}

fn restart(state: &Path) -> Result<Report, ServiceError> {
    preflight_restart(state)?;
    let previous = match control::request(state, ControlRequest::Restart) {
        Ok(Some(ControlReply::Restarting { instance_id })) if instance_id.len() == 32 => instance_id,
        _ => return Err(ServiceError::NotReady),
    };
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        if running_status(state).is_ok_and(|value| value.instance_id.len() == 32 && value.instance_id != previous) {
            return status(state);
        }
        if Instant::now() >= deadline {
            return Err(ServiceError::NotReady);
        }
        thread::sleep(std::time::Duration::from_millis(100));
    }
}
