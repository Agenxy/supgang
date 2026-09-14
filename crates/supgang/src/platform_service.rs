//! Native per-user background-service installation for macOS and Linux.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;

use crate::{control, storage};

mod definition;
mod executable;
#[cfg(target_os = "macos")]
mod system_boot;

const SERVICE_NAME: &str = "supgang";
// A service re-install can briefly contend with the update supervisor while
// the active slot is revalidated, and launchd/systemd may also apply their own
// restart throttle. Keep this longer than the payload's bounded ten-second
// readiness probe so a healthy service is not reported as a failed install.
const START_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Requested background-service operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action<'a> {
    Install {
        endpoints: Option<&'a Path>,
        anchor: bool,
        router_mapping: bool,
    },
    Refresh,
    Status,
    Start,
    Stop,
    Restart,
    Uninstall,
}

/// Stable, non-secret result of a background-service operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    pub startup: &'static str,
    pub manager: &'static str,
    pub state: &'static str,
    pub installed: bool,
    pub running: bool,
    pub data_preserved: bool,
}

/// Background-service validation or manager failure.
#[derive(Debug, Error)]
pub enum ServiceError {
    // Raised only by the macOS boot-service path, so the variant follows the
    // module that constructs it: on Linux it would be dead code under
    // `-D warnings`.
    #[cfg(target_os = "macos")]
    #[error(
        "this boot service needs owner setup; run the reviewed macOS setup script to install, change, stop, or remove it"
    )]
    BootApprovalRequired,
    #[error("background service filesystem operation failed")]
    Io(#[from] io::Error),
    #[error("background service requires a safe, initialized Supgang state directory")]
    InvalidState,
    #[error("the current Supgang executable is not a safe owner-controlled regular file")]
    UnsafeExecutable,
    #[error(
        "the current Supgang command is older than protected update state and cannot replace the installed supervisor"
    )]
    UpdateRollback,
    #[error("the installed supervisor cannot be refreshed while another update operation is in progress")]
    UpdateBusy,
    #[error("the background service endpoint configuration is unsafe or invalid")]
    InvalidEndpoints,
    #[error("the background service directory or definition is unsafe")]
    UnsafeDefinition,
    #[error("the background service is not installed; run `supgang service install`")]
    NotInstalled,
    #[error("Supgang is already running outside the background manager; stop it before installing or starting")]
    UnmanagedProcess,
    #[error("the operating-system background manager rejected the request")]
    Manager,
    #[cfg(target_os = "macos")]
    #[error(
        "macOS has no suitable login session for this service; sign in to the desktop as this account, or use the macOS owner setup script for startup at boot without login"
    )]
    NoMacosUserDomain,
    #[error("the background manager accepted the request, but Supgang did not become ready in time")]
    NotReady,
    #[error("Supgang did not stop within the bounded wait")]
    DidNotStop,
    #[error("background services are supported only on macOS and Linux")]
    Unsupported,
}

/// Runs one native background-service operation.
///
/// # Errors
///
/// Fails closed for unsafe paths, unmanaged competing processes, manager
/// failures, or a service that does not become ready within a fixed bound.
pub fn perform(state_directory: &Path, action: Action<'_>) -> Result<Report, ServiceError> {
    #[cfg(target_os = "macos")]
    {
        return macos::perform(state_directory, action);
    }
    #[cfg(target_os = "linux")]
    {
        return linux::perform(state_directory, action);
    }
    #[allow(unreachable_code)]
    Err(ServiceError::Unsupported)
}

/// Checks that an installed service can be restarted without changing durable state.
///
/// # Errors
///
/// Fails closed when the service, executable, owner state, background-manager
/// domain, or process ownership boundary is not ready for a restart.
pub fn preflight_restart(state_directory: &Path) -> Result<(), ServiceError> {
    #[cfg(target_os = "macos")]
    {
        return macos::preflight_restart(state_directory);
    }
    #[cfg(target_os = "linux")]
    {
        return linux::preflight_restart(state_directory);
    }
    #[allow(unreachable_code)]
    Err(ServiceError::Unsupported)
}

fn validate_state(state_directory: &Path) -> Result<(), ServiceError> {
    storage::validate_directory(state_directory).map_err(|_| ServiceError::InvalidState)?;
    storage::load_identity(state_directory).map_err(|_| ServiceError::InvalidState)?;
    Ok(())
}

fn owner_home() -> Result<PathBuf, ServiceError> {
    #[cfg(target_os = "macos")]
    {
        let owner = nix::unistd::User::from_uid(nix::unistd::getuid())
            .map_err(io::Error::other)?
            .ok_or(ServiceError::UnsafeDefinition)?;
        storage::validate_trusted_owner_directory(&owner.dir).map_err(|_| ServiceError::UnsafeDefinition)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .ok_or(ServiceError::UnsafeDefinition)?;
        storage::validate_trusted_owner_directory(&PathBuf::from(home)).map_err(|_| ServiceError::UnsafeDefinition)
    }
}

fn ensure_child_directory(parent: &Path, name: &str) -> Result<PathBuf, ServiceError> {
    validate_owner_directory(parent)?;
    let child = parent.join(name);
    match fs::symlink_metadata(&child) {
        Ok(_) => validate_owner_directory(&child)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&child)?;
            fs::set_permissions(&child, fs::Permissions::from_mode(0o700))?;
            supgang_acl::clear_inherited_acl(&File::open(&child)?)?;
            validate_owner_directory(&child)?;
            File::open(parent)?.sync_all()?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(child)
}

fn validate_owner_directory(path: &Path) -> Result<(), ServiceError> {
    storage::validate_trusted_owner_directory(path)
        .map(|_| ())
        .map_err(|_| ServiceError::UnsafeDefinition)
}

fn validate_definition(path: &Path) -> Result<bool, ServiceError> {
    let no_follow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).map_err(|_| ServiceError::UnsafeDefinition)?;
    let file = match OpenOptions::new().read(true).custom_flags(no_follow).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let parent = path.parent().ok_or(ServiceError::UnsafeDefinition)?;
    validate_owner_directory(parent)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o022 != 0
        || supgang_acl::reject_non_owner_grants(&file).is_err()
    {
        return Err(ServiceError::UnsafeDefinition);
    }
    Ok(true)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ServiceError> {
    if bytes.is_empty() || bytes.len() > 32 * 1024 {
        return Err(ServiceError::UnsafeDefinition);
    }
    let parent = path.parent().ok_or(ServiceError::UnsafeDefinition)?;
    validate_owner_directory(parent)?;
    let _existing = validate_definition(path)?;
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_| ServiceError::UnsafeDefinition)?;
    let temporary = parent.join(format!(".{SERVICE_NAME}.{}.tmp", hex::encode(random)));
    let no_follow = i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits())
        .map_err(|_| ServiceError::UnsafeDefinition)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(no_follow)
        .open(&temporary)?;
    supgang_acl::clear_inherited_acl(&file)?;
    let result = (|| -> Result<(), ServiceError> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _remove_result = fs::remove_file(&temporary);
    }
    result
}

fn remove_definition(path: &Path) -> Result<(), ServiceError> {
    if validate_definition(path)? {
        fs::remove_file(path)?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}

fn manager_status(program: &Path, arguments: &[&str]) -> Result<bool, ServiceError> {
    let status = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(status.success())
}

fn control_is_ready(state_directory: &Path) -> Result<bool, control::ControlError> {
    control::request(state_directory, control::ControlRequest::Status).map(|reply| reply.is_some())
}

fn wait_for_control(state_directory: &Path, expected: bool, timeout: Duration) -> Result<(), ServiceError> {
    let deadline = Instant::now() + timeout;
    loop {
        match control_is_ready(state_directory) {
            Ok(ready) if ready == expected => return Ok(()),
            Ok(_) | Err(control::ControlError::Io(_) | control::ControlError::InvalidResponse) => {}
            Err(_) => return Err(ServiceError::NotReady),
        }
        if Instant::now() >= deadline {
            return Err(if expected {
                ServiceError::NotReady
            } else {
                ServiceError::DidNotStop
            });
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn ensure_no_unmanaged_process(state_directory: &Path, manager_active: bool) -> Result<(), ServiceError> {
    if !manager_active && control_is_ready(state_directory).map_err(|_| ServiceError::NotReady)? {
        return Err(ServiceError::UnmanagedProcess);
    }
    Ok(())
}

fn replace_installed_executable(state_directory: &Path, require_active: bool) -> Result<PathBuf, ServiceError> {
    let update_lock =
        crate::update::UpdateLock::acquire(state_directory).map_err(|error| service_update_error(&error))?;
    if require_active {
        crate::update::preflight_local_refresh_unlocked(state_directory)
            .map_err(|error| service_update_error(&error))?;
    } else {
        crate::update::preflight_local_install_unlocked(state_directory)
            .map_err(|error| service_update_error(&error))?;
    }
    let executable = executable::install_current()?;
    crate::update::initialize_installed_unlocked(state_directory, &executable)
        .map_err(|error| service_update_error(&error))?;
    drop(update_lock);
    Ok(executable)
}

const fn service_update_error(error: &crate::update::UpdateError) -> ServiceError {
    match error {
        crate::update::UpdateError::Rollback => ServiceError::UpdateRollback,
        crate::update::UpdateError::Busy => ServiceError::UpdateBusy,
        _ => ServiceError::UnsafeExecutable,
    }
}

const fn report(manager: &'static str, installed: bool, active: bool, ready: bool) -> Report {
    let state = if active && ready {
        "running"
    } else if active {
        "starting-or-unhealthy"
    } else if installed {
        "stopped"
    } else {
        "not-installed"
    };
    Report {
        startup: "user-session",
        manager,
        state,
        installed,
        running: active && ready,
        data_preserved: true,
    }
}

#[cfg(test)]
mod tests;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        env,
        path::{Path, PathBuf},
    };

    use super::{
        Action, Report, START_TIMEOUT, STOP_TIMEOUT, ServiceError, control_is_ready, definition,
        ensure_child_directory, ensure_no_unmanaged_process, executable, manager_status, owner_home, remove_definition,
        replace_installed_executable, report, validate_definition, validate_owner_directory, validate_state,
        wait_for_control, write_atomic,
    };

    const MANAGER: &str = "systemd-user";
    const SYSTEMCTL: &str = "/usr/bin/systemctl";
    const UNIT: &str = "supgang.service";

    pub(super) fn perform(state_directory: &Path, action: Action<'_>) -> Result<Report, ServiceError> {
        let service_definition = definition_path(matches!(action, Action::Install { .. }))?;
        match action {
            Action::Install {
                endpoints,
                anchor,
                router_mapping,
            } => install(state_directory, &service_definition, endpoints, anchor, router_mapping),
            Action::Refresh => refresh(state_directory, &service_definition),
            Action::Status => status(state_directory, &service_definition),
            Action::Start => start(state_directory, &service_definition),
            Action::Stop => stop(state_directory, &service_definition),
            Action::Restart => restart(state_directory, &service_definition),
            Action::Uninstall => uninstall(state_directory, &service_definition),
        }
    }

    fn definition_path(create: bool) -> Result<PathBuf, ServiceError> {
        let home = owner_home()?;
        let config = match env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
            Some(value) => {
                let path = PathBuf::from(value);
                validate_owner_directory(&path)?;
                path
            }
            None if create => ensure_child_directory(&home, ".config")?,
            None => home.join(".config"),
        };
        let systemd = if create {
            ensure_child_directory(&config, "systemd")?
        } else {
            config.join("systemd")
        };
        let user = if create {
            ensure_child_directory(&systemd, "user")?
        } else {
            systemd.join("user")
        };
        Ok(user.join(UNIT))
    }

    fn active() -> Result<bool, ServiceError> {
        manager_status(Path::new(SYSTEMCTL), &["--user", "is-active", "--quiet", UNIT])
    }

    fn manager(arguments: &[&str]) -> Result<(), ServiceError> {
        if manager_status(Path::new(SYSTEMCTL), arguments)? {
            Ok(())
        } else {
            Err(ServiceError::Manager)
        }
    }

    fn install(
        state_directory: &Path,
        service_definition: &Path,
        endpoints: Option<&Path>,
        anchor: bool,
        router_mapping: bool,
    ) -> Result<Report, ServiceError> {
        validate_state(state_directory)?;
        let endpoints = definition::validated_endpoints(endpoints)?;
        let manager_active = active()?;
        ensure_no_unmanaged_process(state_directory, manager_active)?;
        let executable = replace_installed_executable(state_directory, false)?;
        write_atomic(
            service_definition,
            definition::render_systemd(
                &executable,
                state_directory,
                endpoints.as_deref(),
                anchor,
                router_mapping,
            )?
            .as_bytes(),
        )?;
        if manager_active {
            manager(&["--user", "stop", UNIT])?;
            wait_for_control(state_directory, false, STOP_TIMEOUT)?;
        }
        manager(&["--user", "daemon-reload"])?;
        manager(&["--user", "enable", "--now", UNIT])?;
        wait_for_control(state_directory, true, START_TIMEOUT)?;
        status(state_directory, service_definition)
    }

    fn refresh(state_directory: &Path, service_definition: &Path) -> Result<Report, ServiceError> {
        preflight_restart_with_definition(state_directory, service_definition)?;
        let _executable = replace_installed_executable(state_directory, true)?;
        restart(state_directory, service_definition)
    }

    pub(super) fn preflight_restart(state_directory: &Path) -> Result<(), ServiceError> {
        preflight_restart_with_definition(state_directory, &definition_path(false)?)
    }

    fn preflight_restart_with_definition(
        state_directory: &Path,
        service_definition: &Path,
    ) -> Result<(), ServiceError> {
        if !validate_definition(service_definition)? {
            return Err(ServiceError::NotInstalled);
        }
        let _executable = executable::validate_installed()?;
        validate_state(state_directory)?;
        let manager_active = active()?;
        ensure_no_unmanaged_process(state_directory, manager_active)
    }

    fn status(state_directory: &Path, definition: &Path) -> Result<Report, ServiceError> {
        let installed = validate_definition(definition)?;
        if installed {
            let _executable = executable::validate_installed()?;
        }
        let manager_active = active()?;
        let ready = manager_active && control_is_ready(state_directory).unwrap_or(false);
        Ok(report(MANAGER, installed, manager_active, ready))
    }

    fn start(state_directory: &Path, definition: &Path) -> Result<Report, ServiceError> {
        if !validate_definition(definition)? {
            return Err(ServiceError::NotInstalled);
        }
        let _executable = executable::validate_installed()?;
        validate_state(state_directory)?;
        let manager_active = active()?;
        ensure_no_unmanaged_process(state_directory, manager_active)?;
        if !manager_active {
            manager(&["--user", "start", UNIT])?;
        }
        wait_for_control(state_directory, true, START_TIMEOUT)?;
        status(state_directory, definition)
    }

    fn stop(state_directory: &Path, definition: &Path) -> Result<Report, ServiceError> {
        let installed = validate_definition(definition)?;
        if active()? {
            manager(&["--user", "stop", UNIT])?;
            wait_for_control(state_directory, false, STOP_TIMEOUT)?;
        }
        Ok(report(MANAGER, installed, false, false))
    }

    fn restart(state_directory: &Path, definition: &Path) -> Result<Report, ServiceError> {
        preflight_restart_with_definition(state_directory, definition)?;
        manager(&["--user", "restart", UNIT])?;
        wait_for_control(state_directory, true, START_TIMEOUT)?;
        status(state_directory, definition)
    }

    fn uninstall(state_directory: &Path, definition: &Path) -> Result<Report, ServiceError> {
        if active()? {
            manager(&["--user", "disable", "--now", UNIT])?;
            wait_for_control(state_directory, false, STOP_TIMEOUT)?;
        } else {
            let _disabled = manager_status(Path::new(SYSTEMCTL), &["--user", "disable", UNIT])?;
        }
        remove_definition(definition)?;
        manager(&["--user", "daemon-reload"])?;
        Ok(report(MANAGER, false, false, false))
    }
}
