use std::path::{Path, PathBuf};

use super::{
    Action, Report, START_TIMEOUT, STOP_TIMEOUT, ServiceError, control_is_ready, definition, ensure_child_directory,
    ensure_no_unmanaged_process, executable, manager_status, owner_home, remove_definition,
    replace_installed_executable, report, validate_definition, validate_state, wait_for_control, write_atomic,
};

const MANAGER: &str = "launchd";
const LABEL: &str = "org.agenxy.supgang";
const LAUNCHCTL: &str = "/bin/launchctl";

pub(super) fn perform(state_directory: &Path, action: Action<'_>) -> Result<Report, ServiceError> {
    if super::system_boot::installed(state_directory)? {
        return super::system_boot::perform(state_directory, action);
    }
    if matches!(
        action,
        Action::Install { .. } | Action::Refresh | Action::Start | Action::Restart
    ) {
        require_user_domain()?;
    }
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
    let library = if create {
        ensure_child_directory(&home, "Library")?
    } else {
        home.join("Library")
    };
    let agents = if create {
        ensure_child_directory(&library, "LaunchAgents")?
    } else {
        library.join("LaunchAgents")
    };
    Ok(agents.join(format!("{LABEL}.plist")))
}

fn loaded_target() -> Result<Option<String>, ServiceError> {
    let uid = rustix::process::getuid().as_raw();
    let mut found = None;
    for domain in ["gui", "user"] {
        let target = format!("{domain}/{uid}/{LABEL}");
        if manager_status(Path::new(LAUNCHCTL), &["print", &target])? {
            if found.is_some() {
                return Err(ServiceError::UnmanagedProcess);
            }
            found = Some(target);
        }
    }
    Ok(found)
}

fn domain() -> Result<String, ServiceError> {
    let path = definition_path(false)?;
    let legacy = if validate_definition(&path)? {
        use std::io::Read as _;
        let file = std::fs::File::open(path)?;
        if file.metadata()?.len() > 32 * 1024 {
            return Err(ServiceError::UnsafeDefinition);
        }
        let mut bytes = Vec::new();
        file.take(32 * 1024 + 1).read_to_end(&mut bytes)?;
        let value =
            plist::Value::from_reader(std::io::Cursor::new(bytes)).map_err(|_| ServiceError::UnsafeDefinition)?;
        value
            .as_dictionary()
            .and_then(|dict| dict.get("LimitLoadToSessionType"))
            .and_then(plist::Value::as_string)
            == Some("Background")
    } else {
        false
    };
    Ok(format!(
        "{}/{}",
        if legacy { "user" } else { "gui" },
        rustix::process::getuid().as_raw()
    ))
}

fn active() -> Result<bool, ServiceError> {
    loaded_target().map(|target| target.is_some())
}

fn install(
    state_directory: &Path,
    service_definition: &Path,
    endpoints: Option<&Path>,
    anchor: bool,
    router_mapping: bool,
) -> Result<Report, ServiceError> {
    let gui = format!("gui/{}", rustix::process::getuid().as_raw());
    if !manager_status(Path::new(LAUNCHCTL), &["print", &gui])? {
        return Err(ServiceError::NoMacosUserDomain);
    }
    validate_state(state_directory)?;
    let endpoints = definition::validated_endpoints(endpoints)?;
    let was_active = active()?;
    ensure_no_unmanaged_process(state_directory, was_active)?;
    let executable = replace_installed_executable(state_directory, false)?;
    write_atomic(
        service_definition,
        definition::render_launchd(
            &executable,
            state_directory,
            endpoints.as_deref(),
            anchor,
            router_mapping,
        )?
        .as_bytes(),
    )?;
    if was_active {
        bootout()?;
        wait_for_control(state_directory, false, STOP_TIMEOUT)?;
    }
    bootstrap(service_definition)?;
    wait_for_control(state_directory, true, START_TIMEOUT)?;
    status(state_directory, service_definition)
}

fn refresh(state_directory: &Path, service_definition: &Path) -> Result<Report, ServiceError> {
    preflight_restart_with_definition(state_directory, service_definition)?;
    let _executable = replace_installed_executable(state_directory, true)?;
    restart(state_directory, service_definition)
}

pub(super) fn preflight_restart(state_directory: &Path) -> Result<(), ServiceError> {
    if super::system_boot::installed(state_directory)? {
        return super::system_boot::preflight_restart(state_directory);
    }
    require_user_domain()?;
    preflight_restart_with_definition(state_directory, &definition_path(false)?)
}

fn preflight_restart_with_definition(state_directory: &Path, service_definition: &Path) -> Result<(), ServiceError> {
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
    let mut result = report(MANAGER, installed, manager_active, ready);
    result.startup = if domain()?.starts_with("user/") {
        "manual-session-only"
    } else {
        "graphical-login"
    };
    Ok(result)
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
        bootstrap(definition)?;
    }
    wait_for_control(state_directory, true, START_TIMEOUT)?;
    status(state_directory, definition)
}

fn stop(state_directory: &Path, definition: &Path) -> Result<Report, ServiceError> {
    let installed = validate_definition(definition)?;
    if active()? {
        bootout()?;
        wait_for_control(state_directory, false, STOP_TIMEOUT)?;
    }
    Ok(report(MANAGER, installed, false, false))
}

fn restart(state_directory: &Path, definition: &Path) -> Result<Report, ServiceError> {
    preflight_restart_with_definition(state_directory, definition)?;
    let manager_active = active()?;
    if manager_active {
        bootout()?;
        wait_for_control(state_directory, false, STOP_TIMEOUT)?;
    }
    bootstrap(definition)?;
    wait_for_control(state_directory, true, START_TIMEOUT)?;
    status(state_directory, definition)
}

fn uninstall(state_directory: &Path, definition: &Path) -> Result<Report, ServiceError> {
    if active()? {
        bootout()?;
        wait_for_control(state_directory, false, STOP_TIMEOUT)?;
    }
    remove_definition(definition)?;
    Ok(report(MANAGER, false, false, false))
}

fn bootout() -> Result<(), ServiceError> {
    let target = loaded_target()?.ok_or(ServiceError::NotInstalled)?;
    if !manager_status(Path::new(LAUNCHCTL), &["bootout", &target])? {
        return Err(ServiceError::Manager);
    }
    Ok(())
}

fn bootstrap(definition: &Path) -> Result<(), ServiceError> {
    let path = definition.to_str().ok_or(ServiceError::UnsafeDefinition)?;
    require_user_domain()?;
    let target = format!("{}/{LABEL}", domain()?);
    if !manager_status(Path::new(LAUNCHCTL), &["enable", &target])? {
        return Err(ServiceError::Manager);
    }
    if !manager_status(Path::new(LAUNCHCTL), &["bootstrap", &domain()?, path])? {
        return Err(ServiceError::Manager);
    }
    Ok(())
}

fn require_user_domain() -> Result<(), ServiceError> {
    if manager_status(Path::new(LAUNCHCTL), &["print", &domain()?])? {
        Ok(())
    } else {
        Err(ServiceError::NoMacosUserDomain)
    }
}
