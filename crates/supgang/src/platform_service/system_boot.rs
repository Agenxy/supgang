//! Owner-controlled runtime under an administrator-installed macOS boot job.

use std::{
    fs::{self, OpenOptions},
    io::{self, Cursor, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    thread,
    time::Instant,
};

use plist::Value;

use super::{
    Action, Report, START_TIMEOUT, ServiceError, control_is_ready, definition, executable, manager_status, owner_home,
    replace_installed_executable, report, validate_state,
};
use crate::control::{self, ControlReply, ControlRequest, ControlStatus};

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

const fn root_directory_is_safe(uid: u32, mode: u32, sticky_parent: bool) -> bool {
    uid == 0 && mode & 0o002 == 0 && (mode & 0o020 == 0 || (sticky_parent && mode & 0o1000 != 0))
}

fn validate_value(
    value: &Value,
    executable: &Path,
    state: &Path,
    home: &Path,
    user: &str,
    uid: u32,
) -> Result<(), ServiceError> {
    let arguments = value
        .as_dictionary()
        .and_then(|dict| dict.get("ProgramArguments"))
        .and_then(Value::as_array)
        .ok_or(ServiceError::UnsafeDefinition)?;
    let arguments = arguments
        .iter()
        .map(|argument| argument.as_string().ok_or(ServiceError::UnsafeDefinition))
        .collect::<Result<Vec<_>, _>>()?;
    let (anchor, mapping, endpoints) = parse_policy(&arguments)?;
    let expected = boot_definition(
        executable,
        state,
        home,
        user,
        uid,
        (anchor, mapping, endpoints.as_deref()),
    )?;
    if value != &expected {
        return Err(ServiceError::UnsafeDefinition);
    }
    Ok(())
}

fn parse_policy(arguments: &[&str]) -> Result<(bool, bool, Option<PathBuf>), ServiceError> {
    let mut remaining = arguments.get(5..).ok_or(ServiceError::UnsafeDefinition)?;
    let anchor = remaining.first() == Some(&"--anchor");
    if anchor {
        remaining = remaining.get(1..).ok_or(ServiceError::UnsafeDefinition)?;
    }
    let mapping = remaining.first() == Some(&"--router-mapping");
    if mapping {
        remaining = remaining.get(1..).ok_or(ServiceError::UnsafeDefinition)?;
    }
    let endpoints = match remaining {
        [] => None,
        ["--endpoints", path] if !mapping => Some(PathBuf::from(path)),
        _ => return Err(ServiceError::UnsafeDefinition),
    };
    if let Some(path) = &endpoints {
        definition::validated_endpoints(Some(path))?;
    }
    Ok((anchor, mapping, endpoints))
}

fn boot_definition(
    executable: &Path,
    state: &Path,
    _home: &Path,
    user: &str,
    uid: u32,
    policy: (bool, bool, Option<&Path>),
) -> Result<Value, ServiceError> {
    let (anchor, mapping, endpoints) = policy;
    let text = definition::render_launchd(executable, state, endpoints, anchor, mapping)?;
    let mut value = Value::from_reader_xml(text.as_bytes()).map_err(|_| ServiceError::UnsafeDefinition)?;
    let dict = value.as_dictionary_mut().ok_or(ServiceError::UnsafeDefinition)?;
    dict.remove("LimitLoadToSessionType");
    dict.insert("Label".to_owned(), Value::String(format!("{LABEL}.{uid}")));
    dict.insert("UserName".to_owned(), Value::String(user.to_owned()));
    dict.insert("Umask".to_owned(), Value::Integer(63.into()));
    Ok(value)
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
            let _executable = replace_installed_executable(state, true)?;
            restart(state)
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{boot_definition, validate_value};

    #[test]
    fn sticky_admin_library_preserves_root_owned_child_trust() {
        assert!(super::root_directory_is_safe(0, 0o1775, true));
        assert!(super::root_directory_is_safe(0, 0o755, false));
        assert!(!super::root_directory_is_safe(501, 0o1775, true));
        assert!(!super::root_directory_is_safe(0, 0o775, true));
        assert!(!super::root_directory_is_safe(0, 0o1777, true));
        assert!(!super::root_directory_is_safe(0, 0o1775, false));
    }

    #[test]
    fn boot_definition_rejects_elevation_and_changed_authority() -> Result<(), Box<dyn std::error::Error>> {
        let executable = Path::new("/Users/member/bin/supgang");
        let state = Path::new("/Users/member/state");
        let home = Path::new("/Users/member");
        let value = boot_definition(executable, state, home, "member", 501, (true, true, None))?;
        validate_value(&value, executable, state, home, "member", 501)?;
        for (key, replacement) in [
            ("UserName", plist::Value::String("root".to_owned())),
            ("KeepAlive", plist::Value::Boolean(false)),
            ("Program", plist::Value::String("/tmp/other".to_owned())),
            (
                "EnvironmentVariables",
                plist::Value::Dictionary(plist::Dictionary::new()),
            ),
        ] {
            let mut changed = value.clone();
            changed
                .as_dictionary_mut()
                .ok_or("not a dictionary")?
                .insert(key.to_owned(), replacement);
            assert!(validate_value(&changed, executable, state, home, "member", 501).is_err());
        }
        assert!(
            validate_value(
                &value,
                executable,
                Path::new("/Users/member/other"),
                home,
                "member",
                501
            )
            .is_err()
        );
        assert!(validate_value(&value, executable, state, home, "member", 502).is_err());
        Ok(())
    }
}
