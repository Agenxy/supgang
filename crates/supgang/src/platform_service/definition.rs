//! Safe native service-definition rendering and endpoint-file validation.

use std::path::{Path, PathBuf};

use crate::{endpoint_config::EndpointConfig, storage};

use super::ServiceError;

/// The scheduling class every launchd definition requests. Supgang carries live
/// remote sessions, so it must not run in the Background class: macOS confines
/// that class to efficiency cores and throttles its I/O, and under sustained
/// load the service then stops answering its control socket and its tunnels.
#[cfg(any(target_os = "macos", test))]
pub(super) const PROCESS_TYPE: &str = "Standard";
/// The class earlier releases wrote. It names no authority, so an installed
/// definition carrying it is accepted and upgraded rather than refused.
#[cfg(any(target_os = "macos", test))]
pub(super) const LEGACY_PROCESS_TYPE: &str = "Background";

/// Returns the definition with a legacy scheduling class replaced, or `None`
/// when it already requests the current class or names some other one.
#[cfg(any(target_os = "macos", test))]
pub(super) fn upgraded_process_type(value: &plist::Value) -> Option<plist::Value> {
    let dict = value.as_dictionary()?;
    if dict.get("ProcessType").and_then(plist::Value::as_string) != Some(LEGACY_PROCESS_TYPE) {
        return None;
    }
    let mut upgraded = value.clone();
    upgraded
        .as_dictionary_mut()?
        .insert("ProcessType".to_owned(), plist::Value::String(PROCESS_TYPE.to_owned()));
    Some(upgraded)
}

pub(super) fn validated_endpoints(path: Option<&Path>) -> Result<Option<PathBuf>, ServiceError> {
    path.map(|path| {
        let canonical = path.canonicalize().map_err(|_| ServiceError::InvalidEndpoints)?;
        let parent = canonical.parent().ok_or(ServiceError::InvalidEndpoints)?;
        storage::validate_trusted_owner_directory(parent).map_err(|_| ServiceError::InvalidEndpoints)?;
        EndpointConfig::read(&canonical).map_err(|_| ServiceError::InvalidEndpoints)?;
        Ok(canonical)
    })
    .transpose()
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn render_launchd(
    executable: &Path,
    state_directory: &Path,
    endpoints: Option<&Path>,
    anchor: bool,
    router_mapping: bool,
) -> Result<String, ServiceError> {
    validate_policy(endpoints, router_mapping)?;
    let executable = xml_text(executable)?;
    let state_directory = xml_text(state_directory)?;
    let endpoint_arguments = if let Some(path) = endpoints {
        format!(
            "    <string>--endpoints</string>\n    <string>{}</string>\n",
            xml_text(path)?
        )
    } else {
        String::new()
    };
    let anchor_argument = if anchor { "    <string>--anchor</string>\n" } else { "" };
    let mapping_argument = if router_mapping {
        "    <string>--router-mapping</string>\n"
    } else {
        ""
    };
    let policy_arguments = format!("{anchor_argument}{mapping_argument}{endpoint_arguments}");
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>org.agenxy.supgang</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>{executable}</string>\n    <string>--json</string>\n    <string>--state-dir</string>\n    <string>{state_directory}</string>\n    <string>supervise</string>\n{policy_arguments}  </array>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>KeepAlive</key>\n  <true/>\n  <key>LimitLoadToSessionType</key>\n  <string>Aqua</string>\n  <key>ProcessType</key>\n  <string>{PROCESS_TYPE}</string>\n  <key>ThrottleInterval</key>\n  <integer>5</integer>\n  <key>StandardOutPath</key>\n  <string>/dev/null</string>\n  <key>StandardErrorPath</key>\n  <string>/dev/null</string>\n</dict>\n</plist>\n"
    ))
}

#[cfg(any(target_os = "macos", test))]
fn xml_text(path: &Path) -> Result<String, ServiceError> {
    let text = path_text(path)?;
    Ok(text
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn render_systemd(
    executable: &Path,
    state_directory: &Path,
    endpoints: Option<&Path>,
    anchor: bool,
    router_mapping: bool,
) -> Result<String, ServiceError> {
    validate_policy(endpoints, router_mapping)?;
    let executable = systemd_argument(executable)?.replace('$', "$$");
    let command_state = systemd_argument(state_directory)?.replace('$', "$$");
    let state_directory = systemd_argument(state_directory)?;
    let endpoint_arguments = if let Some(path) = endpoints {
        format!(" --endpoints {}", systemd_argument(path)?.replace('$', "$$"))
    } else {
        String::new()
    };
    let anchor_argument = if anchor { " --anchor" } else { "" };
    let mapping_argument = if router_mapping { " --router-mapping" } else { "" };
    let policy_arguments = format!("{anchor_argument}{mapping_argument}{endpoint_arguments}");
    Ok(format!(
        "[Unit]\nDescription=Supgang peer address discovery\nDocumentation=https://agenxy.org/projects/supgang/\n\n[Service]\nType=simple\nSyslogIdentifier=supgang\nExecStart={executable} --json --state-dir {command_state} supervise{policy_arguments}\nRestart=always\nRestartSec=5s\nUMask=0077\nStandardOutput=null\nStandardError=null\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths={state_directory}\nRestrictSUIDSGID=true\nLockPersonality=true\nMemoryDenyWriteExecute=true\nRestrictRealtime=true\nSystemCallArchitectures=native\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\nCapabilityBoundingSet=\nAmbientCapabilities=\n\n[Install]\nWantedBy=default.target\n"
    ))
}

#[cfg(any(target_os = "linux", test))]
fn systemd_argument(path: &Path) -> Result<String, ServiceError> {
    let text = path_text(path)?;
    Ok(format!(
        "\"{}\"",
        text.replace('%', "%%").replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn path_text(path: &Path) -> Result<&str, ServiceError> {
    let text = path.to_str().ok_or(ServiceError::UnsafeDefinition)?;
    if !path.is_absolute()
        || text
            .chars()
            .any(|value| value.is_control() || matches!(value, '\u{fffe}' | '\u{ffff}'))
    {
        return Err(ServiceError::UnsafeDefinition);
    }
    Ok(text)
}

pub(super) const fn validate_policy(endpoints: Option<&Path>, router_mapping: bool) -> Result<(), ServiceError> {
    if endpoints.is_some() && router_mapping {
        return Err(ServiceError::InvalidEndpoints);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    use super::{render_systemd, validated_endpoints};

    #[test]
    fn endpoint_file_is_validated_before_it_enters_a_service_definition() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("endpoints.json");
        crate::artifact::write_new(
            &path,
            br#"{"listen":"[::]:44330","candidates":[{"kind":"direct","address":"[2606:4700:4700::1111]:44330"}]}"#,
            4 * 1024,
        )?;
        assert_eq!(validated_endpoints(Some(&path))?, Some(path.canonicalize()?));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(validated_endpoints(Some(&path)).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o777))?;
        assert!(validated_endpoints(Some(&path)).is_err());
        Ok(())
    }

    #[test]
    fn systemd_definition_quotes_optional_endpoints_and_hardens_the_process() -> Result<(), Box<dyn std::error::Error>>
    {
        let unit = render_systemd(
            Path::new("/home/a b/sup%gang"),
            Path::new("/home/a b/state"),
            Some(Path::new("/home/a b/endpoints.json")),
            false,
            false,
        )?;
        assert!(unit.contains(
            "ExecStart=\"/home/a b/sup%%gang\" --json --state-dir \"/home/a b/state\" supervise --endpoints \"/home/a b/endpoints.json\""
        ));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("Description=Supgang peer address discovery\n"));
        assert!(unit.contains("Documentation=https://agenxy.org/projects/supgang/\n"));
        assert!(unit.contains("SyslogIdentifier=supgang\n"));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("StandardOutput=null"));
        assert!(unit.contains("CapabilityBoundingSet=\n"));
        Ok(())
    }

    #[test]
    fn systemd_expansion_is_escaped_only_in_command_arguments() -> Result<(), Box<dyn std::error::Error>> {
        let unit = render_systemd(
            Path::new("/home/${USER}/sg"),
            Path::new("/home/$STATE"),
            Some(Path::new("/home/${CFG}")),
            false,
            false,
        )?;
        assert!(unit.contains("ExecStart=\"/home/$${USER}/sg\" --json --state-dir \"/home/$$STATE\" supervise --endpoints \"/home/$${CFG}\""));
        assert!(unit.contains("ReadWritePaths=\"/home/$STATE\""));
        Ok(())
    }

    #[test]
    fn systemd_definition_can_run_the_same_binary_as_an_anchor() -> Result<(), Box<dyn std::error::Error>> {
        let unit = render_systemd(
            Path::new("/home/member/bin/supgang"),
            Path::new("/home/member/state"),
            None,
            true,
            true,
        )?;
        assert!(unit.contains("/state\" supervise --anchor --router-mapping\n"));
        assert!(!unit.contains("/state\" anchor\n"));
        Ok(())
    }

    #[test]
    fn launchd_definition_escapes_paths_and_suppresses_logs() -> Result<(), Box<dyn std::error::Error>> {
        let plist = super::render_launchd(
            Path::new("/Users/a & b/bin/supgang"),
            Path::new("/Users/a & b/state"),
            Some(Path::new("/Users/a & b/endpoints.json")),
            false,
            false,
        )?;
        assert!(plist.contains("/Users/a &amp; b/bin/supgang"));
        assert!(plist.contains("<string>--endpoints</string>"));
        assert!(plist.contains("/Users/a &amp; b/endpoints.json"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<key>LimitLoadToSessionType</key>\n  <string>Aqua</string>"));
        assert!(plist.contains("<key>ProcessType</key>\n  <string>Standard</string>"));
        assert!(!plist.contains("Background"));
        assert_eq!(plist.matches("<string>/dev/null</string>").count(), 2);
        assert!(!plist.contains("a & b"));
        Ok(())
    }

    #[test]
    fn only_the_legacy_background_class_is_upgraded() -> Result<(), Box<dyn std::error::Error>> {
        let rendered = super::render_launchd(
            Path::new("/Users/a/bin/supgang"),
            Path::new("/Users/a/state"),
            None,
            true,
            true,
        )?;
        let current = plist::Value::from_reader_xml(rendered.as_bytes())?;
        assert_eq!(super::upgraded_process_type(&current), None);

        let mut legacy = current.clone();
        let dict = legacy.as_dictionary_mut().ok_or("not a dictionary")?;
        dict.insert("ProcessType".to_owned(), plist::Value::String("Background".to_owned()));
        assert_eq!(super::upgraded_process_type(&legacy), Some(current.clone()));

        for other in ["Interactive", "Adaptive"] {
            let mut changed = current.clone();
            let dict = changed.as_dictionary_mut().ok_or("not a dictionary")?;
            dict.insert("ProcessType".to_owned(), plist::Value::String(other.to_owned()));
            assert_eq!(super::upgraded_process_type(&changed), None);
        }
        Ok(())
    }
}
