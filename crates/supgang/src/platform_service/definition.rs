//! Safe native service-definition rendering and endpoint-file validation.

use std::path::{Path, PathBuf};

use crate::{endpoint_config::EndpointConfig, storage};

use super::ServiceError;

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

#[cfg(target_os = "macos")]
pub(super) fn render_launchd(
    executable: &Path,
    state_directory: &Path,
    endpoints: Option<&Path>,
    anchor: bool,
    router_mapping: bool,
) -> Result<String, ServiceError> {
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
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>org.agenxy.supgang</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>{executable}</string>\n    <string>--json</string>\n    <string>--state-dir</string>\n    <string>{state_directory}</string>\n    <string>supervise</string>\n{policy_arguments}  </array>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>KeepAlive</key>\n  <true/>\n  <key>LimitLoadToSessionType</key>\n  <string>Aqua</string>\n  <key>ProcessType</key>\n  <string>Background</string>\n  <key>ThrottleInterval</key>\n  <integer>5</integer>\n  <key>StandardOutPath</key>\n  <string>/dev/null</string>\n  <key>StandardErrorPath</key>\n  <string>/dev/null</string>\n</dict>\n</plist>\n"
    ))
}

#[cfg(target_os = "macos")]
fn xml_text(path: &Path) -> Result<String, ServiceError> {
    let text = path.to_str().ok_or(ServiceError::UnsafeDefinition)?;
    if text.chars().any(char::is_control) {
        return Err(ServiceError::UnsafeDefinition);
    }
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
    let executable = systemd_argument(executable)?;
    let state_directory = systemd_argument(state_directory)?;
    let endpoint_arguments = if let Some(path) = endpoints {
        format!(" --endpoints {}", systemd_argument(path)?)
    } else {
        String::new()
    };
    let anchor_argument = if anchor { " --anchor" } else { "" };
    let mapping_argument = if router_mapping { " --router-mapping" } else { "" };
    let policy_arguments = format!("{anchor_argument}{mapping_argument}{endpoint_arguments}");
    Ok(format!(
        "[Unit]\nDescription=Supgang sovereign peer discovery\n\n[Service]\nType=simple\nExecStart={executable} --json --state-dir {state_directory} supervise{policy_arguments}\nRestart=always\nRestartSec=5s\nUMask=0077\nStandardOutput=null\nStandardError=null\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths={state_directory}\nRestrictSUIDSGID=true\nLockPersonality=true\nMemoryDenyWriteExecute=true\nRestrictRealtime=true\nSystemCallArchitectures=native\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\nCapabilityBoundingSet=\nAmbientCapabilities=\n\n[Install]\nWantedBy=default.target\n"
    ))
}

#[cfg(any(target_os = "linux", test))]
fn systemd_argument(path: &Path) -> Result<String, ServiceError> {
    let text = path.to_str().ok_or(ServiceError::UnsafeDefinition)?;
    if text.chars().any(char::is_control) {
        return Err(ServiceError::UnsafeDefinition);
    }
    Ok(format!(
        "\"{}\"",
        text.replace('%', "%%").replace('\\', "\\\\").replace('"', "\\\"")
    ))
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
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("StandardOutput=null"));
        assert!(unit.contains("CapabilityBoundingSet=\n"));
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

    #[cfg(target_os = "macos")]
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
        assert_eq!(plist.matches("<string>/dev/null</string>").count(), 2);
        assert!(!plist.contains("a & b"));
        Ok(())
    }
}
