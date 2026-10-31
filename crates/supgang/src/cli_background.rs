//! Plain-language and stable JSON rendering for native background service management.

use std::{io::Write, path::Path, process::ExitCode};

use serde::Serialize;

use crate::{
    cli_args::ServiceCommand,
    platform_service::{self, Action},
};

const EXIT_FAILURE: u8 = 3;

#[derive(Debug, Serialize)]
struct ServiceOutput {
    startup: &'static str,
    schema: &'static str,
    status: &'static str,
    service: &'static str,
    manager: &'static str,
    installed: bool,
    running: bool,
    data_preserved: bool,
    #[serde(flatten)]
    observation: platform_service::observation::Observation,
}

pub fn service(
    state_directory: &Path,
    command: &ServiceCommand,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let action = match command {
        ServiceCommand::Install {
            endpoints,
            anchor,
            router_mapping,
        } => Action::Install {
            endpoints: endpoints.as_deref(),
            anchor: *anchor,
            router_mapping: *router_mapping,
        },
        ServiceCommand::Refresh => Action::Refresh,
        ServiceCommand::Status => Action::Status,
        ServiceCommand::Start => Action::Start,
        ServiceCommand::Stop => Action::Stop,
        ServiceCommand::Restart => Action::Restart,
        ServiceCommand::Uninstall => Action::Uninstall,
    };
    let report = match platform_service::perform(state_directory, action) {
        Ok(report) => report,
        Err(service_error) => {
            let message = service_error.to_string();
            if json {
                let value = serde_json::json!({
                    "schema": "supgang.error/v1",
                    "status": "error",
                    "error": message,
                });
                let _written = serde_json::to_writer(&mut *output, &value);
                let _newline = writeln!(output);
                return ExitCode::from(EXIT_FAILURE);
            }
            let _written = writeln!(error, "Error: {message}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    let value = ServiceOutput {
        startup: report.startup,
        schema: "supgang.service/v1",
        status: "ok",
        service: report.state,
        manager: report.manager,
        installed: report.installed,
        running: report.running,
        data_preserved: report.data_preserved,
        observation: report.observation.clone(),
    };
    if json {
        let serialized = serde_json::to_writer(&mut *output, &value).is_ok();
        return if serialized && writeln!(output).is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(EXIT_FAILURE)
        };
    }
    let message = match command {
        ServiceCommand::Install { anchor: true, .. } => {
            "Supgang is installed as your gang's meeting point and is running in the background."
        }
        ServiceCommand::Install { anchor: false, .. } => "Supgang is installed and running in the background.",
        ServiceCommand::Refresh => {
            "Supgang's installed program was refreshed without changing its background-service settings."
        }
        ServiceCommand::Status if report.state == "disabled-by-owner" => "Supgang startup is disabled by the owner.",
        ServiceCommand::Status if report.state == "running-outside-manager" => {
            "Supgang is running, but not as this background service."
        }
        ServiceCommand::Status if report.running => {
            "Supgang is answering its control socket; manager ownership is reported below."
        }
        ServiceCommand::Status if report.state == "starting-or-unhealthy" => {
            "Supgang is registered with the manager, but control readiness could not be verified."
        }
        ServiceCommand::Status if report.installed => "Supgang is installed but is not running.",
        ServiceCommand::Status => "Supgang is not installed as a background service.",
        ServiceCommand::Start => "Supgang is running in the background.",
        ServiceCommand::Stop => "Supgang is stopped. Your identity and peer history are unchanged.",
        ServiceCommand::Restart => "Supgang restarted and is running in the background.",
        ServiceCommand::Uninstall => {
            "The background service was removed. Your identity and peer history were not deleted."
        }
    };
    let startup_note = match report.startup {
        "system-boot" => {
            "Startup: registered for system boot. Stopping or removing this registration needs the owner setup command."
        }
        "graphical-login" => {
            "Startup: when this account signs in to the desktop. Use the owner setup command for startup before login."
        }
        "manual-session-only" => {
            "Startup needs repair: this older registration does not return automatically after reboot. Run the owner setup command."
        }
        _ => "Startup depends on this account's operating-system session settings.",
    };
    let show_startup = matches!(command, ServiceCommand::Status | ServiceCommand::Install { .. });
    if writeln!(output, "{message}").is_err() {
        return ExitCode::from(EXIT_FAILURE);
    }
    if show_startup
        && (writeln!(output, "{startup_note}").is_err() || render_observation(&report.observation, output).is_err())
    {
        return ExitCode::from(EXIT_FAILURE);
    }
    ExitCode::SUCCESS
}

fn render_observation(
    observed: &platform_service::observation::Observation,
    output: &mut dyn Write,
) -> std::io::Result<()> {
    let manager_pid = observed
        .manager_pid
        .map_or_else(|| "unknown".to_owned(), |pid| pid.to_string());
    let socket_pid = observed
        .socket_pid
        .map_or_else(|| "not observed".to_owned(), |pid| pid.to_string());
    let lingering = match observed.lingering {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "unknown or not applicable",
    };
    writeln!(
        output,
        "Manager PID: {manager_pid}; socket PID: {socket_pid}; relationship: {}.\nManager enablement: {}; lingering: {lingering}.\nService identity: {}.\nDefinition: {}.\nInstalled program: {}.\nManager program: {}.\nLogs: {}.\nClient version: {}; running version: {}.",
        observed.process_relationship,
        observed.manager_enablement.as_deref().unwrap_or("unknown"),
        observed.service_identity.as_deref().unwrap_or("unknown"),
        observed.definition_path.as_deref().unwrap_or("unknown"),
        observed.installed_program.as_deref().unwrap_or("unknown"),
        observed.manager_program.as_deref().unwrap_or("unknown"),
        observed.log_destination,
        observed.client_version,
        observed
            .running_version
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown"),
    )?;
    if let Some(note) = observed.version_note {
        writeln!(output, "{note}")?;
    }
    if let Some(error) = observed.control_error {
        writeln!(output, "{error}")?;
    }
    Ok(())
}
