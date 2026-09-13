//! Plain-language and stable JSON rendering for secure software updates.

use std::{io::Write, path::Path, process::ExitCode};

use serde::Serialize;

use crate::{
    cli_args::UpdateCommand,
    cli_control,
    control::{self, ControlReply, ControlRequest},
    platform_service::{self, Action},
    transport, update,
};

const EXIT_FAILURE: u8 = 3;

#[derive(Debug, Serialize)]
struct UpdateOutput {
    schema: &'static str,
    status: &'static str,
    operation: &'static str,
    version: Option<String>,
    digest: Option<String>,
    trusted: Option<bool>,
    active_version: Option<String>,
    staged_version: Option<String>,
    activation_pending: Option<bool>,
    queued_peer_deliveries: Option<usize>,
    peer: Option<String>,
}

pub fn update(
    state_directory: &Path,
    command: &UpdateCommand,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let result = execute(state_directory, command);
    let value = match result {
        Ok(value) => value,
        Err(message) => return render_error(json, &message, output, error),
    };
    if json {
        return if serde_json::to_writer(&mut *output, &value).is_ok() && writeln!(output).is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(EXIT_FAILURE)
        };
    }
    let message = match value.operation {
        "trust" => "This computer now trusts that signed Supgang release authority.",
        "bundle" => "Signed update bundle created. Its contents will still be verified by every receiver.",
        "stage" => "The signed release is verified and staged. Run `supgang update apply` to activate it.",
        "send" => {
            "Update queued for that peer. Supgang will retry across reconnects for 24 hours; the receiver must still verify and activate it."
        }
        "apply" => "The verified release was handed to the A/B supervisor for a health-checked restart.",
        "status" if value.activation_pending == Some(true) => "A verified Supgang update is awaiting activation.",
        "status" if value.staged_version.is_some() => "A verified Supgang update is staged but not active.",
        "status" if value.queued_peer_deliveries.is_some_and(|count| count > 0) => {
            "One or more peer updates are queued and will retry when those peers reconnect."
        }
        "status" if value.trusted == Some(true) => "Signed Supgang updates are ready; none is staged.",
        "status" => "No Supgang update authority is pinned on this computer.",
        _ => return ExitCode::from(EXIT_FAILURE),
    };
    if writeln!(output, "{message}").is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILURE)
    }
}

fn execute(state_directory: &Path, command: &UpdateCommand) -> Result<UpdateOutput, String> {
    match command {
        UpdateCommand::Trust { root } => {
            update::trust_root(state_directory, root).map_err(|error| error.to_string())?;
            Ok(simple("trust"))
        }
        UpdateCommand::Bundle {
            metadata,
            targets,
            target,
            output,
        } => {
            let digest =
                update::pack_repository(metadata, targets, target, output).map_err(|error| error.to_string())?;
            Ok(UpdateOutput {
                digest: Some(digest),
                ..simple("bundle")
            })
        }
        UpdateCommand::Stage { bundle } => {
            let runtime = transport::build_runtime().map_err(|error| error.to_string())?;
            let staged = runtime
                .block_on(update::verify_and_stage(state_directory, bundle))
                .map_err(|error| error.to_string())?;
            Ok(UpdateOutput {
                version: Some(staged.version),
                digest: Some(staged.digest),
                ..simple("stage")
            })
        }
        UpdateCommand::Send { peer, bundle } => {
            let target = cli_control::resolve_peer_node(state_directory, peer)?;
            let digest = update::prepare_outbound(state_directory, bundle).map_err(|error| error.to_string())?;
            match control::request(state_directory, ControlRequest::Update { target, digest }) {
                Ok(Some(ControlReply::UpdateQueued { node_id, digest })) => Ok(UpdateOutput {
                    status: "queued",
                    operation: "send",
                    peer: Some(node_id),
                    digest: Some(digest),
                    ..simple("send")
                }),
                Ok(Some(ControlReply::Error { message })) => Err(message),
                Ok(Some(_)) => Err("local service returned an unexpected response".to_owned()),
                Ok(None) => Err("Supgang must be running before it can deliver an update to a peer".to_owned()),
                Err(error) => Err(error.to_string()),
            }
        }
        UpdateCommand::Apply => {
            platform_service::preflight_restart(state_directory).map_err(|error| error.to_string())?;
            let staged = update::activate_staged(state_directory).map_err(|error| error.to_string())?;
            if let Err(error) = platform_service::perform(state_directory, Action::Restart) {
                update::cancel_activation(state_directory).map_err(|cancel_error| {
                    format!("{error}; Supgang also could not disarm the pending update: {cancel_error}")
                })?;
                return Err(error.to_string());
            }
            Ok(UpdateOutput {
                version: Some(staged.version),
                digest: Some(staged.digest),
                activation_pending: Some(true),
                ..simple("apply")
            })
        }
        UpdateCommand::Status => {
            let status = update::status(state_directory).map_err(|error| error.to_string())?;
            Ok(UpdateOutput {
                trusted: Some(status.trusted),
                active_version: Some(status.active_version),
                staged_version: status.staged_version,
                activation_pending: Some(status.activation_pending),
                queued_peer_deliveries: Some(status.queued_peer_deliveries),
                ..simple("status")
            })
        }
    }
}

const fn simple(operation: &'static str) -> UpdateOutput {
    UpdateOutput {
        schema: "supgang.update/v1",
        status: "ok",
        operation,
        version: None,
        digest: None,
        trusted: None,
        active_version: None,
        staged_version: None,
        activation_pending: None,
        queued_peer_deliveries: None,
        peer: None,
    }
}

fn render_error(json: bool, message: &str, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    if json {
        let value = serde_json::json!({
            "schema": "supgang.error/v1",
            "status": "error",
            "error": message,
        });
        let _written = serde_json::to_writer(&mut *output, &value);
        let _newline = writeln!(output);
    } else {
        let _written = writeln!(error, "Error: {message}");
    }
    ExitCode::from(EXIT_FAILURE)
}
