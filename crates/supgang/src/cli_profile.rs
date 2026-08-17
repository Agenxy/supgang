//! Computer-name CLI operations and rendering.

use std::{io::Write, path::Path, process::ExitCode};

use serde::Serialize;

use crate::{
    cli::{NameCommand, render_error, render_json},
    control,
    profile::{self, PeerName},
    state,
};

const EXIT_FAILURE: u8 = 3;

#[derive(Debug, Serialize)]
struct NameOutput {
    schema: &'static str,
    status: &'static str,
    name: String,
    change: &'static str,
}

pub fn name(
    state_directory: &Path,
    command: Option<NameCommand>,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let (name, change) = match command {
        None => match control::request(state_directory, control::ControlRequest::Status) {
            Ok(Some(control::ControlReply::Status { value })) => match PeerName::new(value.name) {
                Ok(name) => (name, "unchanged"),
                Err(profile_error) => return render_error(json, &profile_error.to_string(), output, error),
            },
            Ok(Some(control::ControlReply::Error { message })) => return render_error(json, &message, output, error),
            Ok(Some(_)) => return render_error(json, "local service returned an unexpected response", output, error),
            Ok(None) => {
                let local_state = match state::open(state_directory) {
                    Ok(state) => state,
                    Err(state_error) => return render_error(json, &state_error.to_string(), output, error),
                };
                let node_id = local_state.identity().device.node_id();
                match profile::load_or_create(state_directory, node_id) {
                    Ok(name) => (name, "unchanged"),
                    Err(profile_error) => return render_error(json, &profile_error.to_string(), output, error),
                }
            }
            Err(control_error) => return render_error(json, &control_error.to_string(), output, error),
        },
        Some(NameCommand::Set { name }) => {
            let name = match PeerName::new(name) {
                Ok(name) => name,
                Err(profile_error) => return render_error(json, &profile_error.to_string(), output, error),
            };
            match control::request(state_directory, control::ControlRequest::Status) {
                Ok(Some(_)) => {
                    return render_error(
                        json,
                        "stop the running Supgang service before changing its signed computer name",
                        output,
                        error,
                    );
                }
                Ok(None) => {}
                Err(control_error) => return render_error(json, &control_error.to_string(), output, error),
            }
            let local_state = match state::open(state_directory) {
                Ok(state) => state,
                Err(state_error) => return render_error(json, &state_error.to_string(), output, error),
            };
            if let Err(profile_error) = profile::set(state_directory, &name) {
                return render_error(json, &profile_error.to_string(), output, error);
            }
            drop(local_state);
            (name, "updated")
        }
    };
    let result = NameOutput {
        schema: "supgang.name/v1",
        status: "ok",
        name: name.to_string(),
        change,
    };
    if json {
        render_json(&result, output, error)
    } else if writeln!(output, "This computer: {}", result.name).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILURE)
    }
}
