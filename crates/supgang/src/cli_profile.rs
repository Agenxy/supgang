//! Computer-name CLI operations and rendering.

use std::{io::Write, path::Path, process::ExitCode};

use serde::Serialize;

use crate::{
    cli::{NameCommand, render_error, render_json},
    cli_peer::ServiceRow,
    control,
    profile::{self, PeerName},
    record::{ServiceAdvert, ServiceName},
    state,
};

const EXIT_FAILURE: u8 = 3;

/// A change to the services this computer advertises.
#[derive(Debug)]
pub enum Advertise {
    /// Add or replace one advertisement.
    Add {
        /// The service's own name.
        name: String,
        /// The port it listens on.
        port: u16,
        /// SHA-256 of its TLS public key, as hex.
        key_pin: String,
    },
    /// Remove one advertisement by name.
    Remove {
        /// The service's own name.
        name: String,
    },
}

#[derive(Debug, Serialize)]
struct ServicesOutput {
    schema: &'static str,
    status: &'static str,
    services: Vec<ServiceRow>,
    change: &'static str,
}

/// Adds or removes a service advertisement in the owner-only profile.
///
/// Like `name set`, this refuses while the service is running: the running
/// service signed its record from the profile it read at start, and a
/// profile that says one thing while the fleet is told another is the
/// drift both verbs exist to prevent.
pub fn advertise(
    state_directory: &Path,
    change: Advertise,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    match control::request(state_directory, control::ControlRequest::Status) {
        Ok(Some(_)) => {
            return render_error(
                json,
                "stop the running Supgang service before changing the services it advertises",
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
    let node_id = local_state.identity().device.node_id();
    let (services, changed) = match change {
        Advertise::Add { name, port, key_pin } => {
            let advert = match ServiceAdvert::new(name, port, &key_pin) {
                Ok(advert) => advert,
                Err(record_error) => return render_error(json, &record_error.to_string(), output, error),
            };
            (profile::advertise(state_directory, node_id, advert), "advertised")
        }
        Advertise::Remove { name } => {
            let name = match ServiceName::new(name) {
                Ok(name) => name,
                Err(record_error) => return render_error(json, &record_error.to_string(), output, error),
            };
            (profile::unadvertise(state_directory, node_id, &name), "unadvertised")
        }
    };
    drop(local_state);
    let services = match services {
        Ok(services) => services,
        Err(profile_error) => return render_error(json, &profile_error.to_string(), output, error),
    };
    let result = ServicesOutput {
        schema: "supgang.services/v1",
        status: "ok",
        services: services.iter().map(Into::into).collect(),
        change: changed,
    };
    if json {
        return render_json(&result, output, error);
    }
    let written = if result.services.is_empty() {
        writeln!(output, "This computer advertises no services.")
    } else {
        result.services.iter().try_for_each(|service| {
            writeln!(
                output,
                "{:<16} port {:<5} key {}",
                service.name, service.port, service.key_pin
            )
        })
    };
    let restart = writeln!(
        output,
        "Start the service to sign the change into this computer's record. A record that advertises \
         is version 3: members running a Supgang older than this cannot read it, addresses included."
    );
    if written.is_ok() && restart.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILURE)
    }
}

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
