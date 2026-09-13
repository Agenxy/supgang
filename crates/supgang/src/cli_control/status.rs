//! Plain-language service and Internet-reachability status.

use std::{io::Write, path::Path, process::ExitCode};

use serde::Serialize;

use crate::{
    VERSION,
    cli::{render_error, render_json},
    control::{self, ControlReply, ControlRequest, ControlStatus},
    state,
};

const EXIT_FAILURE: u8 = 3;

#[derive(Debug, Serialize)]
struct StatusOutput {
    schema: &'static str,
    status: &'static str,
    version: &'static str,
    name: String,
    hive_id: String,
    node_id: String,
    service: &'static str,
    listen: Option<String>,
    active_peers: Option<usize>,
    known_peers: Option<usize>,
    router_mapping: Option<String>,
    internet_reachability: Option<String>,
    connection_recovery: Option<String>,
    mode: Option<String>,
}

pub fn status(state_directory: &Path, json: bool, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    match control::request(state_directory, ControlRequest::Status) {
        Ok(Some(ControlReply::Status { value })) => {
            return render_status(
                &value.name,
                &value.hive_id,
                &value.node_id,
                Some(&value),
                json,
                output,
                error,
            );
        }
        Ok(Some(ControlReply::Error { message })) => return render_error(json, &message, output, error),
        Ok(Some(_)) => return render_error(json, "local service returned an unexpected response", output, error),
        Ok(None) => {}
        Err(control_error) => return render_error(json, &control_error.to_string(), output, error),
    }
    match state::open(state_directory) {
        Ok(state) => {
            let node_id = state.identity().device.node_id();
            let name = match crate::profile::load_or_create(state_directory, node_id) {
                Ok(name) => name,
                Err(profile_error) => return render_error(json, &profile_error.to_string(), output, error),
            };
            render_status(
                name.as_str(),
                &state.identity().hive_id.to_string(),
                &node_id.to_string(),
                None,
                json,
                output,
                error,
            )
        }
        Err(storage_error) => render_error(json, &storage_error.to_string(), output, error),
    }
}

fn render_status(
    name: &str,
    hive_id: &str,
    node_id: &str,
    runtime: Option<&ControlStatus>,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let result = StatusOutput {
        schema: "supgang.status/v4",
        status: "ok",
        version: VERSION,
        name: name.to_owned(),
        hive_id: hive_id.to_owned(),
        node_id: node_id.to_owned(),
        service: if runtime.is_some() { "running" } else { "stopped" },
        listen: runtime.map(|value| value.listen.clone()),
        active_peers: runtime.map(|value| value.active_peers),
        known_peers: runtime.map(|value| value.known_peers),
        router_mapping: runtime.map(|value| value.router_mapping.clone()),
        internet_reachability: runtime.map(|value| value.internet_reachability.clone()),
        connection_recovery: runtime.map(|value| value.connection_recovery.clone()),
        mode: runtime.map(|value| value.mode.clone()),
    };
    if json {
        render_json(&result, output, error)
    } else {
        render_status_human(&result, output)
    }
}

fn render_status_human(result: &StatusOutput, output: &mut dyn Write) -> ExitCode {
    let header = writeln!(
        output,
        "Hive: {}\nThis computer: {} [{}]\nService: {}",
        result.hive_id,
        result.name,
        result.node_id.chars().take(8).collect::<String>(),
        result.service
    );
    let runtime = result
        .listen
        .as_ref()
        .zip(result.active_peers)
        .zip(result.known_peers)
        .zip(result.router_mapping.as_deref())
        .zip(result.internet_reachability.as_deref())
        .zip(result.connection_recovery.as_deref())
        .zip(result.mode.as_deref());
    if header.is_err()
        || runtime.is_some_and(|((((((listen, active), known), mapping), reachability), recovery), mode)| {
            writeln!(
                output,
                "Role: {}\nListening: {listen}\nPeers connected now: {active} of {known}\nRouter mapping: {}\nInternet reachability: {}\nConnection recovery: {}",
                human_mode(mode),
                human_router_mapping(mapping),
                human_reachability(reachability),
                human_connection_recovery(recovery)
            )
            .is_err()
        })
    {
        ExitCode::from(EXIT_FAILURE)
    } else {
        ExitCode::SUCCESS
    }
}

fn human_mode(mode: &str) -> &str {
    match mode {
        "anchor" => "user-owned gang meeting point",
        "device" => "computer",
        _ => "unknown",
    }
}

fn human_connection_recovery(recovery: &str) -> &str {
    match recovery {
        "automatic-multi-path" => "automatic direct attempts, synchronized retries, and help from connected peers",
        "remembered-addresses-only" => "remembered addresses only; restart the service to enable newer methods",
        _ => "unknown",
    }
}

fn human_router_mapping(mapping: &str) -> &str {
    match mapping {
        "checking" => "checking the local gateway",
        "mapped-unverified" => "active; the gateway reported an address that is not yet verified",
        "unavailable" => "not available on this network",
        "disabled" => "not enabled for this service",
        _ => "unknown",
    }
}

fn human_reachability(reachability: &str) -> &str {
    match reachability {
        "gateway-reported-address" => "the gateway reported a public address; Supgang has not proved it works",
        "direct-address-unverified" => "a public interface is configured; no peer has confirmed it",
        "peer-reported-address" => "another authenticated computer reported this address; return traffic is unproved",
        "device-claimed-address" => "this computer claims a public address; independent reachability is unproved",
        "local-only" => "local network only; no usable Internet path",
        _ => "unknown",
    }
}
