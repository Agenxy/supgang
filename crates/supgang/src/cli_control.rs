//! CLI routing and rendering through the running service's private socket.

use std::{io::Write, path::Path, process::ExitCode, time::SystemTime};

use serde::Serialize;

use crate::{
    VERSION,
    cli::{render_error, render_json},
    cli_peer,
    control::{self, ControlReply, ControlRequest, ControlStatus},
    ids::NodeId,
    state,
};

const EXIT_FAILURE: u8 = 3;

#[derive(Debug, Serialize)]
struct StatusOutput {
    schema: &'static str,
    status: &'static str,
    version: &'static str,
    hive_id: String,
    node_id: String,
    service: &'static str,
    listen: Option<String>,
    active_peers: Option<usize>,
    known_peers: Option<usize>,
}

#[derive(Debug, Serialize)]
struct RevokeOutput {
    schema: &'static str,
    status: &'static str,
    node_id: String,
    revocation_serial: u64,
    changed: bool,
}

pub fn status(state_directory: &Path, json: bool, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    match control::request(state_directory, ControlRequest::Status) {
        Ok(Some(ControlReply::Status { value })) => {
            return render_status(&value.hive_id, &value.node_id, Some(&value), json, output, error);
        }
        Ok(Some(ControlReply::Error { message })) => return render_error(json, &message, output, error),
        Ok(Some(_)) => return unexpected(json, output, error),
        Ok(None) => {}
        Err(control_error) => return render_error(json, &control_error.to_string(), output, error),
    }
    match state::open(state_directory) {
        Ok(state) => render_status(
            &state.identity().hive_id.to_string(),
            &state.identity().device.node_id().to_string(),
            None,
            json,
            output,
            error,
        ),
        Err(storage_error) => render_error(json, &storage_error.to_string(), output, error),
    }
}

pub fn peers(state_directory: &Path, json: bool, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    match control::request(state_directory, ControlRequest::Peers) {
        Ok(Some(ControlReply::Peers { value })) => render_peers(&value, json, output, error),
        Ok(Some(ControlReply::Error { message })) => render_error(json, &message, output, error),
        Ok(Some(_)) => unexpected(json, output, error),
        Ok(None) => match cli_peer::peers(state_directory) {
            Ok(result) => render_peers(&result, json, output, error),
            Err(message) => render_error(json, &message, output, error),
        },
        Err(control_error) => render_error(json, &control_error.to_string(), output, error),
    }
}

pub fn resolve(
    state_directory: &Path,
    node_id: NodeId,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    match control::request(state_directory, ControlRequest::Resolve(node_id)) {
        Ok(Some(ControlReply::Resolve { value })) => render_resolve(&value, json, output, error),
        Ok(Some(ControlReply::Error { message })) => render_error(json, &message, output, error),
        Ok(Some(_)) => unexpected(json, output, error),
        Ok(None) => match cli_peer::resolve(state_directory, node_id) {
            Ok(result) => render_resolve(&result, json, output, error),
            Err(message) => render_error(json, &message, output, error),
        },
        Err(control_error) => render_error(json, &control_error.to_string(), output, error),
    }
}

pub fn revoke(
    state_directory: &Path,
    node_id: NodeId,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    match control::request(state_directory, ControlRequest::Revoke(node_id)) {
        Ok(Some(ControlReply::Revoked {
            node_id,
            serial,
            changed,
        })) => render_revoke(&node_id, serial, changed, json, output, error),
        Ok(Some(ControlReply::Error { message })) => render_error(json, &message, output, error),
        Ok(Some(_)) => unexpected(json, output, error),
        Ok(None) => {
            let mut local_state = match state::open(state_directory) {
                Ok(state) => state,
                Err(state_error) => return render_error(json, &state_error.to_string(), output, error),
            };
            let before = local_state.revocations().list.serial;
            let now = match unix_time() {
                Ok(now) => now,
                Err(message) => return render_error(json, message, output, error),
            };
            match local_state.revoke(node_id, now) {
                Ok(revocations) => render_revoke(
                    &node_id.to_string(),
                    revocations.list.serial,
                    revocations.list.serial > before,
                    json,
                    output,
                    error,
                ),
                Err(state_error) => render_error(json, &state_error.to_string(), output, error),
            }
        }
        Err(control_error) => render_error(json, &control_error.to_string(), output, error),
    }
}

fn render_status(
    hive_id: &str,
    node_id: &str,
    runtime: Option<&ControlStatus>,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let result = StatusOutput {
        schema: "supgang.status/v1",
        status: "ok",
        version: VERSION,
        hive_id: hive_id.to_owned(),
        node_id: node_id.to_owned(),
        service: if runtime.is_some() { "running" } else { "stopped" },
        listen: runtime.map(|value| value.listen.clone()),
        active_peers: runtime.map(|value| value.active_peers),
        known_peers: runtime.map(|value| value.known_peers),
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
        "Hive: {}\nThis computer: {}\nService: {}",
        result.hive_id, result.node_id, result.service
    );
    let runtime = result.listen.as_ref().zip(result.active_peers).zip(result.known_peers);
    if header.is_err()
        || runtime.is_some_and(|((listen, active), known)| {
            writeln!(output, "Listening: {listen}\nPeers: {active} active, {known} known").is_err()
        })
    {
        ExitCode::from(EXIT_FAILURE)
    } else {
        ExitCode::SUCCESS
    }
}

fn render_peers(result: &cli_peer::PeersOutput, json: bool, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    if json {
        return render_json(result, output, error);
    }
    if result.peers.is_empty() {
        return if writeln!(output, "No peer contacts are known.").is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(EXIT_FAILURE)
        };
    }
    for peer in &result.peers {
        if writeln!(
            output,
            "{}  {}  generation {} sequence {}  {} candidate(s)",
            peer.node_id, peer.status, peer.generation, peer.sequence, peer.candidate_count
        )
        .is_err()
        {
            return ExitCode::from(EXIT_FAILURE);
        }
    }
    ExitCode::SUCCESS
}

fn render_resolve(
    result: &cli_peer::ResolveOutput,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    if json {
        return render_json(result, output, error);
    }
    if writeln!(
        output,
        "Peer {}: generation {}, sequence {}, expires {}",
        result.node_id, result.generation, result.sequence, result.expires_at
    )
    .is_err()
    {
        return ExitCode::from(EXIT_FAILURE);
    }
    for candidate in &result.candidates {
        if writeln!(
            output,
            "{} {} {}",
            candidate.kind, candidate.transport, candidate.address
        )
        .is_err()
        {
            return ExitCode::from(EXIT_FAILURE);
        }
    }
    ExitCode::SUCCESS
}

fn unexpected(json: bool, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    render_error(json, "local service returned an unexpected response", output, error)
}

fn render_revoke(
    node_id: &str,
    serial: u64,
    changed: bool,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let result = RevokeOutput {
        schema: "supgang.revoke/v1",
        status: "ok",
        node_id: node_id.to_owned(),
        revocation_serial: serial,
        changed,
    };
    if json {
        render_json(&result, output, error)
    } else if writeln!(
        output,
        "Device {} is revoked at root serial {}{}.",
        result.node_id,
        result.revocation_serial,
        if changed { "" } else { " (already committed)" }
    )
    .is_ok()
    {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILURE)
    }
}

fn unix_time() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the UNIX epoch")
}
