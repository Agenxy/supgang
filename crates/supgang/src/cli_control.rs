//! CLI routing and rendering through the running service's private socket.

use std::str::FromStr;
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
    name: String,
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
        Ok(Some(_)) => return unexpected(json, output, error),
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

pub fn peers(state_directory: &Path, json: bool, all: bool, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    match control::request(state_directory, ControlRequest::Peers) {
        Ok(Some(ControlReply::Peers { value })) => render_peers(&value, json, all, output, error),
        Ok(Some(ControlReply::Error { message })) => render_error(json, &message, output, error),
        Ok(Some(_)) => unexpected(json, output, error),
        Ok(None) => match cli_peer::peers(state_directory) {
            Ok(result) => render_peers(&result, json, all, output, error),
            Err(message) => render_error(json, &message, output, error),
        },
        Err(control_error) => render_error(json, &control_error.to_string(), output, error),
    }
}

pub fn resolve(
    state_directory: &Path,
    selector: &str,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    if let Ok(node_id) = NodeId::from_str(selector) {
        return resolve_node(state_directory, node_id, json, output, error);
    }
    match control::request(state_directory, ControlRequest::Peers) {
        Ok(Some(ControlReply::Peers { value })) => match cli_peer::resolve_selector_from_rows(&value.peers, selector) {
            Ok(node_id) => resolve_node(state_directory, node_id, json, output, error),
            Err(message) => render_error(json, &message, output, error),
        },
        Ok(Some(ControlReply::Error { message })) => render_error(json, &message, output, error),
        Ok(Some(_)) => unexpected(json, output, error),
        Ok(None) => match cli_peer::resolve(state_directory, selector) {
            Ok(result) => render_resolve(&result, json, output, error),
            Err(message) => render_error(json, &message, output, error),
        },
        Err(control_error) => render_error(json, &control_error.to_string(), output, error),
    }
}

fn resolve_node(
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
        Ok(None) => match cli_peer::resolve(state_directory, &node_id.to_string()) {
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
    name: &str,
    hive_id: &str,
    node_id: &str,
    runtime: Option<&ControlStatus>,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let result = StatusOutput {
        schema: "supgang.status/v2",
        status: "ok",
        version: VERSION,
        name: name.to_owned(),
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
        "Hive: {}\nThis computer: {} [{}]\nService: {}",
        result.hive_id,
        result.name,
        result.node_id.chars().take(8).collect::<String>(),
        result.service
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

fn render_peers(
    result: &cli_peer::PeersOutput,
    json: bool,
    all: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    if json {
        return render_json(result, output, error);
    }
    let mut hidden = 0_usize;
    if let Some(this_computer) = &result.this_computer
        && render_computer(this_computer, true, all, output, &mut hidden).is_err()
    {
        return ExitCode::from(EXIT_FAILURE);
    }
    for peer in &result.peers {
        if render_computer(peer, false, all, output, &mut hidden).is_err() {
            return ExitCode::from(EXIT_FAILURE);
        }
    }
    if result.peers.is_empty() && writeln!(output, "No other computers are known.").is_err() {
        return ExitCode::from(EXIT_FAILURE);
    }
    if !all && hidden > 0 && writeln!(output, "More addresses: supgang peers --all").is_err() {
        return ExitCode::from(EXIT_FAILURE);
    }
    ExitCode::SUCCESS
}

fn render_computer(
    computer: &cli_peer::PeerRow,
    is_local: bool,
    all: bool,
    output: &mut dyn Write,
    hidden: &mut usize,
) -> std::io::Result<()> {
    let label = if is_local { "this computer" } else { &computer.status };
    writeln!(output, "{} [{}]  {}", computer.name, computer.fingerprint, label)?;
    if all {
        return render_all_addresses(computer, output);
    }
    let shown = compact_addresses(&computer.addresses);
    if shown.is_empty() {
        writeln!(output, "  no current address")?;
    } else {
        for candidate in &shown {
            writeln!(
                output,
                "  {:<6} {}{}",
                candidate.scope,
                candidate.address,
                if candidate.preferred { "  preferred" } else { "" }
            )?;
        }
    }
    *hidden = hidden.saturating_add(computer.addresses.len().saturating_sub(shown.len()));
    writeln!(output)
}

fn render_all_addresses(computer: &cli_peer::PeerRow, output: &mut dyn Write) -> std::io::Result<()> {
    if computer.addresses.is_empty() {
        writeln!(output, "  no signed addresses")?;
    }
    for candidate in &computer.addresses {
        writeln!(
            output,
            "  {:<6} {:<52} {:<11} {}{}",
            candidate.scope,
            candidate.address,
            human_candidate_kind(&candidate.kind),
            candidate.provenance,
            if candidate.preferred { "  preferred" } else { "" }
        )?;
    }
    writeln!(output)
}

fn compact_addresses(addresses: &[cli_peer::ResolvedCandidate]) -> Vec<&cli_peer::ResolvedCandidate> {
    let Some(preferred) = addresses.iter().find(|candidate| candidate.preferred) else {
        return Vec::new();
    };
    let mut selected = vec![preferred];
    if preferred.scope == "local" {
        let public = addresses
            .iter()
            .filter(|candidate| candidate.scope == "public")
            .min_by_key(|candidate| !address_is_ipv4(&candidate.address));
        if let Some(public) = public {
            selected.push(public);
        }
    }
    selected
}

fn address_is_ipv4(address: &str) -> bool {
    address
        .parse::<std::net::SocketAddr>()
        .is_ok_and(|value| value.is_ipv4())
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
        "{} [{}]: generation {}, sequence {}, expires {}",
        result.name, result.fingerprint, result.generation, result.sequence, result.expires_at
    )
    .is_err()
    {
        return ExitCode::from(EXIT_FAILURE);
    }
    for candidate in &result.candidates {
        if writeln!(
            output,
            "{} {} {} {}{}",
            candidate.scope,
            human_candidate_kind(&candidate.kind),
            candidate.transport,
            candidate.address,
            if candidate.preferred { " preferred" } else { "" }
        )
        .is_err()
        {
            return ExitCode::from(EXIT_FAILURE);
        }
    }
    ExitCode::SUCCESS
}

fn human_candidate_kind(kind: &str) -> &str {
    match kind {
        "local" => "interface",
        "reflexive" => "peer-seen",
        "mapped" => "router-map",
        value => value,
    }
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

#[cfg(test)]
mod tests {
    use super::compact_addresses;
    use crate::cli_peer::ResolvedCandidate;

    fn candidate(scope: &str, address: &str, preferred: bool) -> ResolvedCandidate {
        ResolvedCandidate {
            scope: scope.to_owned(),
            kind: if scope == "local" { "local" } else { "direct" }.to_owned(),
            transport: "quic-v1".to_owned(),
            address: address.to_owned(),
            provenance: "device-signed".to_owned(),
            preferred,
        }
    }

    #[test]
    fn compact_view_keeps_one_preferred_and_one_ipv4_public_alternative() {
        let addresses = [
            candidate("local", "192.168.1.20:44330", true),
            candidate("local", "192.168.64.1:44330", false),
            candidate("public", "[2600:1700::1]:44330", false),
            candidate("public", "8.8.8.8:44330", false),
        ];
        let selected = compact_addresses(&addresses);
        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected.first().map(|candidate| candidate.address.as_str()),
            Some("192.168.1.20:44330")
        );
        assert_eq!(
            selected.get(1).map(|candidate| candidate.address.as_str()),
            Some("8.8.8.8:44330")
        );
    }

    #[test]
    fn compact_view_does_not_recommend_historical_addresses() {
        let addresses = [candidate("local", "192.168.1.20:44330", false)];
        assert!(compact_addresses(&addresses).is_empty());
    }
}
