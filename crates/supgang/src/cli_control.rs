//! CLI routing and rendering through the running service's private socket.

use std::str::FromStr;
use std::{io::Write, path::Path, process::ExitCode, time::SystemTime};

use serde::Serialize;

use crate::{
    cli::{render_error, render_json},
    cli_peer,
    control::{self, ControlReply, ControlRequest},
    ids::NodeId,
    peer_tag::{self, PeerTag},
    state,
};

mod status;

pub use status::status;

const EXIT_FAILURE: u8 = 3;

#[derive(Debug, Serialize)]
struct RevokeOutput {
    schema: &'static str,
    status: &'static str,
    node_id: String,
    revocation_serial: u64,
    changed: bool,
}

#[derive(Debug, Serialize)]
struct PeerSearchOutput<'a> {
    schema: &'static str,
    status: &'static str,
    query: &'a str,
    matches: Vec<PeerMatchOutput<'a>>,
}

#[derive(Debug, Serialize)]
struct PeerMatchOutput<'a> {
    score: u8,
    matched_by: &'static str,
    exact: bool,
    peer: &'a cli_peer::PeerRow,
}

#[derive(Debug, Serialize)]
struct PeerTagOutput {
    schema: &'static str,
    status: &'static str,
    action: &'static str,
    node_id: String,
    fingerprint: String,
    name: Option<String>,
    tag: String,
    tags: Vec<String>,
    changed: bool,
}

pub fn peers(state_directory: &Path, json: bool, all: bool, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    match peers_snapshot(state_directory) {
        Ok(result) => render_peers(&result, json, all, output, error),
        Err(message) => render_error(json, &message, output, error),
    }
}

/// Shows one peer selected by its stable or human-readable identity.
pub fn peer(
    state_directory: &Path,
    selector: &str,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let result = match peers_snapshot(state_directory) {
        Ok(result) => result,
        Err(message) => return render_error(json, &message, output, error),
    };
    let matches = match cli_peer::selector_matches_from_rows(&result.peers, selector) {
        Ok(matches) if !matches.is_empty() => matches,
        Ok(_) => {
            return render_error(
                json,
                "no known peer significantly matches that name, tag, or fingerprint",
                output,
                error,
            );
        }
        Err(message) => return render_error(json, &message, output, error),
    };
    let rows = matches
        .iter()
        .filter_map(|matched| {
            result
                .peers
                .iter()
                .find(|row| row.node_id == matched.node_id.to_string())
                .map(|peer| PeerMatchOutput {
                    score: matched.score,
                    matched_by: matched.matched_by,
                    exact: matched.exact,
                    peer,
                })
        })
        .collect::<Vec<_>>();
    if rows.len() != matches.len() {
        return render_error(
            json,
            "selected peer disappeared from the local snapshot; retry",
            output,
            error,
        );
    }
    if json {
        render_json(
            &PeerSearchOutput {
                schema: "supgang.peer-search/v2",
                status: "ok",
                query: selector,
                matches: rows,
            },
            output,
            error,
        )
    } else {
        render_peer_matches_human(selector, &rows, output)
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
    match peers_snapshot(state_directory).and_then(|value| cli_peer::resolve_selector_from_rows(&value.peers, selector))
    {
        Ok(node_id) => resolve_node(state_directory, node_id, json, output, error),
        Err(message) => render_error(json, &message, output, error),
    }
}

/// Adds one local peer nickname after resolving its cryptographic identity.
pub fn tag(
    state_directory: &Path,
    selector: &str,
    tag: PeerTag,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let peers = match peers_snapshot(state_directory) {
        Ok(peers) => peers,
        Err(message) => return render_error(json, &message, output, error),
    };
    let node_id = match cli_peer::resolve_selector_from_rows(&peers.peers, selector) {
        Ok(node_id) => node_id,
        Err(message) => return render_error(json, &message, output, error),
    };
    let Some(peer) = peers.peers.iter().find(|peer| peer.node_id == node_id.to_string()) else {
        return render_error(
            json,
            "selected peer disappeared from the local snapshot; retry",
            output,
            error,
        );
    };
    if peer.name.eq_ignore_ascii_case(tag.as_str()) {
        return render_error(
            json,
            "that tag is already the computer's signed name; choose a different nickname",
            output,
            error,
        );
    }
    match peer_tag::add(state_directory, node_id, tag) {
        Ok(mutation) => render_peer_tag(&mutation, Some(&peer.name), "added", json, output, error),
        Err(tag_error) => render_error(json, &tag_error.to_string(), output, error),
    }
}

/// Removes one exact local peer nickname without changing signed peer state.
pub fn untag(
    state_directory: &Path,
    tag: PeerTag,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    match peer_tag::remove(state_directory, tag) {
        Ok(mutation) => render_peer_tag(&mutation, None, "removed", json, output, error),
        Err(tag_error) => render_error(json, &tag_error.to_string(), output, error),
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
        Ok(Some(ControlReply::Resolve { mut value })) => {
            if let Err(message) = cli_peer::apply_tags_to_resolve(state_directory, &mut value) {
                render_error(json, &message, output, error)
            } else {
                render_resolve(&value, json, output, error)
            }
        }
        Ok(Some(ControlReply::Error { message })) => render_error(json, &message, output, error),
        Ok(Some(_)) => unexpected(json, output, error),
        Ok(None) => match cli_peer::resolve(state_directory, &node_id.to_string()) {
            Ok(result) => render_resolve(&result, json, output, error),
            Err(message) => render_error(json, &message, output, error),
        },
        Err(control_error) => render_error(json, &control_error.to_string(), output, error),
    }
}

fn peers_snapshot(state_directory: &Path) -> Result<cli_peer::PeersOutput, String> {
    let mut result = match control::request(state_directory, ControlRequest::Peers) {
        Ok(Some(ControlReply::Peers { value })) => value,
        Ok(Some(ControlReply::Error { message })) => return Err(message),
        Ok(Some(_)) => return Err("local service returned an unexpected response".to_owned()),
        Ok(None) => cli_peer::peers(state_directory)?,
        Err(control_error) => return Err(control_error.to_string()),
    };
    cli_peer::apply_tags(state_directory, &mut result)?;
    Ok(result)
}

pub fn resolve_peer_node(state_directory: &Path, selector: &str) -> Result<NodeId, String> {
    let peers = peers_snapshot(state_directory)?;
    cli_peer::resolve_selector_from_rows(&peers.peers, selector)
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

fn render_peer_matches_human(selector: &str, matches: &[PeerMatchOutput<'_>], output: &mut dyn Write) -> ExitCode {
    if matches.len() > 1 && writeln!(output, "{} matches for {selector}:\n", matches.len()).is_err() {
        return ExitCode::from(EXIT_FAILURE);
    }
    let mut hidden = 0;
    for matched in matches {
        if render_computer(matched.peer, false, false, output, &mut hidden).is_err() {
            return ExitCode::from(EXIT_FAILURE);
        }
    }
    if matches.len() == 1 && hidden > 0 {
        let Some(single) = matches.first() else {
            return ExitCode::from(EXIT_FAILURE);
        };
        if writeln!(output, "More addresses: supgang resolve {}", single.peer.fingerprint).is_err() {
            return ExitCode::from(EXIT_FAILURE);
        }
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
    let label = if is_local {
        "this computer"
    } else {
        peer_status_label(computer)
    };
    let tags = if computer.tags.is_empty() {
        String::new()
    } else {
        format!(" ({})", computer.tags.join(", "))
    };
    writeln!(
        output,
        "{}{} [{}]  {}",
        computer.name, tags, computer.fingerprint, label
    )?;
    if all {
        return render_all_addresses(computer, output);
    }
    let shown = compact_addresses(&computer.addresses);
    if shown.is_empty() {
        if computer.addresses.is_empty() {
            writeln!(output, "  no current address")?;
        } else {
            writeln!(output, "  no address can be tried from this network")?;
        }
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

fn peer_status_label(computer: &cli_peer::PeerRow) -> &str {
    match computer.connected {
        Some(true) => "connected",
        Some(false) => "not connected",
        None => match computer.status.as_str() {
            "expired" => "saved address expired",
            "revoked" => "revoked",
            "equivocation" => "conflicting signed records",
            _ => "connection unknown",
        },
    }
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
            if candidate.preferred {
                "  preferred"
            } else if !candidate.route_compatible {
                "  unavailable from this network"
            } else {
                ""
            }
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
            .min_by_key(|candidate| (public_kind_rank(&candidate.kind), !address_is_ipv4(&candidate.address)));
        if let Some(public) = public {
            selected.push(public);
        }
    }
    selected
}

const fn public_kind_rank(kind: &str) -> u8 {
    match kind.as_bytes() {
        b"owned-relay" => 0,
        b"mapped" => 1,
        b"reflexive" => 2,
        b"direct" => 3,
        _ => 4,
    }
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
        "{}{} [{}]: generation {}, sequence {}, expires {}",
        result.name,
        if result.tags.is_empty() {
            String::new()
        } else {
            format!(" ({})", result.tags.join(", "))
        },
        result.fingerprint,
        result.generation,
        result.sequence,
        result.expires_at
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
            if candidate.preferred {
                " preferred"
            } else if !candidate.route_compatible {
                " unavailable-from-this-network"
            } else {
                ""
            }
        )
        .is_err()
        {
            return ExitCode::from(EXIT_FAILURE);
        }
    }
    ExitCode::SUCCESS
}

fn render_peer_tag(
    mutation: &peer_tag::PeerTagMutation,
    name: Option<&str>,
    action: &'static str,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let node_id = mutation.node_id.to_string();
    let result = PeerTagOutput {
        schema: "supgang.peer-tag/v1",
        status: "ok",
        action,
        fingerprint: node_id.chars().take(8).collect(),
        node_id,
        name: name.map(ToOwned::to_owned),
        tag: mutation.tag.to_string(),
        tags: mutation.tags.clone(),
        changed: mutation.changed,
    };
    if json {
        return render_json(&result, output, error);
    }
    let peer = result.name.as_deref().map_or_else(
        || format!("peer [{}]", result.fingerprint),
        |name| format!("{name} [{}]", result.fingerprint),
    );
    let message = match (action, result.changed) {
        ("added", true) => format!("Tagged {peer} as {}.", result.tag),
        ("added", false) => format!("{peer} already has tag {}.", result.tag),
        _ => format!("Removed tag {} from {peer}.", result.tag),
    };
    if writeln!(output, "{message}").is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILURE)
    }
}

fn human_candidate_kind(kind: &str) -> &str {
    match kind {
        "local" => "interface",
        "device-claimed" => "device claim",
        "peer-reported" => "peer report",
        "gateway-reported" => "gateway report",
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
mod tests;
