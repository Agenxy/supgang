//! Read-only data behind the MCP tools.

use std::{path::Path, str::FromStr};

use serde::Serialize;

use crate::{
    VERSION, cli_peer,
    control::{self, ControlReply, ControlRequest, ControlStatus},
    ids::NodeId,
    profile, state,
};

#[derive(Debug, Serialize)]
pub(super) struct McpStatusOutput {
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
    member_count: usize,
    event_count: usize,
}

pub(super) fn fleet_data(state_directory: &Path) -> Result<cli_peer::PeersOutput, String> {
    let mut fleet = match control::request(state_directory, ControlRequest::Peers) {
        Ok(Some(ControlReply::Peers { value })) => Ok(value),
        Ok(Some(ControlReply::Error { message })) => Err(message),
        Ok(Some(_)) => Err("Supgang's local service returned an unexpected response".to_owned()),
        Ok(None) => return cli_peer::peers_read_only(state_directory),
        Err(error) => Err(error.to_string()),
    }?;
    cli_peer::apply_tags(state_directory, &mut fleet)?;
    Ok(fleet)
}

pub(super) fn status_data(state_directory: &Path) -> Result<McpStatusOutput, String> {
    match control::request(state_directory, ControlRequest::Status) {
        Ok(Some(ControlReply::Status { value })) => return Ok(running_status(value)),
        Ok(Some(ControlReply::Error { message })) => return Err(message),
        Ok(Some(_)) => return Err("Supgang's local service returned an unexpected response".to_owned()),
        Ok(None) => {}
        Err(error) => return Err(error.to_string()),
    }
    let local = state::open_read_only(state_directory).map_err(|error| error.to_string())?;
    let node_id = local.identity().device.node_id();
    let name = profile::load(state_directory).map_err(|error| error.to_string())?;
    Ok(McpStatusOutput {
        schema: "supgang.mcp.status/v2",
        status: "ok",
        version: VERSION,
        name: name.to_string(),
        hive_id: local.identity().hive_id.to_string(),
        node_id: node_id.to_string(),
        service: "stopped",
        listen: None,
        active_peers: None,
        known_peers: None,
        router_mapping: None,
        internet_reachability: None,
        member_count: local.member_count(),
        event_count: local.event_count(),
    })
}

fn running_status(value: ControlStatus) -> McpStatusOutput {
    McpStatusOutput {
        schema: "supgang.mcp.status/v2",
        status: "ok",
        version: VERSION,
        name: value.name,
        hive_id: value.hive_id,
        node_id: value.node_id,
        service: "running",
        listen: Some(value.listen),
        active_peers: Some(value.active_peers),
        known_peers: Some(value.known_peers),
        router_mapping: Some(value.router_mapping),
        internet_reachability: Some(value.internet_reachability),
        member_count: value.member_count,
        event_count: value.event_count,
    }
}

pub(super) fn resolve_data(state_directory: &Path, selector: &str) -> Result<cli_peer::ResolveOutput, String> {
    let node_id = if let Ok(node_id) = NodeId::from_str(selector) {
        node_id
    } else {
        let mut fleet = fleet_data(state_directory)?;
        fleet.peers.extend(fleet.this_computer.take());
        cli_peer::resolve_selector_from_rows(&fleet.peers, selector)?
    };
    let mut resolution = match control::request(state_directory, ControlRequest::Resolve(node_id)) {
        Ok(Some(ControlReply::Resolve { value })) => Ok(value),
        Ok(Some(ControlReply::Error { message })) => Err(message),
        Ok(Some(_)) => Err("Supgang's local service returned an unexpected response".to_owned()),
        Ok(None) => return cli_peer::resolve_read_only(state_directory, &node_id.to_string()),
        Err(error) => Err(error.to_string()),
    }?;
    cli_peer::apply_tags_to_resolve(state_directory, &mut resolution)?;
    Ok(resolution)
}
