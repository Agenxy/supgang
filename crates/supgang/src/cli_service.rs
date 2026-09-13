//! Foreground service startup and readiness rendering for the CLI.

use std::{io::Write, path::Path, time::Duration};

use serde::Serialize;

use crate::{endpoint_config::EndpointConfig, profile, service, settings, state};

#[derive(Debug, Serialize)]
struct RunOutput {
    schema: &'static str,
    status: &'static str,
    mode: &'static str,
    candidate_count: usize,
    address_history: usize,
    automatic_router_mapping: bool,
    #[serde(flatten)]
    recovery: RecoveryOutput,
    strict_mode: bool,
}

#[derive(Debug, Serialize)]
struct RecoveryOutput {
    automatic_peer_assistance: bool,
    synchronized_recovery: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct RunOptions<'a> {
    pub endpoints: Option<&'a Path>,
    pub port: u16,
    pub retry_seconds: u64,
    pub record_hours: u64,
    pub router_mapping: bool,
    pub anchor_mode: bool,
    pub json: bool,
}

pub fn run(state_directory: &Path, options: RunOptions<'_>, output: &mut dyn Write) -> Result<(), String> {
    let automatic_interfaces = options.endpoints.is_none();
    let endpoints = options
        .endpoints
        .map_or_else(|| EndpointConfig::automatic(options.port), EndpointConfig::read)?;
    let local_state = state::open(state_directory).map_err(|error| error.to_string())?;
    let display_name = profile::load_or_create(state_directory, local_state.identity().device.node_id())
        .map_err(|error| error.to_string())?;
    drop(local_state);
    let local_settings = settings::load(state_directory).map_err(|error| error.to_string())?;
    let config = service::ServiceConfig::new(display_name, endpoints.listen(), endpoints.local(), endpoints.direct())
        .and_then(|value| value.with_mapped_addresses(endpoints.mapped()))
        .and_then(|value| {
            value.with_intervals(
                Duration::from_secs(options.retry_seconds),
                Duration::from_secs(options.record_hours.saturating_mul(60 * 60)),
            )
        })
        .and_then(|value| value.with_address_history(local_settings.address_history()))
        .map(|value| value.with_automatic_interface_refresh(automatic_interfaces))
        .map(|value| value.with_automatic_router_mapping(automatic_interfaces && options.router_mapping))
        .map(|value| value.with_anchor_mode(options.anchor_mode))
        .map_err(|error| error.to_string())?;
    let ready = RunOutput {
        schema: "supgang.run/v5",
        status: "running",
        mode: if options.anchor_mode { "anchor" } else { "device" },
        candidate_count: config.candidates.len(),
        address_history: config.address_history,
        automatic_router_mapping: config.automatic_router_mapping,
        recovery: RecoveryOutput {
            automatic_peer_assistance: true,
            synchronized_recovery: true,
        },
        strict_mode: true,
    };
    service::run_with_ready(state_directory, config, || {
        if options.json {
            serde_json::to_writer(&mut *output, &ready).map_err(std::io::Error::other)?;
            writeln!(output)?;
        } else {
            writeln!(
                output,
                "Supgang {} is running with {} advertised address(es), {} historical retries per peer, automatic peer assistance, synchronized recovery, and local-router mapping {}.",
                if options.anchor_mode { "anchor" } else { "device" },
                ready.candidate_count,
                ready.address_history,
                if ready.automatic_router_mapping {
                    "enabled"
                } else {
                    "disabled"
                }
            )?;
        }
        output.flush()
    })
    .map_err(|error| error.to_string())
}
