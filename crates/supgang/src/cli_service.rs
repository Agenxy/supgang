//! Foreground service startup and readiness rendering for the CLI.

use std::{io::Write, path::Path, time::Duration};

use serde::Serialize;

use crate::{endpoint_config::EndpointConfig, service};

#[derive(Debug, Serialize)]
struct RunOutput {
    schema: &'static str,
    status: &'static str,
    candidate_count: usize,
    strict_mode: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct RunOptions<'a> {
    pub endpoints: &'a Path,
    pub retry_seconds: u64,
    pub record_hours: u64,
    pub json: bool,
}

pub fn run(state_directory: &Path, options: RunOptions<'_>, output: &mut dyn Write) -> Result<(), String> {
    let endpoints = EndpointConfig::read(options.endpoints)?;
    let config = service::ServiceConfig::new(endpoints.listen(), endpoints.local(), endpoints.direct())
        .and_then(|value| {
            value.with_intervals(
                Duration::from_secs(options.retry_seconds),
                Duration::from_secs(options.record_hours.saturating_mul(60 * 60)),
            )
        })
        .map_err(|error| error.to_string())?;
    let ready = RunOutput {
        schema: "supgang.run/v2",
        status: "running",
        candidate_count: config.candidates.len(),
        strict_mode: true,
    };
    service::run_with_ready(state_directory, config, || {
        if options.json {
            serde_json::to_writer(&mut *output, &ready).map_err(std::io::Error::other)?;
            writeln!(output)?;
        } else {
            writeln!(
                output,
                "Supgang is running in strict mode with {} advertised candidate(s).",
                ready.candidate_count
            )?;
        }
        output.flush()
    })
    .map_err(|error| error.to_string())
}
