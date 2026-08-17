//! Foreground service startup and readiness rendering for the CLI.

use std::{io::Write, net::SocketAddr, path::Path, time::Duration};

use serde::Serialize;

use crate::service;

#[derive(Debug, Serialize)]
struct RunOutput {
    schema: &'static str,
    status: &'static str,
    listen: String,
    candidate_count: usize,
    strict_mode: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct RunOptions<'a> {
    pub listen: SocketAddr,
    pub local: &'a [SocketAddr],
    pub direct: &'a [SocketAddr],
    pub retry_seconds: u64,
    pub record_hours: u64,
    pub json: bool,
}

pub fn run(state_directory: &Path, options: RunOptions<'_>, output: &mut dyn Write) -> Result<(), String> {
    let config = service::ServiceConfig::new(options.listen, options.local, options.direct)
        .and_then(|value| {
            value.with_intervals(
                Duration::from_secs(options.retry_seconds),
                Duration::from_secs(options.record_hours.saturating_mul(60 * 60)),
            )
        })
        .map_err(|error| error.to_string())?;
    let ready = RunOutput {
        schema: "supgang.run/v1",
        status: "running",
        listen: options.listen.to_string(),
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
                "Supgang is running in strict sovereign mode with {} advertised candidate(s).",
                ready.candidate_count
            )?;
        }
        output.flush()
    })
    .map_err(|error| error.to_string())
}
