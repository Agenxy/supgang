//! Owner exposure commands and byte-only peer service transport.

use std::{io::Write, path::Path, process::ExitCode};

use crate::{
    cli::{render_error, render_json},
    cli_control,
    control::{self, ControlReply, ControlRequest},
    record::ServiceName,
    state, transport, tunnel_policy,
};

pub mod forward;
mod stdio;

pub use forward::forward;

/// Keeps a timeout's own advice, which tells the owner what to do; other
/// control failures are summarised by the caller.
fn request_failed(error: &control::ControlError, summary: &str) -> String {
    match error {
        control::ControlError::Unresponsive { .. } => error.to_string(),
        _ => summary.to_owned(),
    }
}

pub fn add_mapped(
    directory: &Path,
    input: &Path,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let result = (|| {
        let bytes =
            crate::artifact::read(input, 128).map_err(|_| "mapped endpoint input must be a bounded owner-only file")?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "mapped endpoint input is invalid")?;
        let address: std::net::SocketAddrV4 = text
            .trim()
            .parse()
            .map_err(|_| "mapped endpoint must be a public IPv4 UDP socket")?;
        match control::request(directory, ControlRequest::AddMapped { address })
            .map_err(|error| request_failed(&error, "local endpoint publication request failed"))?
        {
            Some(ControlReply::EndpointChanged) => Ok(()),
            Some(ControlReply::Error { message }) => Err(message),
            _ => Err("start a compatible local Supgang service before publishing the mapped endpoint".to_owned()),
        }
    })();
    match result {
        Err(message) => render_error(json, &message, output, error),
        Ok(()) if json => render_json(&serde_json::json!({"schema":"supgang.endpoint-publication/v1","status":"ok"}), output, error),
        Ok(()) => if writeln!(output, "Owner-mapped endpoint signed and queued for authenticated gossip. Verify the peer received it before roaming.").is_ok() {
            ExitCode::SUCCESS
        } else { ExitCode::from(3) },
    }
}

pub fn connect(directory: &Path, peer: &str, name: &str, json: bool, error: &mut dyn Write) -> ExitCode {
    let result = (|| {
        if json {
            return Err("connect carries only application bytes; remove --json".to_owned());
        }
        let name = ServiceName::new(name).map_err(|_| "service name is invalid")?;
        // A ProxyCommand starts before `ssh -f` detaches its master, so it stays
        // in the caller's process group; a job runner ending that group would
        // kill it and break a master that outlives its creator. Its own session
        // leaves only its stdin and stdout, which the ssh process holds, to end it.
        // Already leading a group, as an interactive shell may arrange, is fine.
        let _session = rustix::process::setsid();
        let target = cli_control::resolve_peer_node(directory, peer)?;
        let stream = control::connect_service(directory, target, tunnel_policy::encoded_name(&name))?;
        let runtime = transport::build_runtime().map_err(|_| "service transport runtime setup failed")?;
        runtime.block_on(async {
            let socket = tokio::net::UnixStream::from_std(stream).map_err(|_| "local tunnel socket setup failed")?;
            stdio::bridge(socket)
                .await
                .map_err(|_| "service tunnel ended with an I/O failure".to_owned())
        })
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let _write = writeln!(error, "{message}");
            ExitCode::from(3)
        }
    }
}

pub fn expose(
    directory: &Path,
    name: &str,
    port: u16,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let result = (|| {
        let name = ServiceName::new(name).map_err(|_| "service name is invalid")?;
        let request = ControlRequest::Expose {
            name: tunnel_policy::encoded_name(&name),
            port,
        };
        match control::request(directory, request)
            .map_err(|error| request_failed(&error, "local service exposure request failed"))?
        {
            Some(ControlReply::ExposureChanged) => Ok(()),
            Some(ControlReply::Error { message }) => Err(message),
            Some(_) => Err("local service does not support exposure; refresh its installed artifact".to_owned()),
            None => {
                let _state_lock = state::open(directory).map_err(|_| "protected tunnel state could not be opened")?;
                let mut policy = tunnel_policy::load(directory)?;
                policy.set(name, port)?;
                tunnel_policy::save(directory, &policy)
            }
        }
    })();
    match result {
        Err(message) => render_error(json, &message, output, error),
        Ok(()) if json => render_json(
            &serde_json::json!({"schema":"supgang.exposure/v1","status":"ok"}),
            output,
            error,
        ),
        Ok(()) => {
            let message = if port == 0 {
                "Exposure removed. Existing sessions were ended before acknowledgement."
            } else {
                "Loopback service exposed to authenticated hive members. Existing sessions reconnect under the new policy."
            };
            if writeln!(output, "{message}").is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(3)
            }
        }
    }
}

pub fn exposures(directory: &Path, json: bool, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    let result = (|| match control::request(directory, ControlRequest::Exposures)
        .map_err(|failure| request_failed(&failure, "local exposure listing request failed"))?
    {
        Some(ControlReply::Exposures { value }) => Ok(("running-service", value)),
        Some(ControlReply::Error { message }) => Err(message),
        Some(_) => Err("local service does not support exposure listing; refresh its installed artifact".to_owned()),
        None => {
            let _state =
                state::open_read_only(directory).map_err(|_| "protected state could not be read".to_owned())?;
            let policy = tunnel_policy::load(directory)?;
            Ok((
                "saved-state",
                tunnel_policy::ExposureSnapshot::from_policy(&policy, None),
            ))
        }
    })();
    match result {
        Err(message) => render_error(json, &message, output, error),
        Ok((source, snapshot)) if json => render_json(
            &serde_json::json!({
                "schema": "supgang.exposures/v1",
                "status": "ok",
                "source": source,
                "exposures": snapshot.exposures,
                "limits": snapshot.limits,
            }),
            output,
            error,
        ),
        Ok((source, snapshot)) => {
            let result = (|| -> std::io::Result<()> {
                writeln!(output, "Exposure policy ({source}):")?;
                if snapshot.exposures.is_empty() {
                    writeln!(output, "  No services exposed.")?;
                } else {
                    for exposure in snapshot.exposures {
                        writeln!(output, "  {}: 127.0.0.1:{}", exposure.name, exposure.loopback_port)?;
                    }
                }
                let limits = snapshot.limits;
                writeln!(
                    output,
                    "Limits: {} per peer, {} total, {} seconds idle.",
                    limits.per_peer, limits.total, limits.idle_seconds
                )?;
                if let Some(active_total) = limits.active_total.filter(|active| *active != limits.total) {
                    writeln!(
                        output,
                        "Active total: {active_total}; restart the service to apply the saved total."
                    )?;
                }
                Ok(())
            })();
            if result.is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(3)
            }
        }
    }
}

pub fn limits(
    directory: &Path,
    per_peer: usize,
    total: usize,
    idle_seconds: u64,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let result = (|| {
        // A running service owns the policy and rewrites it on exposure
        // changes, so it saves the limits itself; a boot service cannot be
        // stopped without an administrator, and restarting it needs none.
        let request = ControlRequest::TunnelLimits {
            per_peer: u16::try_from(per_peer).map_err(|_| "per-peer limit is out of range")?,
            total: u16::try_from(total).map_err(|_| "total limit is out of range")?,
            idle_seconds: u32::try_from(idle_seconds).map_err(|_| "idle limit is out of range")?,
        };
        match control::request(directory, request)
            .map_err(|error| request_failed(&error, "local service request failed"))?
        {
            Some(ControlReply::LimitsSaved) => return Ok(true),
            Some(ControlReply::Error { message }) => return Err(message),
            Some(_) => return Err("local service returned an unexpected reply".to_owned()),
            None => {}
        }
        let _lock = state::open(directory).map_err(|_| "protected tunnel state could not be opened")?;
        let mut policy = tunnel_policy::load(directory)?;
        policy.per_peer = per_peer;
        policy.total = total;
        policy.idle_seconds = idle_seconds;
        tunnel_policy::save(directory, &policy).map(|()| false)
    })();
    match result {
        Err(message) => render_error(json, &message, output, error),
        Ok(running) if json => render_json(
            &serde_json::json!({
                "schema": "supgang.tunnel-limits/v2",
                "status": "ok",
                "applies_on": if running { "new-connections-now-total-after-restart" } else { "next-service-start" },
            }),
            output,
            error,
        ),
        Ok(running) => {
            let message = if running {
                "Tunnel limits saved. New connections use them now; restart the service to apply the total."
            } else {
                "Tunnel limits saved. Start the service to apply them."
            };
            if writeln!(output, "{message}").is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(3)
            }
        }
    }
}
