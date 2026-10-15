//! Plain-language reachability diagnosis for `supgang doctor`.

pub(super) fn peer_endpoint_check(directory: &std::path::Path, selector: &str) -> super::DoctorCheck {
    let result = (|| {
        let target = crate::cli_control::resolve_peer_node(directory, selector)?;
        let value = match crate::control::request(directory, crate::control::ControlRequest::Resolve(target))
            .map_err(|_| "peer endpoint check could not reach the local service".to_owned())?
        {
            Some(crate::control::ControlReply::Resolve { value }) => value,
            Some(crate::control::ControlReply::Error { message }) => return Err(message),
            Some(_) => return Err("local peer endpoint reply is incompatible".to_owned()),
            None => crate::cli_peer::resolve(directory, &target.to_string())?,
        };
        let public = value
            .candidates
            .iter()
            .any(|candidate| candidate.scope == "public" && candidate.provenance == "device-signed");
        Ok((public, value.expires_at))
    })();
    match result {
        Ok((public, expires_at)) => super::DoctorCheck {
            id: "peer-public-endpoint",
            status: if public { "ok" } else { "error" },
            detail: format!(
                "peer signed record has {}public endpoint and expires at Unix time {expires_at}; this is no proof of WAN reachability",
                if public { "a " } else { "no " }
            ),
        },
        Err(detail) => super::DoctorCheck {
            id: "peer-public-endpoint",
            status: "error",
            detail,
        },
    }
}

use super::DoctorCheck;
use crate::device_key::custody::{self, Availability, CustodyCapability, CustodyKind};

#[derive(Debug, serde::Serialize)]
pub(super) struct CustodyOutput {
    // None means no valid identity was loaded, not an assumed file fallback.
    provider: Option<CustodyKind>,
    capabilities: Vec<CustodyCapability>,
}

impl CustodyOutput {
    pub(super) fn current(identity_loaded: bool) -> Self {
        Self {
            provider: identity_loaded.then_some(CustodyKind::File),
            capabilities: custody::capabilities(),
        }
    }
}

pub(super) fn render_custody(custody: &CustodyOutput, out: &mut dyn std::io::Write) -> std::io::Result<()> {
    writeln!(
        out,
        "Custody: {}",
        match custody.provider {
            Some(CustodyKind::File) => "file (live identity; extractable)".to_owned(),
            Some(kind) => format!("{} (owner-enrolled; not attested)", kind_name(kind)),
            None => "unknown (identity could not be loaded)".to_owned(),
        }
    )?;
    for capability in &custody.capabilities {
        let name = kind_name(capability.kind);
        match capability.availability {
            Availability::Ready => writeln!(out, "  {name}: ready")?,
            Availability::NotBuilt => writeln!(out, "  {name}: not built")?,
            Availability::Unavailable(reason) => writeln!(out, "  {name}: unavailable; {reason}")?,
        }
    }
    Ok(())
}

const fn kind_name(kind: CustodyKind) -> &'static str {
    match kind {
        CustodyKind::SecureEnclave => "Secure Enclave",
        CustodyKind::Tpm2 => "TPM 2.0",
        CustodyKind::SecurityKey => "Security key",
        CustodyKind::File => "File",
    }
}

pub(super) fn reachability_check(live: Option<&(String, String, usize)>) -> DoctorCheck {
    let Some((mapping, reachability, active_peers)) = live else {
        return DoctorCheck {
            id: "internet-reachability",
            status: "warning",
            detail: "start `supgang run` to check router mapping and live peer connectivity".to_owned(),
        };
    };
    let mut check = match reachability.as_str() {
        "owner-mapped-address-unverified" => DoctorCheck {
            id: "internet-reachability",
            status: "warning",
            detail: "the owner declared a UDP forward, but Supgang has not proved its return path".to_owned(),
        },
        "gateway-reported-address" => DoctorCheck {
            id: "internet-reachability",
            status: "warning",
            detail: "the gateway reported a public address, but Supgang has not proved that it works".to_owned(),
        },
        "peer-reported-address" => DoctorCheck {
            id: "internet-reachability",
            status: "warning",
            detail: "another authenticated computer reported this address, but Supgang has not proved a return path"
                .to_owned(),
        },
        "device-claimed-address" => DoctorCheck {
            id: "internet-reachability",
            status: "warning",
            detail: "this computer claims a public address, but no independent return path has been proved".to_owned(),
        },
        "direct-address-unverified" => DoctorCheck {
            id: "internet-reachability",
            status: "warning",
            detail: "a public interface address is configured, but no peer has confirmed it".to_owned(),
        },
        _ => DoctorCheck {
            id: "internet-reachability",
            status: "warning",
            detail: match mapping.as_str() {
                "checking" => "the local gateway is still being checked for a UDP mapping".to_owned(),
                "unavailable" => {
                    "automatic router mapping is unavailable; other connection methods may still work".to_owned()
                }
                "disabled" => "automatic router mapping is not enabled for this service".to_owned(),
                _ => "no usable Internet path is currently advertised".to_owned(),
            },
        },
    };
    if *active_peers > 0 {
        check.detail = format!("{} computer(s) connected now. {}", active_peers, check.detail);
    }
    check
}

use super::{DoctorOutput, EXIT_FAILURE, VERSION, control, render_json, state, storage};
use std::{io::Write, path::PathBuf, process::ExitCode};
pub(super) fn run(
    state_directory: &PathBuf,
    peer: Option<&str>,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let mut checks = vec![DoctorCheck {
        id: "public-dependencies",
        status: "ok",
        detail: "strict mode has no hosted discovery, account, telemetry, DNS publisher, or vendor relay".to_owned(),
    }];
    let identity_result = storage::load_identity(state_directory);
    checks.push(match &identity_result {
        Ok(_) => DoctorCheck {
            id: "identity",
            status: "ok",
            detail: "protected identity is owner-only and its checksum is valid".to_owned(),
        },
        Err(storage_error) => DoctorCheck {
            id: "identity",
            status: "error",
            detail: storage_error.to_string(),
        },
    });
    let status_response = control::request(state_directory, control::ControlRequest::Status);
    let live_reachability = match &status_response {
        Ok(Some(control::ControlReply::Status { value })) => Some((
            value.router_mapping.clone(),
            value.internet_reachability.clone(),
            value.active_peers,
        )),
        _ => None,
    };
    let (state_ok, state_check) = match status_response {
        Ok(Some(control::ControlReply::Status { value })) => (
            true,
            DoctorCheck {
                id: "authoritative-state",
                status: "ok",
                detail: format!(
                    "running owner service holds {} verified event(s) for {} authorized member(s)",
                    value.event_count, value.member_count
                ),
            },
        ),
        Ok(Some(control::ControlReply::Error { message })) => (
            false,
            DoctorCheck {
                id: "authoritative-state",
                status: "error",
                detail: message,
            },
        ),
        Ok(Some(_)) => (
            false,
            DoctorCheck {
                id: "authoritative-state",
                status: "error",
                detail: "local service returned an unexpected response".to_owned(),
            },
        ),
        Ok(None) => match state::open_read_only(state_directory) {
            Ok(state) if state.revocations().contains(&state.identity().device.node_id()) => (
                false,
                DoctorCheck {
                    id: "authoritative-state",
                    status: "error",
                    detail: "local device identity is root-revoked; service startup is denied".to_owned(),
                },
            ),
            Ok(state) => (
                true,
                DoctorCheck {
                    id: "authoritative-state",
                    status: "ok",
                    detail: format!(
                        "root authorization and {} committed event(s) replayed with consecutive counters",
                        state.event_count()
                    ),
                },
            ),
            Err(state_error) => (
                false,
                DoctorCheck {
                    id: "authoritative-state",
                    status: "error",
                    detail: state_error.to_string(),
                },
            ),
        },
        Err(control_error) => (
            false,
            DoctorCheck {
                id: "authoritative-state",
                status: "error",
                detail: control_error.to_string(),
            },
        ),
    };
    checks.push(state_check);
    checks.push(reachability_check(live_reachability.as_ref()));
    if let Some(peer) = peer {
        checks.push(peer_endpoint_check(state_directory, peer));
    }
    checks.push(DoctorCheck {
        id: "key-provider",
        status: "warning",
        detail: if identity_result.is_ok() {
            "the live Ed25519 identity uses an owner-only file; optional P-256 providers do not migrate it"
        } else {
            "the live identity could not be loaded; its custody is unknown"
        }
        .to_owned(),
    });
    let failed = identity_result.is_err() || !state_ok || checks.iter().any(|check| check.status == "error");
    let result = DoctorOutput {
        schema: "supgang.doctor/v1",
        status: if failed { "error" } else { "warning" },
        version: VERSION,
        strict_mode: true,
        public_dependencies: 0,
        checks,
        custody: CustodyOutput::current(identity_result.is_ok()),
    };
    let rendered = if json {
        render_json(&result, output, error)
    } else {
        render_doctor_human(&result, output)
    };
    if rendered != ExitCode::SUCCESS {
        rendered
    } else if failed {
        ExitCode::from(EXIT_FAILURE)
    } else {
        ExitCode::SUCCESS
    }
}

fn render_doctor_human(result: &DoctorOutput, output: &mut dyn Write) -> ExitCode {
    if writeln!(output, "Supgang doctor: {}", result.status).is_err() {
        return ExitCode::from(EXIT_FAILURE);
    }
    for check in &result.checks {
        if writeln!(output, "[{}] {}: {}", check.status, check.id, check.detail).is_err() {
            return ExitCode::from(EXIT_FAILURE);
        }
    }
    if render_custody(&result.custody, output).is_err() {
        return ExitCode::from(EXIT_FAILURE);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custody_json_is_additive_and_does_not_guess_at_an_unreadable_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let report = CustodyOutput::current(true);
        let json = serde_json::to_value(&report)?;
        assert_eq!(json.get("provider"), Some(&serde_json::json!("file")));
        assert_eq!(
            json.get("capabilities")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(4)
        );
        let unknown = CustodyOutput {
            provider: None,
            capabilities: report.capabilities,
        };
        assert_eq!(
            serde_json::to_value(&unknown)?.get("provider"),
            Some(&serde_json::Value::Null)
        );
        let mut text = Vec::new();
        render_custody(&unknown, &mut text)?;
        let text = String::from_utf8(text)?;
        assert!(text.contains("unknown (identity could not be loaded)"));
        assert!(text.contains("Security key: not built"));
        Ok(())
    }
}
