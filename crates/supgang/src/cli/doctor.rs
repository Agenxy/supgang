//! Plain-language reachability diagnosis for `supgang doctor`.

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
