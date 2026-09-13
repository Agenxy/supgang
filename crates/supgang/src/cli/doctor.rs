//! Plain-language reachability diagnosis for `supgang doctor`.

use super::DoctorCheck;

pub(super) fn reachability_check(live: Option<&(String, String, usize)>) -> DoctorCheck {
    let Some((mapping, reachability, _active_peers)) = live else {
        return DoctorCheck {
            id: "internet-reachability",
            status: "warning",
            detail: "start `supgang run` to check router mapping and live peer connectivity".to_owned(),
        };
    };
    match reachability.as_str() {
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
                    "no usable router mapping is available; this computer is reachable only on its local network"
                        .to_owned()
                }
                "disabled" => "automatic router mapping is not enabled for this service".to_owned(),
                _ => "no usable Internet path is currently advertised".to_owned(),
            },
        },
    }
}
