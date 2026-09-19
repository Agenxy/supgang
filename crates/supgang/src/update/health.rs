//! Local readiness is bound to the selected executable and its child startup.

use std::path::Path;

use super::{SupervisorError, UpdateError};
use crate::control::ControlReply;

pub(super) struct ExpectedPayload {
    node_id: String,
    hive_id: String,
    version: String,
    pub(super) startup_id: String,
}

impl ExpectedPayload {
    pub(super) fn new(state: &Path, version: &str) -> Result<Self, SupervisorError> {
        let local = crate::state::open_read_only(state).map_err(|_| UpdateError::InvalidBundle)?;
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| UpdateError::InvalidBundle)?;
        Ok(Self {
            node_id: local.identity().device.node_id().to_string(),
            hive_id: local.identity().hive_id.to_string(),
            version: version.to_owned(),
            startup_id: hex::encode(random),
        })
    }

    pub(super) fn matches(&self, reply: Option<&ControlReply>, pid: Option<u32>) -> bool {
        let Some(ControlReply::Status { value }) = reply else {
            return false;
        };
        value.node_id == self.node_id
            && value.hive_id == self.hive_id
            && value.version == self.version
            && value.startup_id == self.startup_id
            && pid.is_some_and(|pid| pid != 0 && value.process_id == pid)
            && value.restart_supported
            && value.member_count > 0
            && value.instance_id.len() == 32
            && value.instance_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            && value
                .listen
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|address| address.port() != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::ExpectedPayload;
    use crate::control::{ControlReply, ControlStatus};

    #[test]
    fn readiness_rejects_errors_stale_sockets_and_wrong_identity_or_candidate() -> Result<(), Box<dyn std::error::Error>>
    {
        let probe = ExpectedPayload {
            node_id: "node".to_owned(),
            hive_id: "hive".to_owned(),
            version: "1.2.3".to_owned(),
            startup_id: "1".repeat(32),
        };
        let status: ControlStatus = serde_json::from_value(serde_json::json!({
            "node_id":"node", "hive_id":"hive", "version":"1.2.3", "startup_id":"1".repeat(32), "process_id":42,
            "instance_id":"2".repeat(32), "restart_supported":true, "name":"test", "listen":"127.0.0.1:44330",
            "active_peers":0, "known_peers":0, "router_mapping":"disabled", "internet_reachability":"unverified", "member_count":1, "event_count":1
        }))?;
        assert!(probe.matches(Some(&ControlReply::Status { value: status.clone() }), Some(42)));
        assert!(!probe.matches(None, Some(42)));
        assert!(!probe.matches(
            Some(&ControlReply::Error {
                message: "not ready".to_owned()
            }),
            Some(42)
        ));
        for field in ["node_id", "hive_id", "version", "startup_id", "instance_id", "listen"] {
            let mut encoded = serde_json::to_value(&status)?;
            *encoded.get_mut(field).ok_or("field")? = serde_json::json!("wrong");
            let changed = serde_json::from_value(encoded)?;
            assert!(
                !probe.matches(Some(&ControlReply::Status { value: changed }), Some(42)),
                "accepted {field}"
            );
        }
        assert!(!probe.matches(Some(&ControlReply::Status { value: status }), Some(43)));
        Ok(())
    }
}
