//! Owner-only, bounded configuration for listening and advertised endpoints.

use std::{collections::BTreeSet, net::SocketAddr, path::Path};

use serde::Deserialize;

use crate::{
    artifact,
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate, MAX_CANDIDATES},
};

/// Maximum accepted endpoint configuration size.
const MAX_ENDPOINT_CONFIG_BYTES: usize = 4 * 1024;

/// Validated local endpoint configuration.
#[derive(Clone, Debug)]
pub struct EndpointConfig {
    listen: SocketAddr,
    local: Vec<SocketAddr>,
    direct: Vec<SocketAddr>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointDocument {
    listen: SocketAddr,
    candidates: Vec<ConfiguredCandidate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfiguredCandidate {
    kind: ConfiguredKind,
    address: SocketAddr,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ConfiguredKind {
    Local,
    Direct,
}

impl EndpointConfig {
    /// Loads a mode-0600 regular JSON file without following a final symlink.
    ///
    /// # Errors
    ///
    /// Rejects unsafe metadata, oversized input, unknown fields, duplicate
    /// candidates, invalid sockets, and empty or over-budget candidate sets.
    pub fn read(path: impl AsRef<Path>) -> Result<Self, String> {
        let bytes = artifact::read(path, MAX_ENDPOINT_CONFIG_BYTES)
            .map_err(|error| format!("endpoint configuration failed validation: {error}"))?;
        let document: EndpointDocument = serde_json::from_slice(&bytes)
            .map_err(|_| "endpoint configuration is not valid bounded JSON".to_owned())?;
        if document.listen.port() == 0 {
            return Err("endpoint listen port must not be zero".to_owned());
        }
        if document.candidates.is_empty() {
            return Err("endpoint configuration requires at least one candidate".to_owned());
        }
        if document.candidates.len() > MAX_CANDIDATES {
            return Err("endpoint configuration exceeds the candidate limit".to_owned());
        }

        let mut seen = BTreeSet::new();
        let mut local = Vec::new();
        let mut direct = Vec::new();
        for configured in document.candidates {
            let kind = match configured.kind {
                ConfiguredKind::Local => CandidateKind::Local,
                ConfiguredKind::Direct => CandidateKind::Direct,
            };
            EndpointCandidate::new(kind, CandidateTransport::QuicV1, configured.address)
                .map_err(|error| error.to_string())?;
            if !seen.insert(configured.address) {
                return Err("endpoint configuration contains a duplicate candidate".to_owned());
            }
            match configured.kind {
                ConfiguredKind::Local => local.push(configured.address),
                ConfiguredKind::Direct => direct.push(configured.address),
            }
        }
        Ok(Self {
            listen: document.listen,
            local,
            direct,
        })
    }

    /// Returns the local socket on which the service accepts QUIC.
    #[must_use]
    pub const fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// Returns explicitly classified LAN candidates.
    #[must_use]
    pub fn local(&self) -> &[SocketAddr] {
        &self.local
    }

    /// Returns explicitly classified globally routed candidates.
    #[must_use]
    pub fn direct(&self) -> &[SocketAddr] {
        &self.direct
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use crate::artifact;

    use super::{EndpointConfig, MAX_ENDPOINT_CONFIG_BYTES};
    use crate::candidate::MAX_CANDIDATES;

    fn write_config(path: &std::path::Path, text: &str) -> Result<(), Box<dyn std::error::Error>> {
        artifact::write_new(path, text.as_bytes(), MAX_ENDPOINT_CONFIG_BYTES)?;
        Ok(())
    }

    #[test]
    fn reads_a_bounded_owner_only_configuration() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("endpoints.json");
        write_config(
            &path,
            r#"{"listen":"[::]:44330","candidates":[{"kind":"local","address":"127.0.0.1:44330"}]}"#,
        )?;
        let config = EndpointConfig::read(&path)?;
        assert_eq!(config.listen().port(), 44_330);
        assert_eq!(config.local().len(), 1);
        assert!(config.direct().is_empty());
        Ok(())
    }

    #[test]
    fn rejects_permissive_unknown_and_duplicate_input() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let permissive = directory.path().join("permissive.json");
        write_config(
            &permissive,
            r#"{"listen":"127.0.0.1:1","candidates":[{"kind":"local","address":"127.0.0.1:1"}]}"#,
        )?;
        fs::set_permissions(&permissive, fs::Permissions::from_mode(0o644))?;
        assert!(EndpointConfig::read(&permissive).is_err());

        let duplicate = directory.path().join("duplicate.json");
        write_config(
            &duplicate,
            r#"{"listen":"127.0.0.1:1","candidates":[{"kind":"local","address":"127.0.0.1:1"},{"kind":"local","address":"127.0.0.1:1"}]}"#,
        )?;
        assert!(EndpointConfig::read(&duplicate).is_err());

        let cross_kind_duplicate = directory.path().join("cross-kind-duplicate.json");
        write_config(
            &cross_kind_duplicate,
            r#"{"listen":"[::]:1","candidates":[{"kind":"local","address":"8.8.8.8:1"},{"kind":"direct","address":"8.8.8.8:1"}]}"#,
        )?;
        assert!(EndpointConfig::read(&cross_kind_duplicate).is_err());

        let unknown = directory.path().join("unknown.json");
        write_config(
            &unknown,
            r#"{"listen":"127.0.0.1:1","extra":true,"candidates":[{"kind":"local","address":"127.0.0.1:1"}]}"#,
        )?;
        assert!(EndpointConfig::read(&unknown).is_err());

        let oversized = directory.path().join("oversized.json");
        artifact::write_new(
            &oversized,
            &[b'x'; MAX_ENDPOINT_CONFIG_BYTES + 1],
            MAX_ENDPOINT_CONFIG_BYTES + 1,
        )?;
        assert!(EndpointConfig::read(&oversized).is_err());
        Ok(())
    }

    #[test]
    fn rejects_more_than_the_protocol_candidate_budget() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("too-many.json");
        let candidates = (1..=MAX_CANDIDATES + 1)
            .map(|port| serde_json::json!({"kind": "local", "address": format!("127.0.0.1:{port}")}))
            .collect::<Vec<_>>();
        let document = serde_json::json!({"listen": "127.0.0.1:1", "candidates": candidates});
        write_config(&path, &serde_json::to_string(&document)?)?;
        assert!(EndpointConfig::read(&path).is_err());
        Ok(())
    }
}
