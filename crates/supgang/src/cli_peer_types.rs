//! Stable, non-secret data contracts shared by the CLI, control socket, and MCP server.

use serde::{Deserialize, Serialize};

/// A non-secret row returned by `peers`.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PeerRow {
    pub name: String,
    pub name_source: String,
    /// Local nicknames, never signed by or synchronized with the peer.
    #[serde(default)]
    pub tags: Vec<String>,
    pub fingerprint: String,
    pub node_id: String,
    /// Live authenticated session state, or absent when read offline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected: Option<bool>,
    pub status: String,
    pub generation: u64,
    pub sequence: u64,
    pub expires_at: u64,
    pub candidate_count: usize,
    pub addresses: Vec<ResolvedCandidate>,
}

/// Machine-readable peer-directory summary.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PeersOutput {
    pub schema: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub this_computer: Option<PeerRow>,
    pub peers: Vec<PeerRow>,
}

/// One explicitly requested address candidate.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct ResolvedCandidate {
    pub scope: String,
    pub kind: String,
    pub transport: String,
    pub address: String,
    pub provenance: String,
    /// Device that signed a short-lived report, when this is not authoritative endpoint state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reporter: Option<String>,
    /// Expiry of a short-lived report, when distinct from the endpoint record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_expires_at: Option<u64>,
    /// Whether this computer currently has a compatible physical-network route.
    /// This does not claim that a router or firewall will admit the connection.
    #[serde(default)]
    pub route_compatible: bool,
    pub preferred: bool,
}

/// Machine-readable address resolution with signed-record provenance.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct ResolveOutput {
    pub schema: String,
    pub status: String,
    pub node_id: String,
    pub name: String,
    /// Local nicknames, never signed by or synchronized with the peer.
    #[serde(default)]
    pub tags: Vec<String>,
    pub fingerprint: String,
    pub generation: u64,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub candidates: Vec<ResolvedCandidate>,
}
