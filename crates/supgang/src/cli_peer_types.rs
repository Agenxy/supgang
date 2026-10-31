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
    /// Owner-only live transport diagnostics, not an advertised or durable address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<PeerConnection>,
    pub status: String,
    pub generation: u64,
    pub sequence: u64,
    pub expires_at: u64,
    pub candidate_count: usize,
    pub addresses: Vec<ResolvedCandidate>,
    /// Services the computer advertises in its signed record, at its addresses.
    #[serde(default)]
    pub services: Vec<ServiceRow>,
}

/// The actual socket used by an authenticated connection at the time of the read.
/// Counters describe transport activity, not application-level delivery receipts.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PeerConnection {
    /// Canonical remote socket, distinct from the peer's advertised candidates.
    pub remote_address: String,
    /// Number of UDP datagrams received on this connection.
    pub received_datagrams: u64,
    /// Number of UDP datagrams sent on this connection.
    pub sent_datagrams: u64,
    /// The QUIC path's measured state, for telling a lossy or policed network
    /// from a transport problem. Absent from older services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathStatistics>,
}

/// One QUIC path's congestion and loss state at the time of the read.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PathStatistics {
    /// Smoothed round-trip time in milliseconds.
    pub rtt_ms: u64,
    /// Congestion window in bytes: how much may be in flight.
    pub congestion_window_bytes: u64,
    /// Times congestion control reduced the window.
    pub congestion_events: u64,
    /// QUIC packets sent on this path.
    pub sent_packets: u64,
    /// QUIC packets declared lost on this path.
    pub lost_packets: u64,
    /// Current path MTU in bytes.
    pub current_mtu: u16,
    /// Times MTU discovery found larger packets silently dropped.
    pub black_holes_detected: u64,
}

impl From<&quinn::PathStats> for PathStatistics {
    fn from(path: &quinn::PathStats) -> Self {
        Self {
            rtt_ms: u64::try_from(path.rtt.as_millis()).unwrap_or(u64::MAX),
            congestion_window_bytes: path.cwnd,
            congestion_events: path.congestion_events,
            sent_packets: path.sent_packets,
            lost_packets: path.lost_packets,
            current_mtu: path.current_mtu,
            black_holes_detected: path.black_holes_detected,
        }
    }
}

/// One service a computer says it offers, signed by that computer's device.
///
/// A claim, not an observation: Supgang has not dialled the port. A consumer
/// that connects to one of the computer's addresses on `port` and finds a
/// TLS key whose SHA-256 is `key_pin` is talking to what the computer signed.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct ServiceRow {
    /// The service's own name: `dibs`, `remap`, and so on.
    pub name: String,
    /// The port it listens on, at the computer's addresses.
    pub port: u16,
    /// Lowercase hex SHA-256 of the service's TLS public key.
    pub key_pin: String,
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
    /// Whether this computer has a compatible address family for an attempt.
    /// This is not a route-table lookup or proof of firewall/router permission.
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
    /// Services the computer advertises in its signed record, at these candidates.
    #[serde(default)]
    pub services: Vec<ServiceRow>,
}

impl From<&crate::record::ServiceAdvert> for ServiceRow {
    fn from(advert: &crate::record::ServiceAdvert) -> Self {
        Self {
            name: advert.name.as_str().to_owned(),
            port: advert.port,
            key_pin: advert.key_pin_hex(),
        }
    }
}
