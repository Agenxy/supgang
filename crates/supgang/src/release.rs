//! Build-time release identity, bounded authenticated-session gossip codec,
//! and advisory gang update-notice computation.
//!
//! Peer release reports are self-claimed informational data exchanged only over
//! already mutually authenticated QUIC sessions. They never modify durable
//! state, never authorize or install software, and never block any operation.

use std::{cmp::Ordering, collections::BTreeSet};

use minicbor::{Decoder, Encoder, data::Type, decode as cbor_decode};
use quinn::Connection;
use semver::{Prerelease, Version};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ids::NodeId;

/// Maximum byte length of a `SemVer` version string carried in release gossip.
pub const MAX_RELEASE_VERSION_BYTES: usize = 64;
/// Exact hexadecimal character length of a known Git SHA-1 source commit.
pub const COMMIT_HEX_LEN: usize = 40;
/// Sentinel value used when no source commit was embedded at build time.
pub const UNKNOWN_COMMIT: &str = "unknown";
/// Maximum encoded byte length of one release-identity datagram frame.
pub const MAX_RELEASE_FRAME_BYTES: usize = 160;
/// Maximum distinct newer versions remembered for one-time log deduplication.
pub const MAX_LOGGED_VERSIONS: usize = 64;

const FRAME_VERSION: u8 = 1;
const FRAME_KIND: u8 = 3;
const FRAME_FIELDS: u64 = 4;

/// A release-identity validation, encoding, or datagram-delivery failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReleaseError {
    /// The version string was empty, overlong, non-ASCII, or not valid `SemVer`.
    #[error("release version is invalid or exceeds its 64-byte bound")]
    InvalidVersion,
    /// The source commit was not 40 lowercase hexadecimal characters.
    #[error("release source commit must be 40 lowercase hexadecimal characters")]
    InvalidCommit,
    /// The encoded frame was empty or exceeded the fixed datagram budget.
    #[error("release identity frame exceeds its size limit")]
    Oversized,
    /// The datagram was malformed, non-canonical, or used an unsupported version.
    #[error("release identity frame is invalid")]
    InvalidFrame,
    /// QUIC datagrams were unavailable or the bounded send buffer was full.
    #[error("release identity frame could not be sent")]
    Transport,
}

/// A validated `SemVer` version and optional 40-hex source commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseIdentity {
    version: String,
    commit: Option<String>,
}

impl ReleaseIdentity {
    /// Returns the release identity compiled into this binary.
    #[must_use]
    pub fn local() -> Self {
        let commit = normalize_commit(crate::SOURCE_COMMIT);
        Self {
            version: crate::VERSION.to_owned(),
            commit,
        }
    }

    /// Validates and constructs a release identity.
    ///
    /// # Errors
    ///
    /// Rejects invalid `SemVer`, versions longer than 64 bytes, or commits that
    /// are not exactly 40 lowercase hexadecimal characters.
    pub fn new(version: impl Into<String>, commit: Option<String>) -> Result<Self, ReleaseError> {
        let version = version.into();
        validate_version(&version)?;
        if let Some(ref commit_hex) = commit {
            validate_commit_lowercase(commit_hex)?;
        }
        Ok(Self { version, commit })
    }

    /// Returns the `SemVer` version string.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the 40-character lowercase hex source commit when known.
    #[must_use]
    pub fn commit(&self) -> Option<&str> {
        self.commit.as_deref()
    }

    /// Returns the source commit string, or `"unknown"` when absent.
    #[must_use]
    pub fn commit_str(&self) -> &str {
        self.commit.as_deref().unwrap_or(UNKNOWN_COMMIT)
    }

    /// Returns the 7-character short commit, or `"unknown"` when absent.
    #[must_use]
    pub fn short_commit(&self) -> &str {
        short_commit(self.commit_str())
    }

    /// Formats the human-facing release string, e.g. `0.2.0-alpha.21 (ddf00d8)`.
    #[must_use]
    pub fn display_version(&self) -> String {
        format!("{} ({})", self.version, self.short_commit())
    }

    /// Parses the version as a `semver::Version`.
    #[must_use]
    pub fn semver(&self) -> Option<Version> {
        Version::parse(&self.version).ok()
    }
}

/// Machine-readable version and commit summary for CLI, control, and MCP output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseInfo {
    /// `SemVer` version string.
    pub version: String,
    /// 40-character lowercase hexadecimal source commit, or `"unknown"`.
    pub commit: String,
}

impl From<&ReleaseIdentity> for ReleaseInfo {
    fn from(identity: &ReleaseIdentity) -> Self {
        Self {
            version: identity.version().to_owned(),
            commit: identity.commit_str().to_owned(),
        }
    }
}

/// Outcome of comparing one peer's reported release against the local build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseComparison {
    /// Peer reports a strictly higher `SemVer` precedence.
    PeerNewer,
    /// Peer reports equal `SemVer` precedence and a different known source commit.
    BuildDiffers,
    /// Peer matches local, has an unknown commit at equal version, or is older.
    CurrentOrOlder,
}

/// One connected authenticated peer's reported release identity.
#[derive(Clone, Copy, Debug)]
pub struct PeerReleaseObservation<'a> {
    /// Stable 64-hex node identity.
    pub node_id: NodeId,
    /// Device-signed display name (or fallback label).
    pub name: &'a str,
    /// Peer-reported release identity.
    pub release: &'a ReleaseIdentity,
}

/// One connected authenticated peer named in an [`UpdateNotice`].
///
/// Identifies the peer only by name, short fingerprint, and stable node ID;
/// never carries any IP address or socket candidate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateNoticePeer {
    /// Device-signed display name (or fallback label).
    pub name: String,
    /// Short 8-hex-character fingerprint of `node_id`.
    pub fingerprint: String,
    /// Stable 64-hex-character node identity.
    pub node_id: String,
    /// Peer-reported `SemVer` version.
    pub version: String,
    /// Peer-reported 40-hex commit, or `"unknown"`.
    pub commit: String,
}

/// Advisory release awareness computed from live authenticated gang peers.
///
/// Peer-reported only: never verified by TUF and never triggers an update.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateNotice {
    /// `"update-available"` when a peer reports a strictly higher `SemVer`, or
    /// `"build-differs"` when a peer reports the same `SemVer` with a different commit.
    pub kind: String,
    /// Local `SemVer` version being compared against.
    pub local_version: String,
    /// Local source commit (40 lowercase hex characters or `"unknown"`).
    pub local_commit: String,
    /// Highest strictly newer `SemVer` reported, or the equal version for `"build-differs"`.
    pub peer_version: String,
    /// Plain-language summary naming the version/build difference and peer(s),
    /// never any network address.
    pub summary: String,
    /// Connected authenticated peer(s) reporting this newer release or differing build.
    pub peers: Vec<UpdateNoticePeer>,
}

/// Compares a peer-reported release identity against the local release identity
/// using full `SemVer` 2.0.0 precedence (including prereleases, ignoring build metadata).
#[must_use]
pub fn compare_release(local: &ReleaseIdentity, peer: &ReleaseIdentity) -> ReleaseComparison {
    let (Some(local_ver), Some(peer_ver)) = (local.semver(), peer.semver()) else {
        return ReleaseComparison::CurrentOrOlder;
    };
    match peer_ver.cmp_precedence(&local_ver) {
        Ordering::Greater => ReleaseComparison::PeerNewer,
        Ordering::Equal => match (local.commit(), peer.commit()) {
            (Some(local_commit), Some(peer_commit)) if local_commit != peer_commit => ReleaseComparison::BuildDiffers,
            _ => ReleaseComparison::CurrentOrOlder,
        },
        Ordering::Less => ReleaseComparison::CurrentOrOlder,
    }
}

/// Computes the fleet-wide advisory [`UpdateNotice`] from connected authenticated peers.
///
/// Strictly newer `SemVer` takes precedence over an equal-version differing build.
#[must_use]
pub fn compute_update_notice(local: &ReleaseIdentity, peers: &[PeerReleaseObservation<'_>]) -> Option<UpdateNotice> {
    let local_ver = local.semver()?;
    let mut highest_newer: Option<Version> = None;
    let mut newer_peers: Vec<(NodeId, UpdateNoticePeer)> = Vec::new();
    let mut differing_peers: Vec<(NodeId, UpdateNoticePeer)> = Vec::new();

    for observation in peers {
        let Some(peer_ver) = observation.release.semver() else {
            continue;
        };
        match peer_ver.cmp_precedence(&local_ver) {
            Ordering::Greater => {
                let row = notice_peer(observation);
                match highest_newer.as_ref().map(|current| peer_ver.cmp_precedence(current)) {
                    None | Some(Ordering::Greater) => {
                        highest_newer = Some(peer_ver);
                        newer_peers.clear();
                        newer_peers.push((observation.node_id, row));
                    }
                    Some(Ordering::Equal) => {
                        newer_peers.push((observation.node_id, row));
                    }
                    Some(Ordering::Less) => {}
                }
            }
            Ordering::Equal => {
                if let (Some(local_commit), Some(peer_commit)) = (local.commit(), observation.release.commit())
                    && local_commit != peer_commit
                {
                    differing_peers.push((observation.node_id, notice_peer(observation)));
                }
            }
            Ordering::Less => {}
        }
    }

    if let Some(highest) = highest_newer {
        newer_peers.sort_by_key(|(node_id, _)| *node_id);
        let listed: Vec<UpdateNoticePeer> = newer_peers.into_iter().map(|(_, row)| row).collect();
        let peer_version = listed
            .first()
            .map_or_else(|| highest.to_string(), |first| first.version.clone());
        let names = format_peer_list(&listed);
        let noun = if listed.len() == 1 { "peer" } else { "peers" };
        let verb = if listed.len() == 1 { "reports" } else { "report" };
        let summary = format!(
            "{noun} {names} {verb} newer release {peer_version} (this computer runs {})",
            local.version()
        );
        return Some(UpdateNotice {
            kind: "update-available".to_owned(),
            local_version: local.version().to_owned(),
            local_commit: local.commit_str().to_owned(),
            peer_version,
            summary,
            peers: listed,
        });
    }

    if !differing_peers.is_empty() {
        differing_peers.sort_by_key(|(node_id, _)| *node_id);
        let listed: Vec<UpdateNoticePeer> = differing_peers.into_iter().map(|(_, row)| row).collect();
        let names = format_peer_list_with_commits(&listed);
        let noun = if listed.len() == 1 { "peer" } else { "peers" };
        let summary = format!(
            "build differs: {noun} {names} while this computer runs {}",
            local.display_version()
        );
        return Some(UpdateNotice {
            kind: "build-differs".to_owned(),
            local_version: local.version().to_owned(),
            local_commit: local.commit_str().to_owned(),
            peer_version: local.version().to_owned(),
            summary,
            peers: listed,
        });
    }

    None
}

/// Bounded in-memory deduplication for logging one concise notice per newly
/// seen strictly newer `SemVer` reported by an authenticated peer.
#[derive(Clone, Debug, Default)]
pub struct ReleaseNoticeLog {
    seen: BTreeSet<PrecedenceVersion>,
}

impl ReleaseNoticeLog {
    /// Creates an empty bounded notice log.
    #[must_use]
    pub const fn new() -> Self {
        Self { seen: BTreeSet::new() }
    }

    /// Records a newly seen strictly newer peer version and returns one concise
    /// log line (naming peer display name and short fingerprint, never an
    /// address), or `None` if already logged, equal/older, or at capacity.
    pub fn record_if_new(&mut self, local: &ReleaseIdentity, peer: &PeerReleaseObservation<'_>) -> Option<String> {
        if compare_release(local, peer.release) != ReleaseComparison::PeerNewer {
            return None;
        }
        let key = PrecedenceVersion::from_version(&peer.release.semver()?);
        if self.seen.contains(&key) || self.seen.len() >= MAX_LOGGED_VERSIONS {
            return None;
        }
        self.seen.insert(key);
        let fingerprint = short_fingerprint(peer.node_id);
        Some(format!(
            "supgang: peer {} [{fingerprint}] reports newer release {} (this computer runs {}); updates are manual",
            peer.name,
            peer.release.display_version(),
            local.display_version()
        ))
    }
}

/// Encodes a release identity as a canonical, bounded CBOR datagram frame.
///
/// # Errors
///
/// Returns an error if validation fails or the encoded frame exceeds 160 bytes.
pub fn encode_frame(identity: &ReleaseIdentity) -> Result<Vec<u8>, ReleaseError> {
    validate_version(&identity.version)?;
    if let Some(ref commit_hex) = identity.commit {
        validate_commit_lowercase(commit_hex)?;
    }
    let mut output = Vec::with_capacity(96);
    let mut encoder = Encoder::new(&mut output);
    encoder.array(FRAME_FIELDS).map_err(map_encode)?;
    encoder.u8(FRAME_VERSION).map_err(map_encode)?;
    encoder.u8(FRAME_KIND).map_err(map_encode)?;
    encoder.str(&identity.version).map_err(map_encode)?;
    match identity.commit.as_deref() {
        Some(commit_hex) => encoder.str(commit_hex).map_err(map_encode)?,
        None => encoder.null().map_err(map_encode)?,
    };
    if output.is_empty() || output.len() > MAX_RELEASE_FRAME_BYTES {
        return Err(ReleaseError::Oversized);
    }
    Ok(output)
}

/// Decodes and canonically verifies a bounded release-identity datagram frame.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, non-canonical, unknown-version,
/// invalid-`SemVer`, or invalid-commit frames.
pub fn decode_frame(input: &[u8]) -> Result<ReleaseIdentity, ReleaseError> {
    if input.is_empty() || input.len() > MAX_RELEASE_FRAME_BYTES {
        return Err(ReleaseError::Oversized);
    }
    let mut decoder = Decoder::new(input);
    if decoder.array().map_err(map_decode)? != Some(FRAME_FIELDS)
        || decoder.u8().map_err(map_decode)? != FRAME_VERSION
        || decoder.u8().map_err(map_decode)? != FRAME_KIND
    {
        return Err(ReleaseError::InvalidFrame);
    }
    let version = decoder.str().map_err(map_decode)?.to_owned();
    let commit = match decoder.datatype().map_err(map_decode)? {
        Type::Null => {
            decoder.null().map_err(map_decode)?;
            None
        }
        Type::String => Some(decoder.str().map_err(map_decode)?.to_owned()),
        _ => return Err(ReleaseError::InvalidFrame),
    };
    if decoder.position() != input.len() {
        return Err(ReleaseError::InvalidFrame);
    }
    let identity = ReleaseIdentity::new(version, commit)?;
    if encode_frame(&identity)?.as_slice() != input {
        return Err(ReleaseError::InvalidFrame);
    }
    Ok(identity)
}

/// Sends one bounded release-identity datagram over an authenticated QUIC session.
///
/// # Errors
///
/// Returns an error if encoding fails or the QUIC datagram send queue rejects it.
pub fn send(connection: &Connection, identity: &ReleaseIdentity) -> Result<(), ReleaseError> {
    let frame = encode_frame(identity)?;
    connection
        .send_datagram(frame.into())
        .map_err(|_| ReleaseError::Transport)
}

/// Formats the short 7-character commit display, or `"unknown"` when absent.
#[must_use]
pub fn short_commit(commit: &str) -> &str {
    if commit.len() == COMMIT_HEX_LEN && commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        commit.get(..7).unwrap_or(UNKNOWN_COMMIT)
    } else {
        UNKNOWN_COMMIT
    }
}

/// Normalizes a 40-character hexadecimal commit string to lowercase, returning
/// `None` for `"unknown"` or any invalid input.
#[must_use]
pub fn normalize_commit(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() == COMMIT_HEX_LEN && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(trimmed.to_ascii_lowercase())
    } else {
        None
    }
}

fn validate_version(version: &str) -> Result<(), ReleaseError> {
    if version.is_empty()
        || version.len() > MAX_RELEASE_VERSION_BYTES
        || !version.bytes().all(|byte| byte.is_ascii_graphic())
        || Version::parse(version).is_err()
    {
        return Err(ReleaseError::InvalidVersion);
    }
    Ok(())
}

fn validate_commit_lowercase(commit: &str) -> Result<(), ReleaseError> {
    if commit.len() != COMMIT_HEX_LEN || !commit.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(ReleaseError::InvalidCommit);
    }
    Ok(())
}

fn short_fingerprint(node_id: NodeId) -> String {
    node_id.to_string().chars().take(8).collect()
}

fn notice_peer(observation: &PeerReleaseObservation<'_>) -> UpdateNoticePeer {
    UpdateNoticePeer {
        name: observation.name.to_owned(),
        fingerprint: short_fingerprint(observation.node_id),
        node_id: observation.node_id.to_string(),
        version: observation.release.version().to_owned(),
        commit: observation.release.commit_str().to_owned(),
    }
}

fn format_peer_list(peers: &[UpdateNoticePeer]) -> String {
    peers
        .iter()
        .map(|peer| format!("{} [{}]", peer.name, peer.fingerprint))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_peer_list_with_commits(peers: &[UpdateNoticePeer]) -> String {
    peers
        .iter()
        .map(|peer| {
            format!(
                "{} [{}] ({} {})",
                peer.name,
                peer.fingerprint,
                peer.version,
                short_commit(&peer.commit)
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PrecedenceVersion {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Prerelease,
}

impl PrecedenceVersion {
    fn from_version(version: &Version) -> Self {
        Self {
            major: version.major,
            minor: version.minor,
            patch: version.patch,
            pre: version.pre.clone(),
        }
    }
}

fn map_encode<E>(_: minicbor::encode::Error<E>) -> ReleaseError {
    ReleaseError::InvalidFrame
}

fn map_decode(_: cbor_decode::Error) -> ReleaseError {
    ReleaseError::InvalidFrame
}

#[cfg(test)]
mod tests;
