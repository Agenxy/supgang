//! Peer-contact CLI operations kept separate from argument and rendering policy.

use std::{path::Path, time::SystemTime};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::{
    artifact,
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
    contact::{MAX_CONTACT_BYTES, PeerContact, decode_contact, encode_contact},
    endpoint_config::EndpointConfig,
    ids::NodeId,
    peer_directory::{ImportDecision, PeerDirectory},
    record::Capabilities,
    state, transport_storage,
};

/// Machine-readable result of publishing this computer's signed contact.
#[derive(Debug, Serialize)]
pub struct PublishOutput {
    pub schema: &'static str,
    pub status: &'static str,
    pub node_id: String,
    pub sequence: u64,
    pub expires_at: u64,
    pub candidate_count: usize,
}

/// Machine-readable result of importing one signed peer contact.
#[derive(Debug, Serialize)]
pub struct ImportOutput {
    pub schema: &'static str,
    pub status: &'static str,
    pub node_id: String,
    pub decision: &'static str,
}

/// A non-secret row returned by `peers`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PeerRow {
    pub node_id: String,
    pub status: String,
    pub generation: u64,
    pub sequence: u64,
    pub expires_at: u64,
    pub candidate_count: usize,
}

/// Machine-readable peer-directory summary.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PeersOutput {
    pub schema: String,
    pub status: String,
    pub peers: Vec<PeerRow>,
}

/// One explicitly requested address candidate.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResolvedCandidate {
    pub kind: String,
    pub transport: String,
    pub address: String,
}

/// Machine-readable address resolution with signed-record provenance.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResolveOutput {
    pub schema: String,
    pub status: String,
    pub node_id: String,
    pub generation: u64,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub candidates: Vec<ResolvedCandidate>,
}

pub fn publish(
    state_directory: &Path,
    output_path: &Path,
    endpoint_path: &Path,
    lifetime_hours: u16,
) -> Result<PublishOutput, String> {
    if !(1..=168).contains(&lifetime_hours) {
        return Err("contact lifetime must be from 1 through 168 hours".to_owned());
    }
    let endpoints = EndpointConfig::read(endpoint_path)?;
    let mut candidates = Vec::with_capacity(endpoints.local().len().saturating_add(endpoints.direct().len()));
    for address in endpoints.local() {
        candidates.push(
            EndpointCandidate::new(CandidateKind::Local, CandidateTransport::QuicV1, *address)
                .map_err(|error| error.to_string())?,
        );
    }
    for address in endpoints.direct() {
        candidates.push(
            EndpointCandidate::new(CandidateKind::Direct, CandidateTransport::QuicV1, *address)
                .map_err(|error| error.to_string())?,
        );
    }
    let now = unix_time()?;
    let expires_at = now.saturating_add(u64::from(lifetime_hours) * 60 * 60);
    let transport = transport_storage::load_or_create(state_directory).map_err(|error| error.to_string())?;
    let mut local_state = state::open(state_directory).map_err(|error| error.to_string())?;
    let membership = local_state
        .local_membership()
        .cloned()
        .ok_or_else(|| "local membership is missing".to_owned())?;
    let endpoint = local_state
        .sign_endpoint_record(transport.key_id(), candidates, Capabilities::NONE, now, expires_at)
        .map_err(|error| error.to_string())?;
    let contact = PeerContact { membership, endpoint };
    contact
        .verify(&local_state.identity().root_verifying_key, now)
        .map_err(|error| error.to_string())?;
    let encoded = encode_contact(&contact).map_err(|error| error.to_string())?;
    artifact::write_new(output_path, &encoded, MAX_CONTACT_BYTES).map_err(|error| error.to_string())?;
    Ok(PublishOutput {
        schema: "supgang.publish/v1",
        status: "ok",
        node_id: contact.endpoint.record.node_id.to_string(),
        sequence: contact.endpoint.record.sequence,
        expires_at,
        candidate_count: contact.endpoint.record.candidates.len(),
    })
}

pub fn import(state_directory: &Path, input_path: &Path) -> Result<ImportOutput, String> {
    let bytes = artifact::read(input_path, MAX_CONTACT_BYTES).map_err(|error| error.to_string())?;
    let contact = decode_contact(&bytes).map_err(|error| error.to_string())?;
    let local_state = state::open(state_directory).map_err(|error| error.to_string())?;
    let node_id = contact.endpoint.record.node_id;
    let mut directory = PeerDirectory::open(
        state_directory,
        local_state.identity().root_verifying_key,
        local_state.identity().device.node_id(),
        local_state.revocations(),
    )
    .map_err(|error| error.to_string())?;
    let decision = directory
        .import(contact, unix_time()?)
        .map_err(|error| error.to_string())?;
    Ok(ImportOutput {
        schema: "supgang.import/v1",
        status: "ok",
        node_id: node_id.to_string(),
        decision: decision_name(decision),
    })
}

pub fn peers(state_directory: &Path) -> Result<PeersOutput, String> {
    let local_state = state::open(state_directory).map_err(|error| error.to_string())?;
    let root_key = local_state.identity().root_verifying_key;
    let directory = PeerDirectory::open(
        state_directory,
        root_key,
        local_state.identity().device.node_id(),
        local_state.revocations(),
    )
    .map_err(|error| error.to_string())?;
    Ok(peers_from_directory(&directory, &root_key, unix_time()?))
}

pub fn peers_from_directory(directory: &PeerDirectory, root_key: &VerifyingKey, now: u64) -> PeersOutput {
    let peers = directory
        .entries()
        .iter()
        .map(|(node_id, entry)| {
            let record = &entry.current().endpoint.record;
            PeerRow {
                node_id: node_id.to_string(),
                status: if directory.is_revoked(node_id) {
                    "revoked".to_owned()
                } else if entry.is_conflicted() {
                    "equivocation".to_owned()
                } else if entry.current().verify(root_key, now).is_ok() {
                    "fresh".to_owned()
                } else {
                    "expired".to_owned()
                },
                generation: record.generation,
                sequence: record.sequence,
                expires_at: record.expires_at,
                candidate_count: record.candidates.len(),
            }
        })
        .collect();
    PeersOutput {
        schema: "supgang.peers/v1".to_owned(),
        status: "ok".to_owned(),
        peers,
    }
}

pub fn resolve(state_directory: &Path, node_id: NodeId) -> Result<ResolveOutput, String> {
    let local_state = state::open(state_directory).map_err(|error| error.to_string())?;
    let directory = PeerDirectory::open(
        state_directory,
        local_state.identity().root_verifying_key,
        local_state.identity().device.node_id(),
        local_state.revocations(),
    )
    .map_err(|error| error.to_string())?;
    resolve_from_directory(&directory, node_id, unix_time()?)
}

pub fn resolve_from_directory(directory: &PeerDirectory, node_id: NodeId, now: u64) -> Result<ResolveOutput, String> {
    let contact = directory
        .usable(&node_id, now)
        .ok_or_else(|| "peer has no fresh, non-conflicted signed endpoint record".to_owned())?;
    let record = &contact.endpoint.record;
    let candidates = record
        .candidates
        .iter()
        .map(|candidate| ResolvedCandidate {
            kind: candidate_kind_name(candidate.kind()).to_owned(),
            transport: "quic-v1".to_owned(),
            address: candidate.address().to_string(),
        })
        .collect();
    Ok(ResolveOutput {
        schema: "supgang.resolve/v1".to_owned(),
        status: "ok".to_owned(),
        node_id: node_id.to_string(),
        generation: record.generation,
        sequence: record.sequence,
        issued_at: record.issued_at,
        expires_at: record.expires_at,
        candidates,
    })
}

const fn decision_name(decision: ImportDecision) -> &'static str {
    match decision {
        ImportDecision::AcceptedFirst => "accepted-first",
        ImportDecision::AcceptedNewer => "accepted-newer",
        ImportDecision::Duplicate => "duplicate",
        ImportDecision::RejectedStale => "rejected-stale",
    }
}

const fn candidate_kind_name(kind: CandidateKind) -> &'static str {
    match kind {
        CandidateKind::Local => "local",
        CandidateKind::Direct => "direct",
        CandidateKind::Reflexive => "reflexive",
        CandidateKind::Mapped => "mapped",
        CandidateKind::OwnedRelay => "owned-relay",
    }
}

fn unix_time() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the UNIX epoch".to_owned())
}
