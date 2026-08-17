//! Peer-contact CLI operations kept separate from argument and rendering policy.

use std::{path::Path, str::FromStr, time::SystemTime};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::{
    artifact,
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
    contact::{MAX_CONTACT_BYTES, PeerContact, decode_contact, encode_contact},
    endpoint_config::EndpointConfig,
    ids::NodeId,
    network::InterfaceNetwork,
    peer_directory::{ImportDecision, PeerDirectory},
    profile,
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
    pub name: String,
    pub name_source: String,
    pub fingerprint: String,
    pub node_id: String,
    pub status: String,
    pub generation: u64,
    pub sequence: u64,
    pub expires_at: u64,
    pub candidate_count: usize,
    pub addresses: Vec<ResolvedCandidate>,
}

/// Machine-readable peer-directory summary.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PeersOutput {
    pub schema: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub this_computer: Option<PeerRow>,
    pub peers: Vec<PeerRow>,
}

/// One explicitly requested address candidate.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResolvedCandidate {
    pub scope: String,
    pub kind: String,
    pub transport: String,
    pub address: String,
    pub provenance: String,
    pub preferred: bool,
}

/// Machine-readable address resolution with signed-record provenance.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResolveOutput {
    pub schema: String,
    pub status: String,
    pub node_id: String,
    pub name: String,
    pub fingerprint: String,
    pub generation: u64,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub candidates: Vec<ResolvedCandidate>,
}

pub fn publish(
    state_directory: &Path,
    output_path: &Path,
    endpoint_path: Option<&Path>,
    port: u16,
    lifetime_hours: u16,
) -> Result<PublishOutput, String> {
    if !(1..=168).contains(&lifetime_hours) {
        return Err("contact lifetime must be from 1 through 168 hours".to_owned());
    }
    let endpoints = endpoint_path.map_or_else(|| EndpointConfig::automatic(port), EndpointConfig::read)?;
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
    let display_name = profile::load_or_create(state_directory, local_state.identity().device.node_id())
        .map_err(|error| error.to_string())?;
    let membership = local_state
        .local_membership()
        .cloned()
        .ok_or_else(|| "local membership is missing".to_owned())?;
    let endpoint = local_state
        .sign_endpoint_record(
            display_name,
            transport.key_id(),
            candidates,
            Capabilities::NONE,
            now,
            expires_at,
        )
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
    let this_computer = stopped_local_row(state_directory, &local_state)?;
    let directory = PeerDirectory::open(
        state_directory,
        root_key,
        local_state.identity().device.node_id(),
        local_state.revocations(),
    )
    .map_err(|error| error.to_string())?;
    Ok(peers_from_directory(&directory, &root_key, unix_time()?, this_computer))
}

pub fn peers_from_directory(
    directory: &PeerDirectory,
    root_key: &VerifyingKey,
    now: u64,
    this_computer: PeerRow,
) -> PeersOutput {
    let local_networks = crate::network::interface_networks().unwrap_or_default();
    let peers = directory
        .entries()
        .iter()
        .map(|(node_id, entry)| {
            let record = &entry.current().endpoint.record;
            let (name, name_source) = display_name(record.display_name.as_ref(), *node_id);
            let status = if directory.is_revoked(node_id) {
                "revoked"
            } else if entry.is_conflicted() {
                "equivocation"
            } else if entry.current().verify(root_key, now).is_ok() {
                "fresh"
            } else {
                "expired"
            };
            let addresses = resolved_candidates(&record.candidates, &local_networks, status == "fresh");
            PeerRow {
                name,
                name_source: name_source.to_owned(),
                fingerprint: short_fingerprint(*node_id),
                node_id: node_id.to_string(),
                status: status.to_owned(),
                generation: record.generation,
                sequence: record.sequence,
                expires_at: record.expires_at,
                candidate_count: record.candidates.len(),
                addresses,
            }
        })
        .collect();
    PeersOutput {
        schema: "supgang.peers/v3".to_owned(),
        status: "ok".to_owned(),
        this_computer: Some(this_computer),
        peers,
    }
}

pub fn running_local_row(contact: &PeerContact) -> PeerRow {
    let record = &contact.endpoint.record;
    let preferred_index = self_preferred_index(&record.candidates);
    PeerRow {
        name: record.display_name.as_ref().map_or_else(
            || format!("computer-{}", short_fingerprint(record.node_id)),
            ToString::to_string,
        ),
        name_source: "device-signed".to_owned(),
        fingerprint: short_fingerprint(record.node_id),
        node_id: record.node_id.to_string(),
        status: "running".to_owned(),
        generation: record.generation,
        sequence: record.sequence,
        expires_at: record.expires_at,
        candidate_count: record.candidates.len(),
        addresses: resolved_with_preference(&record.candidates, preferred_index, "device-signed"),
    }
}

pub fn resolve(state_directory: &Path, selector: &str) -> Result<ResolveOutput, String> {
    let local_state = state::open(state_directory).map_err(|error| error.to_string())?;
    let directory = PeerDirectory::open(
        state_directory,
        local_state.identity().root_verifying_key,
        local_state.identity().device.node_id(),
        local_state.revocations(),
    )
    .map_err(|error| error.to_string())?;
    let this_computer = stopped_local_row(state_directory, &local_state)?;
    let rows = peers_from_directory(
        &directory,
        &local_state.identity().root_verifying_key,
        unix_time()?,
        this_computer,
    );
    let node_id = resolve_selector_from_rows(&rows.peers, selector)?;
    resolve_from_directory(&directory, node_id, unix_time()?)
}

pub fn resolve_from_directory(directory: &PeerDirectory, node_id: NodeId, now: u64) -> Result<ResolveOutput, String> {
    let contact = directory
        .usable(&node_id, now)
        .ok_or_else(|| "peer has no fresh, non-conflicted signed endpoint record".to_owned())?;
    let record = &contact.endpoint.record;
    let local_networks = crate::network::interface_networks().unwrap_or_default();
    let candidates = resolved_candidates(&record.candidates, &local_networks, true);
    let (name, _source) = display_name(record.display_name.as_ref(), node_id);
    Ok(ResolveOutput {
        schema: "supgang.resolve/v2".to_owned(),
        status: "ok".to_owned(),
        node_id: node_id.to_string(),
        name,
        fingerprint: short_fingerprint(node_id),
        generation: record.generation,
        sequence: record.sequence,
        issued_at: record.issued_at,
        expires_at: record.expires_at,
        candidates,
    })
}

/// Resolves an exact name, unique fingerprint prefix, or full stable node ID.
pub fn resolve_selector_from_rows(rows: &[PeerRow], selector: &str) -> Result<NodeId, String> {
    if let Ok(node_id) = NodeId::from_str(selector) {
        return rows
            .iter()
            .any(|row| row.node_id == node_id.to_string())
            .then_some(node_id)
            .ok_or_else(|| "no known peer matches that node ID".to_owned());
    }
    if selector.len() < 2 || selector.len() > crate::profile::MAX_PEER_NAME_BYTES {
        return Err("peer selector must be a computer name, fingerprint, or full node ID".to_owned());
    }
    let normalized = selector.to_ascii_lowercase();
    let mut matches = rows
        .iter()
        .filter_map(|row| {
            let name_matches = row.name.eq_ignore_ascii_case(selector);
            let id_matches = selector.len() >= 8 && row.node_id.starts_with(&normalized);
            if name_matches || id_matches {
                NodeId::from_str(&row.node_id).ok()
            } else {
                None
            }
        })
        .take(2)
        .collect::<Vec<_>>();
    match matches.as_mut_slice() {
        [node_id] => Ok(*node_id),
        [] => Err("no known peer matches that computer name or fingerprint".to_owned()),
        _ => Err("peer name or fingerprint is ambiguous; use the longer fingerprint shown by `supgang`".to_owned()),
    }
}

fn resolved_candidates(
    candidates: &[EndpointCandidate],
    local_networks: &[InterfaceNetwork],
    choose_preferred: bool,
) -> Vec<ResolvedCandidate> {
    let preferred_index = choose_preferred
        .then(|| {
            candidates
                .iter()
                .position(|candidate| {
                    candidate.kind() == CandidateKind::Local
                        && local_networks
                            .iter()
                            .any(|network| network.contains(candidate.address().ip()))
                })
                .or_else(|| {
                    candidates
                        .iter()
                        .position(|candidate| candidate.kind() != CandidateKind::Local)
                })
                .or_else(|| (!candidates.is_empty()).then_some(0))
        })
        .flatten();
    resolved_with_preference(candidates, preferred_index, "device-signed")
}

fn resolved_with_preference(
    candidates: &[EndpointCandidate],
    preferred_index: Option<usize>,
    provenance: &str,
) -> Vec<ResolvedCandidate> {
    candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| ResolvedCandidate {
            scope: candidate_scope(candidate.kind()).to_owned(),
            kind: candidate_kind_name(candidate.kind()).to_owned(),
            transport: "quic-v1".to_owned(),
            address: candidate.address().to_string(),
            provenance: provenance.to_owned(),
            preferred: Some(index) == preferred_index,
        })
        .collect()
}

fn stopped_local_row(state_directory: &Path, local_state: &state::LocalState) -> Result<PeerRow, String> {
    let node_id = local_state.identity().device.node_id();
    let name = profile::load_or_create(state_directory, node_id).map_err(|error| error.to_string())?;
    let candidates = EndpointConfig::automatic(crate::endpoint_config::DEFAULT_PORT)
        .map(|config| candidates_from_config(&config))
        .unwrap_or_default();
    let preferred_index = self_preferred_index(&candidates);
    Ok(PeerRow {
        name: name.to_string(),
        name_source: "local-profile".to_owned(),
        fingerprint: short_fingerprint(node_id),
        node_id: node_id.to_string(),
        status: "stopped".to_owned(),
        generation: local_state.generation(),
        sequence: local_state.sequence(),
        expires_at: 0,
        candidate_count: candidates.len(),
        addresses: resolved_with_preference(&candidates, preferred_index, "local-interface"),
    })
}

fn candidates_from_config(config: &EndpointConfig) -> Vec<EndpointCandidate> {
    config
        .local()
        .iter()
        .filter_map(|address| EndpointCandidate::new(CandidateKind::Local, CandidateTransport::QuicV1, *address).ok())
        .chain(config.direct().iter().filter_map(|address| {
            EndpointCandidate::new(CandidateKind::Direct, CandidateTransport::QuicV1, *address).ok()
        }))
        .collect()
}

fn self_preferred_index(candidates: &[EndpointCandidate]) -> Option<usize> {
    candidates
        .iter()
        .position(|candidate| {
            candidate.kind() == CandidateKind::Local
                && matches!(candidate.address().ip(), std::net::IpAddr::V4(address) if address.is_private())
        })
        .or_else(|| {
            candidates
                .iter()
                .position(|candidate| candidate.kind() == CandidateKind::Local && candidate.address().is_ipv4())
        })
        .or_else(|| {
            candidates
                .iter()
                .position(|candidate| candidate.kind() == CandidateKind::Local)
        })
        .or_else(|| {
            candidates
                .iter()
                .position(|candidate| candidate.kind() != CandidateKind::Local && candidate.address().is_ipv4())
        })
        .or_else(|| (!candidates.is_empty()).then_some(0))
}

fn display_name(name: Option<&crate::profile::PeerName>, node_id: NodeId) -> (String, &'static str) {
    name.map_or_else(
        || (format!("computer-{}", short_fingerprint(node_id)), "fallback"),
        |value| (value.as_str().to_owned(), "device-signed"),
    )
}

fn short_fingerprint(node_id: NodeId) -> String {
    node_id.to_string().chars().take(8).collect()
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

const fn candidate_scope(kind: CandidateKind) -> &'static str {
    match kind {
        CandidateKind::Local => "local",
        CandidateKind::Direct | CandidateKind::Reflexive | CandidateKind::Mapped | CandidateKind::OwnedRelay => {
            "public"
        }
    }
}

fn unix_time() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the UNIX epoch".to_owned())
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        str::FromStr,
    };

    use super::{PeerRow, resolve_selector_from_rows, resolved_candidates, self_preferred_index};
    use crate::{
        candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
        ids::NodeId,
        network::InterfaceNetwork,
    };

    fn row(name: &str, byte: u8) -> PeerRow {
        let node_id = NodeId::from_bytes([byte; 32]);
        PeerRow {
            name: name.to_owned(),
            name_source: "device-signed".to_owned(),
            fingerprint: node_id.to_string().chars().take(8).collect(),
            node_id: node_id.to_string(),
            status: "fresh".to_owned(),
            generation: 0,
            sequence: 1,
            expires_at: 100,
            candidate_count: 0,
            addresses: Vec::new(),
        }
    }

    #[test]
    fn names_are_convenient_but_ambiguity_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let first = row("Solis", 1);
        let second = row("Solis", 2);
        assert_eq!(
            resolve_selector_from_rows(std::slice::from_ref(&first), "solis")?,
            NodeId::from_str(&first.node_id)?
        );
        assert!(resolve_selector_from_rows(&[first.clone(), second], "Solis").is_err());
        assert_eq!(
            resolve_selector_from_rows(std::slice::from_ref(&first), &first.fingerprint)?,
            NodeId::from_str(&first.node_id)?
        );
        Ok(())
    }

    #[test]
    fn historical_addresses_are_never_recommended() -> Result<(), Box<dyn std::error::Error>> {
        let candidates = [EndpointCandidate::new(
            CandidateKind::Local,
            CandidateTransport::QuicV1,
            SocketAddr::from(([192, 168, 1, 191], 4_433)),
        )?];
        let networks = [InterfaceNetwork::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
        )];

        let addresses = resolved_candidates(&candidates, &networks, false);
        assert!(addresses.iter().all(|address| !address.preferred));
        Ok(())
    }

    #[test]
    fn this_computer_prefers_a_private_ipv4_interface() -> Result<(), Box<dyn std::error::Error>> {
        let candidates = [
            EndpointCandidate::new(
                CandidateKind::Local,
                CandidateTransport::QuicV1,
                SocketAddr::from(([100, 77, 1, 2], 44_330)),
            )?,
            EndpointCandidate::new(
                CandidateKind::Local,
                CandidateTransport::QuicV1,
                SocketAddr::from(([192, 168, 1, 20], 44_330)),
            )?,
            EndpointCandidate::new(
                CandidateKind::Direct,
                CandidateTransport::QuicV1,
                SocketAddr::from(([8, 8, 8, 8], 44_330)),
            )?,
        ];
        assert_eq!(self_preferred_index(&candidates), Some(1));
        Ok(())
    }
}
