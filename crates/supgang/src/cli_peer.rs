//! Peer-contact CLI operations kept separate from argument and rendering policy.

use std::{path::Path, str::FromStr, time::SystemTime};

use ed25519_dalek::VerifyingKey;
use serde::Serialize;

use crate::{
    artifact,
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
    contact::{MAX_CONTACT_BYTES, PeerContact, decode_contact, encode_contact},
    endpoint_config::EndpointConfig,
    ids::NodeId,
    network::InterfaceNetwork,
    peer_directory::{ImportDecision, PeerDirectory},
    peer_tag, profile,
    record::{Capabilities, EndpointClaims},
    state, transport_storage,
};

pub use crate::cli_peer_types::{PeerRow, PeersOutput, ResolveOutput, ResolvedCandidate, ServiceRow};

mod resolution;

#[cfg(test)]
use resolution::resolved_candidates;
use resolution::{resolved_peer_candidates, resolved_with_preference};

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

/// One exact or significant local selector match in descending relevance.
#[derive(Clone, Debug, Serialize)]
pub struct PeerSelectorMatch {
    pub node_id: NodeId,
    pub score: u8,
    pub matched_by: &'static str,
    pub exact: bool,
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
    for address in endpoints.mapped() {
        candidates.push(
            EndpointCandidate::new(CandidateKind::Mapped, CandidateTransport::QuicV1, *address)
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
            EndpointClaims {
                candidates,
                capabilities: Capabilities::NONE,
                services: profile::services(state_directory).map_err(|error| error.to_string())?,
            },
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
    let mut result = peers_from_directory(&directory, &root_key, unix_time()?, this_computer);
    apply_tags(state_directory, &mut result)?;
    Ok(result)
}

/// Reads the peer summary without creating a missing local profile.
pub fn peers_read_only(state_directory: &Path) -> Result<PeersOutput, String> {
    let local_state = state::open_read_only(state_directory).map_err(|error| error.to_string())?;
    let root_key = local_state.identity().root_verifying_key;
    let this_computer = stopped_local_row_read_only(state_directory, &local_state)?;
    let directory = PeerDirectory::open_read_only(
        state_directory,
        root_key,
        local_state.identity().device.node_id(),
        local_state.revocations(),
    )
    .map_err(|error| error.to_string())?;
    let mut result = peers_from_directory(&directory, &root_key, unix_time()?, this_computer);
    apply_tags(state_directory, &mut result)?;
    Ok(result)
}

/// Resolves a peer from validating snapshots without repairing durable state.
pub fn resolve_read_only(state_directory: &Path, selector: &str) -> Result<ResolveOutput, String> {
    let local_state = state::open_read_only(state_directory).map_err(|error| error.to_string())?;
    let directory = PeerDirectory::open_read_only(
        state_directory,
        local_state.identity().root_verifying_key,
        local_state.identity().device.node_id(),
        local_state.revocations(),
    )
    .map_err(|error| error.to_string())?;
    let mut rows = peer_rows_from_directory(&directory, &local_state.identity().root_verifying_key, unix_time()?);
    apply_tags_to_rows(state_directory, &mut rows)?;
    let node_id = resolve_selector_from_rows(&rows, selector)?;
    let mut result = resolve_from_directory(&directory, node_id, unix_time()?)?;
    apply_tags_to_resolve(state_directory, &mut result)?;
    Ok(result)
}

pub fn peers_from_directory(
    directory: &PeerDirectory,
    root_key: &VerifyingKey,
    now: u64,
    this_computer: PeerRow,
) -> PeersOutput {
    PeersOutput {
        schema: "supgang.peers/v6".to_owned(),
        status: "ok".to_owned(),
        this_computer: Some(this_computer),
        peers: peer_rows_from_directory(directory, root_key, now),
    }
}

fn peer_rows_from_directory(directory: &PeerDirectory, root_key: &VerifyingKey, now: u64) -> Vec<PeerRow> {
    let local_networks = crate::network::interface_networks().unwrap_or_default();
    directory
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
            let addresses = resolved_peer_candidates(
                directory,
                *node_id,
                &record.candidates,
                &local_networks,
                now,
                status == "fresh" && !entry.is_conflicted(),
            );
            PeerRow {
                name,
                name_source: name_source.to_owned(),
                tags: Vec::new(),
                fingerprint: short_fingerprint(*node_id),
                node_id: node_id.to_string(),
                connected: None,
                status: status.to_owned(),
                generation: record.generation,
                sequence: record.sequence,
                expires_at: record.expires_at,
                candidate_count: addresses.len(),
                addresses,
                services: record.services.iter().map(Into::into).collect(),
            }
        })
        .collect()
}

pub fn running_local_row(contact: &PeerContact) -> PeerRow {
    let record = &contact.endpoint.record;
    let local_networks = crate::network::interface_networks().unwrap_or_default();
    let preferred_index = self_preferred_index(&record.candidates, &local_networks);
    PeerRow {
        name: record.display_name.as_ref().map_or_else(
            || format!("computer-{}", short_fingerprint(record.node_id)),
            ToString::to_string,
        ),
        name_source: "device-signed".to_owned(),
        tags: Vec::new(),
        fingerprint: short_fingerprint(record.node_id),
        node_id: record.node_id.to_string(),
        connected: Some(true),
        status: "running".to_owned(),
        generation: record.generation,
        sequence: record.sequence,
        expires_at: record.expires_at,
        candidate_count: record.candidates.len(),
        addresses: resolved_with_preference(&record.candidates, preferred_index, "device-signed", &local_networks),
        services: record.services.iter().map(Into::into).collect(),
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
    let mut rows = peer_rows_from_directory(&directory, &local_state.identity().root_verifying_key, unix_time()?);
    apply_tags_to_rows(state_directory, &mut rows)?;
    let node_id = resolve_selector_from_rows(&rows, selector)?;
    let mut result = resolve_from_directory(&directory, node_id, unix_time()?)?;
    apply_tags_to_resolve(state_directory, &mut result)?;
    Ok(result)
}

pub fn resolve_from_directory(directory: &PeerDirectory, node_id: NodeId, now: u64) -> Result<ResolveOutput, String> {
    let contact = directory
        .usable(&node_id, now)
        .ok_or_else(|| "peer has no fresh, non-conflicted signed endpoint record".to_owned())?;
    let record = &contact.endpoint.record;
    let local_networks = crate::network::interface_networks().unwrap_or_default();
    let candidates = resolved_peer_candidates(directory, node_id, &record.candidates, &local_networks, now, true);
    let (name, _source) = display_name(record.display_name.as_ref(), node_id);
    Ok(ResolveOutput {
        schema: "supgang.resolve/v5".to_owned(),
        status: "ok".to_owned(),
        node_id: node_id.to_string(),
        name,
        tags: Vec::new(),
        fingerprint: short_fingerprint(node_id),
        generation: record.generation,
        sequence: record.sequence,
        issued_at: record.issued_at,
        expires_at: record.expires_at,
        candidates,
        services: record.services.iter().map(Into::into).collect(),
    })
}

/// Resolves an exact or uniquely significant peer selector.
pub fn resolve_selector_from_rows(rows: &[PeerRow], selector: &str) -> Result<NodeId, String> {
    let candidates = selector_matches_from_rows(rows, selector)?;
    match candidates.as_slice() {
        [selected] => Ok(selected.node_id),
        [] => Err("no known peer significantly matches that name, tag, or fingerprint".to_owned()),
        _ => Err(format!(
            "{} peers match; run `supgang {selector}` to inspect them, then use a tag or fingerprint",
            candidates.len()
        )),
    }
}

/// Returns every exact match, or every significantly ranked fuzzy match.
pub fn selector_matches_from_rows(rows: &[PeerRow], selector: &str) -> Result<Vec<PeerSelectorMatch>, String> {
    if let Ok(node_id) = NodeId::from_str(selector) {
        return rows
            .iter()
            .any(|row| row.node_id == node_id.to_string())
            .then_some(vec![PeerSelectorMatch {
                node_id,
                score: 100,
                matched_by: "node-id",
                exact: true,
            }])
            .ok_or_else(|| "no known peer matches that node ID".to_owned());
    }
    if selector.len() < 2 || selector.len() > crate::profile::MAX_PEER_NAME_BYTES || !selector.is_ascii() {
        return Err("peer selector must be 2 through 63 ASCII characters, or a full node ID".to_owned());
    }
    let normalized = selector.to_ascii_lowercase();
    let mut exact_tags = rows
        .iter()
        .filter(|row| row.tags.iter().any(|tag| tag.eq_ignore_ascii_case(selector)))
        .filter_map(|row| {
            Some(PeerSelectorMatch {
                node_id: NodeId::from_str(&row.node_id).ok()?,
                score: 100,
                matched_by: "tag",
                exact: true,
            })
        })
        .collect::<Vec<_>>();
    if !exact_tags.is_empty() {
        sort_selector_matches(&mut exact_tags, rows);
        return Ok(exact_tags);
    }
    let mut exact = rows
        .iter()
        .filter_map(|row| exact_match(row, selector, &normalized))
        .collect::<Vec<_>>();
    if !exact.is_empty() {
        sort_selector_matches(&mut exact, rows);
        return Ok(exact);
    }
    let mut fuzzy = rows
        .iter()
        .filter_map(|row| fuzzy_match(row, &normalized))
        .collect::<Vec<_>>();
    sort_selector_matches(&mut fuzzy, rows);
    Ok(fuzzy)
}

fn exact_match(row: &PeerRow, selector: &str, normalized: &str) -> Option<PeerSelectorMatch> {
    let (matched_by, matches) = if row.name.eq_ignore_ascii_case(selector) {
        ("name", true)
    } else {
        (
            "fingerprint",
            selector.len() >= 8 && row.node_id.starts_with(normalized),
        )
    };
    if !matches {
        return None;
    }
    Some(PeerSelectorMatch {
        node_id: NodeId::from_str(&row.node_id).ok()?,
        score: 100,
        matched_by,
        exact: true,
    })
}

fn fuzzy_match(row: &PeerRow, normalized: &str) -> Option<PeerSelectorMatch> {
    let name = fuzzy_text_score(&row.name.to_ascii_lowercase(), normalized).map(|score| (score, "name"));
    let tag = row
        .tags
        .iter()
        .filter_map(|tag| fuzzy_text_score(&tag.to_ascii_lowercase(), normalized))
        .max()
        .map(|score| (score, "tag"));
    let (score, matched_by) = match (name, tag) {
        (Some(name), Some(tag)) => {
            if tag.0 >= name.0 {
                tag
            } else {
                name
            }
        }
        (Some(value), None) | (None, Some(value)) => value,
        (None, None) => return None,
    };
    Some(PeerSelectorMatch {
        node_id: NodeId::from_str(&row.node_id).ok()?,
        score,
        matched_by,
        exact: false,
    })
}

fn fuzzy_text_score(candidate: &str, query: &str) -> Option<u8> {
    if candidate.starts_with(query) {
        return Some(95_u8.saturating_sub(length_penalty(candidate, query)));
    }
    if query.len() >= 3
        && let Some(position) = candidate.find(query)
    {
        return Some(85_u8.saturating_sub(u8::try_from(position).unwrap_or(u8::MAX).min(10)));
    }
    let maximum_distance = match query.len() {
        0..=4 => 1,
        5..=8 => 2,
        _ => 3,
    };
    let distance = bounded_edit_distance(candidate.as_bytes(), query.as_bytes(), maximum_distance)?;
    Some(
        75_u8
            .saturating_sub(u8::try_from(distance).unwrap_or(u8::MAX).saturating_mul(10))
            .saturating_sub(length_penalty(candidate, query)),
    )
}

fn length_penalty(candidate: &str, query: &str) -> u8 {
    u8::try_from(candidate.len().abs_diff(query.len()))
        .unwrap_or(u8::MAX)
        .min(15)
}

fn bounded_edit_distance(left: &[u8], right: &[u8], maximum: usize) -> Option<usize> {
    if left.len().abs_diff(right.len()) > maximum {
        return None;
    }
    let mut previous = (0..=right.len()).collect::<Vec<_>>();
    let mut current = vec![0; right.len().saturating_add(1)];
    for (left_index, left_byte) in left.iter().enumerate() {
        let first = left_index.saturating_add(1);
        *current.first_mut()? = first;
        let mut row_minimum = first;
        for (right_index, right_byte) in right.iter().enumerate() {
            let next_index = right_index.saturating_add(1);
            let substitution = previous
                .get(right_index)?
                .saturating_add(usize::from(left_byte != right_byte));
            let insertion = current.get(right_index)?.saturating_add(1);
            let deletion = previous.get(next_index)?.saturating_add(1);
            let next = substitution.min(insertion).min(deletion);
            *current.get_mut(next_index)? = next;
            row_minimum = row_minimum.min(next);
        }
        if row_minimum > maximum {
            return None;
        }
        core::mem::swap(&mut previous, &mut current);
    }
    let distance = *previous.get(right.len())?;
    (distance <= maximum).then_some(distance)
}

fn sort_selector_matches(matches: &mut [PeerSelectorMatch], rows: &[PeerRow]) {
    matches.sort_by(|left, right| {
        right.score.cmp(&left.score).then_with(|| {
            let left_name = rows
                .iter()
                .find(|row| row.node_id == left.node_id.to_string())
                .map_or("", |row| row.name.as_str());
            let right_name = rows
                .iter()
                .find(|row| row.node_id == right.node_id.to_string())
                .map_or("", |row| row.name.as_str());
            left_name
                .to_ascii_lowercase()
                .cmp(&right_name.to_ascii_lowercase())
                .then_with(|| left.node_id.cmp(&right.node_id))
        })
    });
}

/// Applies validated local tags to a fleet snapshot from any source.
pub fn apply_tags(state_directory: &Path, result: &mut PeersOutput) -> Result<(), String> {
    apply_tags_to_rows(state_directory, &mut result.peers)
}

/// Applies validated local tags to peer rows from a daemon or immutable snapshot.
pub fn apply_tags_to_rows(state_directory: &Path, rows: &mut [PeerRow]) -> Result<(), String> {
    let tags = peer_tag::load(state_directory).map_err(|error| error.to_string())?;
    for row in rows {
        let node_id = NodeId::from_str(&row.node_id).map_err(|_| "peer row contains an invalid node ID".to_owned())?;
        row.tags = tags.for_peer(&node_id);
    }
    Ok(())
}

/// Applies validated local tags to a resolved peer from any source.
pub fn apply_tags_to_resolve(state_directory: &Path, result: &mut ResolveOutput) -> Result<(), String> {
    let node_id =
        NodeId::from_str(&result.node_id).map_err(|_| "resolved peer contains an invalid node ID".to_owned())?;
    result.tags = peer_tag::load(state_directory)
        .map_err(|error| error.to_string())?
        .for_peer(&node_id);
    Ok(())
}

fn stopped_local_row(state_directory: &Path, local_state: &state::LocalState) -> Result<PeerRow, String> {
    let node_id = local_state.identity().device.node_id();
    let name = profile::load_or_create(state_directory, node_id).map_err(|error| error.to_string())?;
    let services = profile::services(state_directory).map_err(|error| error.to_string())?;
    Ok(stopped_local_row_with_name(local_state, &name, &services))
}

fn stopped_local_row_read_only(state_directory: &Path, local_state: &state::LocalState) -> Result<PeerRow, String> {
    let name = profile::load(state_directory).map_err(|error| error.to_string())?;
    let services = profile::services(state_directory).map_err(|error| error.to_string())?;
    Ok(stopped_local_row_with_name(local_state, &name, &services))
}

fn stopped_local_row_with_name(
    local_state: &state::LocalState,
    name: &profile::PeerName,
    services: &[crate::record::ServiceAdvert],
) -> PeerRow {
    let node_id = local_state.identity().device.node_id();
    let candidates = EndpointConfig::automatic(crate::endpoint_config::DEFAULT_PORT)
        .map(|config| candidates_from_config(&config))
        .unwrap_or_default();
    let local_networks = crate::network::interface_networks().unwrap_or_default();
    let preferred_index = self_preferred_index(&candidates, &local_networks);
    PeerRow {
        name: name.to_string(),
        name_source: "local-profile".to_owned(),
        tags: Vec::new(),
        fingerprint: short_fingerprint(node_id),
        node_id: node_id.to_string(),
        connected: None,
        status: "stopped".to_owned(),
        generation: local_state.generation(),
        sequence: local_state.sequence(),
        expires_at: 0,
        candidate_count: candidates.len(),
        addresses: resolved_with_preference(&candidates, preferred_index, "local-interface", &local_networks),
        services: services.iter().map(Into::into).collect(),
    }
}

fn candidates_from_config(config: &EndpointConfig) -> Vec<EndpointCandidate> {
    config
        .local()
        .iter()
        .filter_map(|address| EndpointCandidate::new(CandidateKind::Local, CandidateTransport::QuicV1, *address).ok())
        .chain(config.direct().iter().filter_map(|address| {
            EndpointCandidate::new(CandidateKind::Direct, CandidateTransport::QuicV1, *address).ok()
        }))
        .chain(config.mapped().iter().filter_map(|address| {
            EndpointCandidate::new(CandidateKind::Mapped, CandidateTransport::QuicV1, *address).ok()
        }))
        .collect()
}

fn self_preferred_index(candidates: &[EndpointCandidate], local_networks: &[InterfaceNetwork]) -> Option<usize> {
    let compatible =
        |candidate: &EndpointCandidate| crate::network::candidate_is_route_compatible(candidate, local_networks);
    candidates
        .iter()
        .position(|candidate| {
            compatible(candidate)
                && candidate.kind() == CandidateKind::Local
                && matches!(candidate.address().ip(), std::net::IpAddr::V4(address) if address.is_private())
        })
        .or_else(|| {
            candidates.iter().position(|candidate| {
                compatible(candidate) && candidate.kind() == CandidateKind::Local && candidate.address().is_ipv4()
            })
        })
        .or_else(|| {
            candidates
                .iter()
                .position(|candidate| compatible(candidate) && candidate.kind() == CandidateKind::Local)
        })
        .or_else(|| {
            candidates.iter().position(|candidate| {
                compatible(candidate) && candidate.kind() != CandidateKind::Local && candidate.address().is_ipv4()
            })
        })
        .or_else(|| candidates.iter().position(compatible))
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
        CandidateKind::Reflexive => "device-claimed",
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
mod tests;
