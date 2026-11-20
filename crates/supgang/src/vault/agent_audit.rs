//! Fail-closed, append-only audit segments for agent-purpose keys.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{Lock, VaultError, unix_now, validate_name};
use crate::{
    artifact,
    ids::NodeId,
    storage::{no_follow_flag, sync_directory, validate_owner_file_metadata},
};

const DOMAIN: &[u8] = b"supgang/agent-audit/v1\0";
const LOCK_NAME: &str = "vault-agent-audit.lock";
const HEAD_NAME: &str = "vault-agent-audit.head";
const HEAD_TEMP_NAME: &str = ".vault-agent-audit.head.tmp";
const MAX_HEAD_BYTES: usize = 256;
const MAX_SEGMENTS: usize = 16;
const MAX_SEGMENT_BYTES: usize = 256 * 1024;
const MAX_RECORD_BYTES: usize = 768;
const CREATION_WINDOW_SECONDS: u64 = 24 * 60 * 60;
const MAX_CREATIONS_PER_MEMBER: usize = 8;
const MAX_CREATIONS_PER_HIVE: usize = 32;
const SIGN_WINDOW_SECONDS: u64 = 60 * 60;
const MAX_SIGNS_PER_MEMBER_PURPOSE: usize = 64;
const MAX_SIGNS_PER_PURPOSE: usize = 256;
const MAX_DENIALS_PER_MEMBER: usize = 64;
const MAX_DENIALS_PER_HIVE: usize = 256;
const MAX_LIVE_NONCES: usize = 4096;
const MAX_LIVE_NONCES_PER_MEMBER: usize = 256;
const NONCE_GRACE_SECONDS: u64 = 120;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Action {
    CreateReserved,
    CreateActivated,
    RevokeReserved,
    Sign,
    NonceReserved,
    Denied,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Decision {
    Reserved,
    Authorized,
    Denied,
}

#[derive(Clone, Copy)]
struct Event<'a> {
    requester: NodeId,
    action: Action,
    purpose: &'a str,
    context: Option<&'a str>,
    digest: &'a [u8; 32],
    public_key: Option<&'a [u8; 32]>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Record {
    version: u8,
    sequence: u64,
    previous: String,
    requester: NodeId,
    action: Action,
    decision: Decision,
    purpose: String,
    context: Option<String>,
    digest: String,
    fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    at: u64,
    hash: String,
}

#[derive(Deserialize, Serialize)]
struct Head {
    version: u8,
    sequence: u64,
    hash: String,
    at: u64,
}

struct VerifiedRecord {
    hash: [u8; 32],
    creation: Option<(NodeId, u64)>,
    denial: Option<(NodeId, u64)>,
    nonce: Option<(NodeId, [u8; 32], u64, Option<String>)>,
    key_event: Option<KeyEvent>,
    at: u64,
}

type KeyRef = (String, String, String);

enum KeyEvent {
    Reserved(KeyRef, bool),
    Activated(KeyRef),
}

impl Record {
    fn new(sequence: u64, previous: [u8; 32], event: Event<'_>) -> Result<Self, VaultError> {
        validate_name(event.purpose)?;
        if !matches!(
            (event.action, event.context),
            (
                Action::CreateReserved | Action::CreateActivated | Action::RevokeReserved,
                None
            ) | (Action::Sign | Action::NonceReserved | Action::Denied, Some(_))
        ) || (event.public_key.is_none() && !matches!(event.action, Action::Denied))
            || event
                .context
                .is_some_and(|value| super::signing::validate_context(value).is_err())
        {
            return Err(VaultError::InvalidAgentPolicy);
        }
        let mut record = Self {
            version: 1,
            sequence,
            previous: hex::encode(previous),
            requester: event.requester,
            action: event.action,
            decision: match event.action {
                Action::CreateReserved | Action::RevokeReserved | Action::NonceReserved => Decision::Reserved,
                Action::CreateActivated | Action::Sign => Decision::Authorized,
                Action::Denied => Decision::Denied,
            },
            purpose: event.purpose.to_owned(),
            context: event.context.map(str::to_owned),
            digest: hex::encode(event.digest),
            fingerprint: event
                .public_key
                .map_or_else(|| "unknown".to_owned(), |key| hex::encode(Sha256::digest(key))),
            nonce: None,
            expires_at: None,
            at: unix_now(),
            hash: String::new(),
        };
        record.hash = hex::encode(record.compute_hash()?);
        Ok(record)
    }

    fn new_nonce(
        sequence: u64,
        previous: [u8; 32],
        event: Event<'_>,
        nonce: [u8; 32],
        expires_at: u64,
    ) -> Result<Self, VaultError> {
        if !matches!(
            event.action,
            Action::NonceReserved | Action::Denied | Action::CreateReserved
        ) || expires_at < unix_now()
        {
            return Err(VaultError::AgentAudit);
        }
        let mut record = Self::new(sequence, previous, event)?;
        if expires_at < record.at {
            return Err(VaultError::AgentAudit);
        }
        record.nonce = Some(hex::encode(nonce));
        record.expires_at = Some(expires_at);
        record.hash = hex::encode(record.compute_hash()?);
        Ok(record)
    }

    fn compute_hash(&self) -> Result<[u8; 32], VaultError> {
        let mut core = self.clone();
        core.hash.clear();
        let bytes = serde_json::to_vec(&core).map_err(|_| VaultError::AgentAudit)?;
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }

    fn encode(&self) -> Result<Vec<u8>, VaultError> {
        let mut bytes = serde_json::to_vec(self).map_err(|_| VaultError::AgentAudit)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(VaultError::AgentAudit);
        }
        Ok(bytes)
    }

    fn verify(bytes: &[u8], sequence: u64, previous: [u8; 32]) -> Result<VerifiedRecord, VaultError> {
        if bytes.len() > MAX_RECORD_BYTES || bytes.is_empty() {
            return Err(VaultError::AgentAudit);
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|_| VaultError::AgentAudit)?;
        let canonical = serde_json::to_vec(&record).map_err(|_| VaultError::AgentAudit)?;
        if canonical != bytes
            || record.version != 1
            || record.sequence != sequence
            || record.previous != hex::encode(previous)
            || validate_name(&record.purpose).is_err()
            || record
                .context
                .as_deref()
                .is_some_and(|value| super::signing::validate_context(value).is_err())
            || !matches!(
                (record.action, record.context.as_ref()),
                (
                    Action::CreateReserved | Action::CreateActivated | Action::RevokeReserved,
                    None
                ) | (Action::Sign | Action::NonceReserved | Action::Denied, Some(_))
            )
            || !matches!(
                (record.action, record.decision),
                (
                    Action::CreateReserved | Action::RevokeReserved | Action::NonceReserved,
                    Decision::Reserved
                ) | (Action::CreateActivated | Action::Sign, Decision::Authorized)
                    | (Action::Denied, Decision::Denied)
            )
            || (matches!(record.action, Action::NonceReserved | Action::Denied)
                && (record.nonce.is_none() || record.expires_at.is_none()))
            || (matches!(
                record.action,
                Action::CreateActivated | Action::Sign | Action::RevokeReserved
            ) && (record.nonce.is_some() || record.expires_at.is_some()))
            || record.digest.len() != 64
            || (record.fingerprint.len() != 64
                && !(matches!(record.action, Action::Denied) && record.fingerprint == "unknown"))
            || record
                .digest
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
            || (record.fingerprint != "unknown"
                && record
                    .fingerprint
                    .bytes()
                    .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase()))
        {
            return Err(VaultError::AgentAudit);
        }
        let nonce = match (&record.nonce, record.expires_at) {
            (Some(value), Some(expires_at)) => {
                if value.len() != 64
                    || expires_at < record.at
                    || expires_at
                        > record
                            .at
                            .saturating_add(crate::agent_sign_protocol::MAX_REQUEST_LIFETIME_SECONDS)
                {
                    return Err(VaultError::AgentAudit);
                }
                let bytes = hex::decode(value).map_err(|_| VaultError::AgentAudit)?;
                if hex::encode(&bytes) != *value {
                    return Err(VaultError::AgentAudit);
                }
                Some((
                    record.requester,
                    bytes.try_into().map_err(|_| VaultError::AgentAudit)?,
                    expires_at,
                    matches!(record.action, Action::NonceReserved).then(|| record.purpose.clone()),
                ))
            }
            (None, None) => None,
            _ => return Err(VaultError::AgentAudit),
        };
        let hash = record.compute_hash()?;
        if record.hash != hex::encode(hash) {
            return Err(VaultError::AgentAudit);
        }
        let creation = matches!(record.action, Action::CreateReserved).then_some((record.requester, record.at));
        let denial = matches!(record.action, Action::Denied).then_some((record.requester, record.at));
        let key = (
            record.purpose.clone(),
            record.fingerprint.clone(),
            record.digest.clone(),
        );
        let key_event = match record.action {
            Action::CreateReserved => Some(KeyEvent::Reserved(key, record.nonce.is_some())),
            Action::CreateActivated => Some(KeyEvent::Activated(key)),
            _ => None,
        };
        Ok(VerifiedRecord {
            hash,
            creation,
            denial,
            nonce,
            key_event,
            at: record.at,
        })
    }
}

fn segment_name(index: usize) -> String {
    format!("vault-agent-audit-{index:04}.log")
}

fn path_exists(path: &Path) -> Result<bool, VaultError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(VaultError::AgentAudit),
    }
}

fn verify_head(directory: &Path, sequence: u64, hash: [u8; 32], at: u64) -> Result<(), VaultError> {
    if path_exists(&directory.join(HEAD_TEMP_NAME))? {
        return Err(VaultError::AgentAudit);
    }
    let path = directory.join(HEAD_NAME);
    if !path_exists(&path)? {
        return if sequence == 0 {
            Ok(())
        } else {
            Err(VaultError::AgentAudit)
        };
    }
    if sequence == 0 {
        return Err(VaultError::AgentAudit);
    }
    let bytes = artifact::read(&path, MAX_HEAD_BYTES).map_err(|_| VaultError::AgentAudit)?;
    let content = bytes.strip_suffix(b"\n").ok_or(VaultError::AgentAudit)?;
    let head: Head = serde_json::from_slice(content).map_err(|_| VaultError::AgentAudit)?;
    if serde_json::to_vec(&head).map_err(|_| VaultError::AgentAudit)? != content
        || head.version != 1
        || head.sequence != sequence
        || head.hash != hex::encode(hash)
        || head.at != at
    {
        return Err(VaultError::AgentAudit);
    }
    Ok(())
}

fn write_head(directory: &Path, sequence: u64, hash: [u8; 32], at: u64) -> Result<(), VaultError> {
    let head = Head {
        version: 1,
        sequence,
        hash: hex::encode(hash),
        at,
    };
    let mut bytes = serde_json::to_vec(&head).map_err(|_| VaultError::AgentAudit)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_HEAD_BYTES {
        return Err(VaultError::AgentAudit);
    }
    let temporary = directory.join(HEAD_TEMP_NAME);
    artifact::write_new(&temporary, &bytes, MAX_HEAD_BYTES).map_err(|_| VaultError::AgentAudit)?;
    fs::rename(temporary, directory.join(HEAD_NAME)).map_err(|_| VaultError::AgentAudit)?;
    sync_directory(directory).map_err(|_| VaultError::AgentAudit)?;
    Ok(())
}

struct Scan {
    sequence: u64,
    hash: [u8; 32],
    last: Option<usize>,
    last_bytes: usize,
    last_at: u64,
    recent_creators: Vec<NodeId>,
    used_nonces: BTreeSet<[u8; 32]>,
    live_nonce_members: Vec<NodeId>,
    recent_signs: Vec<(NodeId, String)>,
    recent_denials: Vec<NodeId>,
    created_keys: BTreeMap<KeyRef, bool>,
}

fn scan(directory: &Path) -> Result<Scan, VaultError> {
    let mut sequence = 0_u64;
    let mut hash = [0_u8; 32];
    let mut last = None;
    let mut last_bytes = 0;
    let mut last_at = 0;
    let mut gap = false;
    let mut recent_creators = Vec::new();
    let mut used_nonces = BTreeSet::new();
    let mut live_nonce_members = Vec::new();
    let mut recent_signs = Vec::new();
    let mut recent_denials = Vec::new();
    let mut created_keys = BTreeMap::new();
    let now = unix_now();
    let cutoff = now.saturating_sub(CREATION_WINDOW_SECONDS);
    for index in 0..MAX_SEGMENTS {
        let path = directory.join(segment_name(index));
        match fs::symlink_metadata(&path) {
            Ok(_) if gap => return Err(VaultError::AgentAudit),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                gap = true;
                continue;
            }
            Err(_) => return Err(VaultError::AgentAudit),
        }
        let bytes = artifact::read(&path, MAX_SEGMENT_BYTES).map_err(|_| VaultError::AgentAudit)?;
        let content = bytes.strip_suffix(b"\n").ok_or(VaultError::AgentAudit)?;
        for line in content.split(|byte| *byte == b'\n') {
            sequence = sequence.checked_add(1).ok_or(VaultError::AgentAudit)?;
            let verified = Record::verify(line, sequence, hash)?;
            if let Some(key_event) = verified.key_event {
                match key_event {
                    KeyEvent::Reserved(key, remote) => {
                        if created_keys.insert(key, !remote).is_some() {
                            return Err(VaultError::AgentAudit);
                        }
                    }
                    KeyEvent::Activated(key) => {
                        let active = created_keys.get_mut(&key).ok_or(VaultError::AgentAudit)?;
                        if *active {
                            return Err(VaultError::AgentAudit);
                        }
                        *active = true;
                    }
                }
            }
            if verified.at < last_at || verified.at > now {
                return Err(VaultError::AgentAudit);
            }
            last_at = verified.at;
            hash = verified.hash;
            if let Some((requester, at)) = verified.creation
                && at >= cutoff
            {
                recent_creators.push(requester);
            }
            if let Some((requester, at)) = verified.denial
                && at >= now.saturating_sub(SIGN_WINDOW_SECONDS)
            {
                recent_denials.push(requester);
                if recent_denials.len() > MAX_DENIALS_PER_HIVE {
                    return Err(VaultError::AgentAudit);
                }
            }
            if let Some((requester, nonce, expires_at, sign_purpose)) = verified.nonce {
                if !used_nonces.insert(nonce) {
                    return Err(VaultError::AgentAudit);
                }
                if expires_at.saturating_add(NONCE_GRACE_SECONDS) >= now {
                    live_nonce_members.push(requester);
                    if live_nonce_members.len() > MAX_LIVE_NONCES {
                        return Err(VaultError::AgentAudit);
                    }
                    if live_nonce_members.iter().filter(|member| **member == requester).count()
                        > MAX_LIVE_NONCES_PER_MEMBER
                    {
                        return Err(VaultError::AgentAudit);
                    }
                }
                if let Some(purpose) = sign_purpose
                    && verified.at >= now.saturating_sub(SIGN_WINDOW_SECONDS)
                {
                    recent_signs.push((requester, purpose));
                }
            }
        }
        last = Some(index);
        last_bytes = bytes.len();
    }
    if path_exists(&directory.join(segment_name(MAX_SEGMENTS)))? {
        return Err(VaultError::AgentAudit);
    }
    verify_head(directory, sequence, hash, last_at)?;
    Ok(Scan {
        sequence,
        hash,
        last,
        last_bytes,
        last_at,
        recent_creators,
        used_nonces,
        live_nonce_members,
        recent_signs,
        recent_denials,
        created_keys,
    })
}

fn append(
    directory: &Path,
    event: Event<'_>,
    require_existing: bool,
    nonce: Option<([u8; 32], u64)>,
) -> Result<(), VaultError> {
    let _lock = Lock::open(directory, LOCK_NAME, false).map_err(|_| VaultError::AgentAudit)?;
    let state = scan(directory)?;
    if require_existing && state.sequence == 0 {
        return Err(VaultError::AgentAudit);
    }
    if matches!(event.action, Action::CreateActivated) && state.created_keys.get(&key_ref(&event)?) != Some(&false) {
        return Err(VaultError::AgentAudit);
    }
    if matches!(event.action, Action::CreateReserved)
        && (state.recent_creators.len() >= MAX_CREATIONS_PER_HIVE
            || state
                .recent_creators
                .iter()
                .filter(|creator| **creator == event.requester)
                .count()
                >= MAX_CREATIONS_PER_MEMBER)
    {
        return Err(VaultError::AgentKeyCreationLimit);
    }
    if matches!(event.action, Action::Denied)
        && (state.recent_denials.len() >= MAX_DENIALS_PER_HIVE
            || state
                .recent_denials
                .iter()
                .filter(|member| **member == event.requester)
                .count()
                >= MAX_DENIALS_PER_MEMBER)
    {
        return Err(VaultError::AgentDenialLimit);
    }
    if let Some((value, expires_at)) = nonce {
        let now = unix_now();
        if !matches!(
            event.action,
            Action::NonceReserved | Action::Denied | Action::CreateReserved
        ) || expires_at < now
            || expires_at > now.saturating_add(crate::agent_sign_protocol::MAX_REQUEST_LIFETIME_SECONDS)
        {
            return Err(VaultError::AgentAudit);
        }
        if state.used_nonces.contains(&value) {
            return Err(VaultError::AgentNonceReplay);
        }
        if state.live_nonce_members.len() >= MAX_LIVE_NONCES
            || state
                .live_nonce_members
                .iter()
                .filter(|requester| **requester == event.requester)
                .count()
                >= MAX_LIVE_NONCES_PER_MEMBER
        {
            return Err(VaultError::AgentNonceLimit);
        }
        if matches!(event.action, Action::NonceReserved) {
            let per_purpose = state
                .recent_signs
                .iter()
                .filter(|(_, purpose)| purpose == event.purpose)
                .count();
            let per_member = state
                .recent_signs
                .iter()
                .filter(|(requester, purpose)| *requester == event.requester && purpose == event.purpose)
                .count();
            if per_purpose >= MAX_SIGNS_PER_PURPOSE || per_member >= MAX_SIGNS_PER_MEMBER_PURPOSE {
                return Err(VaultError::AgentSignLimit);
            }
        }
    } else if matches!(event.action, Action::NonceReserved | Action::Denied) {
        return Err(VaultError::AgentAudit);
    }
    let sequence = state.sequence.checked_add(1).ok_or(VaultError::AgentAudit)?;
    let record = if let Some((value, expires_at)) = nonce {
        Record::new_nonce(sequence, state.hash, event, value, expires_at)?
    } else {
        Record::new(sequence, state.hash, event)?
    };
    if record.at < state.last_at {
        return Err(VaultError::AgentAudit);
    }
    let hash = record.compute_hash()?;
    let line = record.encode()?;
    let (index, fresh) = match state.last {
        None => (0, true),
        Some(index) if state.last_bytes + line.len() <= MAX_SEGMENT_BYTES => (index, false),
        Some(index) if index + 1 < MAX_SEGMENTS => (index + 1, true),
        Some(_) => return Err(VaultError::AgentAuditFull),
    };
    let path = directory.join(segment_name(index));
    if fresh {
        artifact::write_new(&path, &line, MAX_SEGMENT_BYTES).map_err(|_| VaultError::AgentAudit)?;
    } else {
        let mut file = OpenOptions::new()
            .append(true)
            .custom_flags(no_follow_flag().map_err(|_| VaultError::AgentAudit)?)
            .open(&path)
            .map_err(|_| VaultError::AgentAudit)?;
        validate_owner_file_metadata(&file).map_err(|_| VaultError::AgentAudit)?;
        if usize::try_from(file.metadata().map_err(|_| VaultError::AgentAudit)?.len())
            .map_err(|_| VaultError::AgentAudit)?
            != state.last_bytes
        {
            return Err(VaultError::AgentAudit);
        }
        file.write_all(&line).map_err(|_| VaultError::AgentAudit)?;
        file.sync_all().map_err(|_| VaultError::AgentAudit)?;
        sync_directory(directory).map_err(|_| VaultError::AgentAudit)?;
    }
    write_head(directory, sequence, hash, record.at)?;
    Ok(())
}

fn key_ref(event: &Event<'_>) -> Result<KeyRef, VaultError> {
    let public_key = event.public_key.ok_or(VaultError::AgentAudit)?;
    Ok((
        event.purpose.to_owned(),
        hex::encode(Sha256::digest(public_key)),
        hex::encode(event.digest),
    ))
}

/// Refuses replay before the key-opening read audit. The caller holds the
/// vault lock through the later durable nonce reservation.
mod operations;
pub(super) use operations::{
    create_activated, create_reserved, denied, ensure_activated, preflight_creation_nonce, preflight_nonce,
    reserve_nonce, revoke_reserved, signed,
};

#[cfg(test)]
mod tests;
