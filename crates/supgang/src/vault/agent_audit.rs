//! Fail-closed, append-only audit segments for agent-purpose keys.

use std::{
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
const MAX_SEGMENTS: usize = 16;
const MAX_SEGMENT_BYTES: usize = 256 * 1024;
const MAX_RECORD_BYTES: usize = 768;
const CREATION_WINDOW_SECONDS: u64 = 24 * 60 * 60;
const MAX_CREATIONS_PER_MEMBER: usize = 8;
const MAX_CREATIONS_PER_HIVE: usize = 32;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Action {
    CreateReserved,
    RevokeReserved,
    Sign,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Decision {
    Reserved,
    Authorized,
}

#[derive(Clone, Copy)]
struct Event<'a> {
    requester: NodeId,
    action: Action,
    purpose: &'a str,
    context: Option<&'a str>,
    digest: &'a [u8; 32],
    fingerprint: &'a [u8; 32],
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
    at: u64,
    hash: String,
}

struct VerifiedRecord {
    hash: [u8; 32],
    creation: Option<(NodeId, u64)>,
    at: u64,
}

impl Record {
    fn new(sequence: u64, previous: [u8; 32], event: Event<'_>) -> Result<Self, VaultError> {
        validate_name(event.purpose)?;
        if !matches!(
            (event.action, event.context),
            (Action::CreateReserved | Action::RevokeReserved, None) | (Action::Sign, Some(_))
        ) || event
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
                Action::CreateReserved | Action::RevokeReserved => Decision::Reserved,
                Action::Sign => Decision::Authorized,
            },
            purpose: event.purpose.to_owned(),
            context: event.context.map(str::to_owned),
            digest: hex::encode(event.digest),
            fingerprint: hex::encode(event.fingerprint),
            at: unix_now(),
            hash: String::new(),
        };
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
                (Action::CreateReserved | Action::RevokeReserved, None) | (Action::Sign, Some(_))
            )
            || !matches!(
                (record.action, record.decision),
                (Action::CreateReserved | Action::RevokeReserved, Decision::Reserved)
                    | (Action::Sign, Decision::Authorized)
            )
            || record.digest.len() != 64
            || record.fingerprint.len() != 64
            || record
                .digest
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
            || record
                .fingerprint
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(VaultError::AgentAudit);
        }
        let hash = record.compute_hash()?;
        if record.hash != hex::encode(hash) {
            return Err(VaultError::AgentAudit);
        }
        let creation = matches!(record.action, Action::CreateReserved).then_some((record.requester, record.at));
        Ok(VerifiedRecord {
            hash,
            creation,
            at: record.at,
        })
    }
}

fn segment_name(index: usize) -> String {
    format!("vault-agent-audit-{index:04}.log")
}

struct Scan {
    sequence: u64,
    hash: [u8; 32],
    last: Option<usize>,
    last_bytes: usize,
    last_at: u64,
    recent_creators: Vec<NodeId>,
}

fn scan(directory: &Path) -> Result<Scan, VaultError> {
    let mut sequence = 0_u64;
    let mut hash = [0_u8; 32];
    let mut last = None;
    let mut last_bytes = 0;
    let mut last_at = 0;
    let mut gap = false;
    let mut recent_creators = Vec::new();
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
        }
        last = Some(index);
        last_bytes = bytes.len();
    }
    if fs::symlink_metadata(directory.join(segment_name(MAX_SEGMENTS))).is_ok() {
        return Err(VaultError::AgentAudit);
    }
    Ok(Scan {
        sequence,
        hash,
        last,
        last_bytes,
        last_at,
        recent_creators,
    })
}

fn append(directory: &Path, event: Event<'_>) -> Result<(), VaultError> {
    let _lock = Lock::open(directory, LOCK_NAME, false).map_err(|_| VaultError::AgentAudit)?;
    let state = scan(directory)?;
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
    let sequence = state.sequence.checked_add(1).ok_or(VaultError::AgentAudit)?;
    let record = Record::new(sequence, state.hash, event)?;
    if record.at < state.last_at {
        return Err(VaultError::AgentAudit);
    }
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
    Ok(())
}

pub(super) fn create_reserved(
    directory: &Path,
    requester: NodeId,
    purpose: &str,
    policy: &[u8],
    public_key: &[u8; 32],
) -> Result<(), VaultError> {
    let digest: [u8; 32] = Sha256::digest(policy).into();
    append(
        directory,
        Event {
            requester,
            action: Action::CreateReserved,
            purpose,
            context: None,
            digest: &digest,
            fingerprint: public_key,
        },
    )
}

pub(super) fn signed(
    directory: &Path,
    requester: NodeId,
    purpose: &str,
    context: &str,
    digest: &[u8; 32],
    public_key: &[u8; 32],
) -> Result<(), VaultError> {
    append(
        directory,
        Event {
            requester,
            action: Action::Sign,
            purpose,
            context: Some(context),
            digest,
            fingerprint: public_key,
        },
    )
}

pub(super) fn revoke_reserved(
    directory: &Path,
    requester: NodeId,
    purpose: &str,
    policy: &[u8],
    public_key: &[u8; 32],
) -> Result<(), VaultError> {
    let digest: [u8; 32] = Sha256::digest(policy).into();
    append(
        directory,
        Event {
            requester,
            action: Action::RevokeReserved,
            purpose,
            context: None,
            digest: &digest,
            fingerprint: public_key,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{Action, Event, Record, create_reserved, scan, segment_name};
    use crate::{artifact, ids::NodeId, vault::VaultError};

    #[test]
    fn linked_segments_verify_and_tampering_refuses() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let requester = NodeId::from_bytes([1; 32]);
        let first = Record::new(
            1,
            [0; 32],
            Event {
                requester,
                action: Action::CreateReserved,
                purpose: "build",
                context: None,
                digest: &[2; 32],
                fingerprint: &[3; 32],
            },
        )?;
        let first_bytes = first.encode()?;
        artifact::write_new(directory.path().join(segment_name(0)), &first_bytes, 256 * 1024)?;
        let second = Record::new(
            2,
            first.compute_hash()?,
            Event {
                requester,
                action: Action::Sign,
                purpose: "build",
                context: Some("build.stage"),
                digest: &[4; 32],
                fingerprint: &[3; 32],
            },
        )?;
        let second_bytes = second.encode()?;
        artifact::write_new(directory.path().join(segment_name(1)), &second_bytes, 256 * 1024)?;
        let verified = scan(directory.path())?;
        assert_eq!(verified.sequence, 2);
        assert_eq!(verified.hash, second.compute_hash()?);

        let mut changed = first_bytes;
        let offset = changed.iter().position(|byte| *byte == b'b').ok_or("missing purpose")?;
        *changed.get_mut(offset).ok_or("missing purpose")? = b'c';
        std::fs::write(directory.path().join(segment_name(0)), &changed)?;
        assert!(matches!(scan(directory.path()), Err(VaultError::AgentAudit)));
        Ok(())
    }

    #[test]
    fn creation_limits_count_each_member_and_the_hive() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        for member in 1..=4 {
            let requester = NodeId::from_bytes([member; 32]);
            for index in 0..8 {
                create_reserved(
                    directory.path(),
                    requester,
                    &format!("key{member}_{index}"),
                    b"policy",
                    &[3; 32],
                )?;
            }
            assert!(matches!(
                create_reserved(directory.path(), requester, "extra", b"policy", &[3; 32]),
                Err(VaultError::AgentKeyCreationLimit)
            ));
        }
        assert!(matches!(
            create_reserved(
                directory.path(),
                NodeId::from_bytes([5; 32]),
                "extra",
                b"policy",
                &[3; 32]
            ),
            Err(VaultError::AgentKeyCreationLimit)
        ));
        Ok(())
    }

    #[test]
    fn future_audit_time_refuses_further_effects() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let requester = NodeId::from_bytes([1; 32]);
        let mut record = Record::new(
            1,
            [0; 32],
            Event {
                requester,
                action: Action::CreateReserved,
                purpose: "build",
                context: None,
                digest: &[2; 32],
                fingerprint: &[3; 32],
            },
        )?;
        record.at = record.at.saturating_add(60);
        record.hash = hex::encode(record.compute_hash()?);
        artifact::write_new(directory.path().join(segment_name(0)), &record.encode()?, 256 * 1024)?;
        assert!(matches!(scan(directory.path()), Err(VaultError::AgentAudit)));
        Ok(())
    }
}
