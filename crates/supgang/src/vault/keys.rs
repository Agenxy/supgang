//! Shared sealed Ed25519 seed operations for distinct vault key kinds.

use std::{io, path::Path};

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use super::{
    AgentPolicy, Document, Enclave, Kind, Lock, MAX_SECRETS, SealMetadata, VERSION, VaultError, agent_audit,
    append_audit, audit, load, open, save, seal_entry, signing, unix_now, validate_name, validate_note,
};
use crate::{ids::NodeId, storage::validate_directory};

type OpenedSeed = (Zeroizing<Vec<u8>>, [u8; 32], Option<AgentPolicy>);

pub(super) fn generate(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    note: &str,
    kind: Kind,
) -> Result<[u8; 32], VaultError> {
    generate_with_policy(state_directory, enclave, name, note, kind, None)
}

pub(super) fn generate_agent(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    note: &str,
    policy: &AgentPolicy,
    requester: NodeId,
) -> Result<[u8; 32], VaultError> {
    let encoded = policy.encode()?;
    generate_with_policy(
        state_directory,
        enclave,
        name,
        note,
        Kind::SigningEd25519,
        Some((&encoded, requester)),
    )
}

fn generate_with_policy(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    note: &str,
    kind: Kind,
    agent: Option<(&[u8], NodeId)>,
) -> Result<[u8; 32], VaultError> {
    let operation = match kind {
        Kind::SigningEd25519 => "add-signing",
        Kind::SshEd25519 => "add-ssh",
        Kind::Secret | Kind::LmsSha256H20W1 => return Err(VaultError::Corrupt),
    };
    validate_name(name)?;
    validate_note(note)?;
    let (directory, _lock) = Lock::acquire(state_directory)?;
    let mut document = load(&directory)?.map_or_else(
        || {
            enclave.generate().map(|(key, public)| Document {
                version: VERSION,
                key,
                public,
                entries: Vec::new(),
            })
        },
        Ok,
    )?;
    if document.entries.iter().any(|entry| entry.name == name) {
        return Err(VaultError::AlreadyExists(name.to_owned()));
    }
    if document.entries.len() >= MAX_SECRETS {
        return Err(VaultError::Full);
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(io::Error::other)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    drop(signing_key);
    let entry = seal_entry(
        &document.public,
        name,
        note,
        unix_now(),
        seed.as_ref(),
        SealMetadata {
            kind,
            signing_public: Some(public_key),
            lms_public: None,
            lms_next_q: None,
        },
        agent.map(|(policy, _)| policy),
    )?;
    drop(seed);
    let has_agent_key = document.entries.iter().any(|entry| entry.policy.is_some());
    document.version = VERSION;
    document.entries.push(entry);
    document.entries.sort_by(|left, right| left.name.cmp(&right.name));
    if let Some((policy, requester)) = agent {
        if signing::current_member(state_directory)? != requester {
            return Err(VaultError::MemberAuthority);
        }
        agent_audit::create_reserved(&directory, requester, name, policy, &public_key, has_agent_key)?;
        if signing::current_member(state_directory)? != requester {
            return Err(VaultError::MemberAuthority);
        }
    }
    save(&directory, &document)?;
    if agent.is_none() {
        audit(&directory, operation, name, None);
    }
    Ok(public_key)
}

pub(super) fn open_seed(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    purpose: &str,
    required: Kind,
) -> Result<OpenedSeed, VaultError> {
    validate_name(name)?;
    let directory = validate_directory(state_directory)?;
    append_audit(&directory, "read", name, Some(purpose)).map_err(|_| VaultError::Audit)?;
    let document = load(&directory)?.ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    let entry = document
        .entries
        .iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    if entry.kind != required {
        return Err(match required {
            Kind::SigningEd25519 => VaultError::NotSigningKey,
            Kind::SshEd25519 => VaultError::NotSshKey,
            Kind::Secret | Kind::LmsSha256H20W1 => VaultError::Corrupt,
        });
    }
    let public_key = entry.signing_public.ok_or(VaultError::Corrupt)?;
    let policy = entry.policy.as_deref().map(AgentPolicy::decode).transpose()?;
    let shared = enclave.agree(&document.key, &entry.ephemeral)?;
    let seed = open(&shared, &document.public, entry)?;
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(seed.as_slice().try_into().map_err(|_| VaultError::Corrupt)?);
    let derived = SigningKey::from_bytes(&bytes).verifying_key().to_bytes();
    drop(bytes);
    if derived != public_key {
        return Err(VaultError::Corrupt);
    }
    Ok((seed, public_key, policy))
}
