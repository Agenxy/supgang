//! Explicit, fingerprint-pinned upgrade of a legacy signing key's sealed policy.

use std::{io, path::Path};

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use super::{
    AgentPolicy, Enclave, Kind, Lock, SealMetadata, VERSION, VaultError, agent_audit, append_audit, load, open, save,
    seal_entry, signing, unix_now, validate_name,
};
use crate::ids::NodeId;

/// Attach one immutable agent policy without changing the existing public key.
///
/// The expected fingerprint must be obtained from an independent consumer pin
/// review; a repeated call with the same policy is safe after a lost reply.
///
/// # Errors
/// Refuses a wrong fingerprint, different existing policy, non-signing key,
/// invalid root authority, unauditable state, or a storage/enclave failure.
pub fn migrate_agent_policy(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    expected_fingerprint: &str,
    policy: &AgentPolicy,
) -> Result<signing::SigningPublic, VaultError> {
    let requester = signing::current_member(state_directory)?;
    migrate_with_authority(state_directory, enclave, name, expected_fingerprint, policy, &|| {
        let current = signing::current_member(state_directory)?;
        if current == requester {
            Ok(current)
        } else {
            Err(VaultError::MemberAuthority)
        }
    })
}

pub(super) fn migrate_with_authority(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    expected_fingerprint: &str,
    policy: &AgentPolicy,
    authorize: &dyn Fn() -> Result<NodeId, VaultError>,
) -> Result<signing::SigningPublic, VaultError> {
    validate_name(name)?;
    let policy_bytes = policy.encode()?;
    let requester = authorize()?;
    if !policy.admits_member(requester) {
        return Err(VaultError::AgentPolicyDenied);
    }
    let (directory, _lock) = Lock::acquire(state_directory)?;
    let mut document = load(&directory)?.ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    let index = document
        .entries
        .iter()
        .position(|entry| entry.name == name)
        .ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    let entry = document.entries.get(index).ok_or(VaultError::Corrupt)?;
    if entry.kind != Kind::SigningEd25519 {
        return Err(VaultError::NotSigningKey);
    }
    let public_key = entry.signing_public.ok_or(VaultError::Corrupt)?;
    let fingerprint = signing::fingerprint(&public_key);
    if fingerprint != expected_fingerprint {
        return Err(VaultError::AgentFingerprintMismatch);
    }
    if entry.policy.as_deref().is_some_and(|existing| existing != policy_bytes) {
        return Err(VaultError::AgentPolicyAlreadySet);
    }
    let state = agent_audit::creation_state(&directory, name, &policy_bytes, &public_key)?;
    if entry.policy.is_some() && state.is_none() || entry.policy.is_none() && state == Some(true) {
        return Err(VaultError::AgentAudit);
    }

    // A legacy ciphertext is opened only after a durable, owner-only read
    // audit. The seed stays in zeroizing process memory while it is resealed.
    append_audit(&directory, "read", name, Some("policy-migration")).map_err(|_| VaultError::Audit)?;
    let shared = enclave.agree(&document.key, &entry.ephemeral)?;
    let seed = open(&shared, &document.public, entry)?;
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(seed.as_slice().try_into().map_err(|_| VaultError::Corrupt)?);
    if SigningKey::from_bytes(&bytes).verifying_key().to_bytes() != public_key {
        return Err(VaultError::Corrupt);
    }
    drop(bytes);
    let identity = signing::SigningPublic {
        public_key,
        fingerprint,
    };
    if entry.policy.is_some() {
        drop(seed);
        authorize()?;
        if state == Some(false) {
            agent_audit::create_activated(&directory, requester, name, &policy_bytes, &public_key)?;
        }
        return Ok(identity);
    }

    let resealed = seal_entry(
        &document.public,
        &entry.name,
        &entry.note,
        entry.stored_at,
        &seed,
        SealMetadata {
            kind: Kind::SigningEd25519,
            signing_public: Some(public_key),
            lms_public: None,
            lms_next_q: None,
            remote_creator: None,
            presence_digest: None,
        },
        Some(&policy_bytes),
    )?;
    drop(seed);
    let require_existing = document.entries.iter().any(|item| item.policy.is_some());
    *document.entries.get_mut(index).ok_or(VaultError::Corrupt)? = resealed;
    document.version = VERSION;
    authorize()?;
    if state.is_none() {
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let expires_at = unix_now().checked_add(300).ok_or(VaultError::AgentAudit)?;
        agent_audit::create_reserved(
            &directory,
            requester,
            name,
            &policy_bytes,
            &public_key,
            require_existing,
            Some((nonce, expires_at)),
        )?;
    }
    save(&directory, &document)?;
    authorize()?;
    agent_audit::create_activated(&directory, requester, name, &policy_bytes, &public_key)?;
    Ok(identity)
}

#[cfg(test)]
mod tests;
