//! Vault-held Ed25519 signing, without a private-key export path.

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{AgentPolicy, Enclave, Kind, VaultError, keys};
use crate::state;

pub(super) const SIGN_DOMAIN: &[u8] = b"supgang-sign/v1\0";

/// Non-exportable Ed25519 public identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningPublic {
    /// Raw 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
    /// Lowercase SHA-256 of the raw public key.
    pub fingerprint: String,
}

/// Signature over the versioned context and a caller-supplied SHA-256 digest.
pub struct SignedDigest {
    /// Public identity of the signing entry.
    pub identity: SigningPublic,
    /// Raw Ed25519 signature.
    pub signature: [u8; 64],
}

/// Generates a fresh key using OS randomness and seals its seed to this vault.
/// The key has no export path through the vault API.
///
/// # Errors
/// Refuses invalid names or notes, overwrites, a full vault and storage failures.
pub fn keygen(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    note: &str,
) -> Result<SigningPublic, VaultError> {
    let public_key = keys::generate(state_directory, enclave, name, note, Kind::SigningEd25519)?;
    Ok(SigningPublic {
        public_key,
        fingerprint: fingerprint(&public_key),
    })
}

/// Creates a non-exportable key with an immutable agent-purpose policy.
/// The purpose is the vault entry name; no consumer pin is installed here.
///
/// # Errors
/// Refuses an unauthorized local creator, an invalid policy or storage failure.
pub fn keygen_agent(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    note: &str,
    policy: &AgentPolicy,
) -> Result<SigningPublic, VaultError> {
    let requester = current_member(state_directory)?;
    if !policy.admits_member(requester) {
        return Err(VaultError::AgentPolicyDenied);
    }
    let public_key = keys::generate_agent(state_directory, enclave, name, note, policy, requester)?;
    Ok(SigningPublic {
        public_key,
        fingerprint: fingerprint(&public_key),
    })
}

/// Reads the authenticated public identity of a signing key.
///
/// # Errors
/// Refuses unknown or changed entries and any failed read audit.
pub fn public_key(state_directory: &Path, enclave: &dyn Enclave, name: &str) -> Result<SigningPublic, VaultError> {
    let (seed, public_key, _policy) =
        keys::open_seed(state_directory, enclave, name, "public-key", Kind::SigningEd25519)?;
    drop(seed);
    Ok(SigningPublic {
        public_key,
        fingerprint: fingerprint(&public_key),
    })
}

/// Signs `supgang-sign/v1\0 || context || 0 || digest32` after recording the read.
///
/// # Errors
/// Refuses malformed context, unknown or changed entries and any failed read audit.
pub fn sign(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    context: &str,
    digest: &[u8; 32],
) -> Result<SignedDigest, VaultError> {
    validate_context(context)?;
    let (seed, public_key, policy) = keys::open_seed(state_directory, enclave, name, "sign", Kind::SigningEd25519)?;
    let requester = if let Some(policy) = policy {
        let requester = current_member(state_directory)?;
        if !policy.admits_member(requester) || !policy.admits_context(context) {
            return Err(VaultError::AgentPolicyDenied);
        }
        Some(requester)
    } else {
        None
    };
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(seed.as_slice().try_into().map_err(|_| VaultError::Corrupt)?);
    let key = SigningKey::from_bytes(&bytes);
    let signature = key.sign(&framed_message(context, digest)).to_bytes();
    drop(key);
    drop(bytes);
    drop(seed);
    if let Some(requester) = requester {
        if current_member(state_directory)? != requester {
            return Err(VaultError::MemberAuthority);
        }
        let directory = crate::storage::validate_directory(state_directory)?;
        super::agent_audit::signed(&directory, requester, name, context, digest, &public_key)?;
    }
    Ok(SignedDigest {
        identity: SigningPublic {
            public_key,
            fingerprint: fingerprint(&public_key),
        },
        signature,
    })
}

pub(super) fn current_member(state_directory: &Path) -> Result<crate::ids::NodeId, VaultError> {
    let state = state::open_read_only(state_directory).map_err(|_| VaultError::MemberAuthority)?;
    // Only the authority has current local revocation state. Other members need
    // a bounded-fresh root status check before this local path can be enabled.
    if state.identity().root.is_none() {
        return Err(VaultError::MemberAuthority);
    }
    let node = state.identity().device.node_id();
    let certificate = state.local_membership().ok_or(VaultError::MemberAuthority)?;
    let now = super::unix_now();
    if certificate.certificate.issued_at > now {
        return Err(VaultError::MemberAuthority);
    }
    certificate
        .certificate
        .validate_time(now)
        .map_err(|_| VaultError::MemberAuthority)?;
    if state.revocations().contains(&node) {
        return Err(VaultError::MemberAuthority);
    }
    Ok(node)
}

/// Validates the public context grammar.
///
/// # Errors
/// [`VaultError::InvalidSigningRequest`] for anything outside the grammar.
pub fn validate_context(context: &str) -> Result<(), VaultError> {
    let bytes = context.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(VaultError::InvalidSigningRequest);
    }
    Ok(())
}

pub(super) fn framed_message(context: &str, digest: &[u8; 32]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(SIGN_DOMAIN.len() + 64 + 1 + 32);
    framed.extend_from_slice(SIGN_DOMAIN);
    framed.extend_from_slice(context.as_bytes());
    framed.push(0);
    framed.extend_from_slice(digest);
    framed
}

pub(super) fn fingerprint(public: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public))
}
