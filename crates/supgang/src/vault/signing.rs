//! Vault-held Ed25519 signing, without a private-key export path.

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{AgentPolicy, Enclave, Kind, Lock, VaultError, keys};
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
    let (_directory, _vault_lock) = Lock::acquire(state_directory)?;
    let (seed, public_key, policy) = keys::open_seed(state_directory, enclave, name, "sign", Kind::SigningEd25519)?;
    let requester = if let Some(policy) = policy {
        let requester = current_member(state_directory)?;
        if !policy.admits_member(requester) || !policy.admits_context(context) {
            return Err(VaultError::AgentPolicyDenied);
        }
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(std::io::Error::other)?;
        let request = crate::agent_sign_protocol::SignRequest {
            nonce,
            purpose: name.to_owned(),
            context: context.to_owned(),
            digest: *digest,
            expires_at: super::unix_now().checked_add(300).ok_or(VaultError::MemberAuthority)?,
        };
        let directory = crate::storage::validate_directory(state_directory)?;
        super::agent_audit::reserve_nonce(&directory, requester, &request, &public_key)?;
        if current_member(state_directory)? != requester {
            return Err(VaultError::MemberAuthority);
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
        if current_member(state_directory)? != requester {
            return Err(VaultError::MemberAuthority);
        }
    }
    Ok(SignedDigest {
        identity: SigningPublic {
            public_key,
            fingerprint: fingerprint(&public_key),
        },
        signature,
    })
}

/// Signs for a member authenticated by the live peer session. The caller must
/// also hold that session's authorization and discard the result if it expires
/// or is invalidated while this synchronous operation runs.
pub fn sign_member(
    state_directory: &Path,
    enclave: &dyn Enclave,
    requester: crate::ids::NodeId,
    request: &crate::agent_sign_protocol::SignRequest,
    session_current: impl Fn() -> bool,
) -> Result<SignedDigest, VaultError> {
    request
        .validate(super::unix_now())
        .map_err(|_| VaultError::InvalidSigningRequest)?;
    let (_directory, _vault_lock) = Lock::acquire(state_directory)?;
    if !session_current() {
        return Err(VaultError::MemberAuthority);
    }
    current_member_for(state_directory, requester)?;
    let (seed, public_key, policy) =
        keys::open_seed(state_directory, enclave, &request.purpose, "sign", Kind::SigningEd25519)?;
    let policy = policy.ok_or(VaultError::AgentPolicyDenied)?;
    if !policy.admits_member(requester) || !policy.admits_context(&request.context) {
        return Err(VaultError::AgentPolicyDenied);
    }
    if !session_current() {
        return Err(VaultError::MemberAuthority);
    }
    let directory = crate::storage::validate_directory(state_directory)?;
    super::agent_audit::reserve_nonce(&directory, requester, request, &public_key)?;
    current_member_for(state_directory, requester)?;
    if !session_current() {
        return Err(VaultError::MemberAuthority);
    }
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(seed.as_slice().try_into().map_err(|_| VaultError::Corrupt)?);
    let key = SigningKey::from_bytes(&bytes);
    let signature = key.sign(&framed_message(&request.context, &request.digest)).to_bytes();
    drop(key);
    drop(bytes);
    drop(seed);
    current_member_for(state_directory, requester)?;
    if !session_current() {
        return Err(VaultError::MemberAuthority);
    }
    super::agent_audit::signed(
        &directory,
        requester,
        &request.purpose,
        &request.context,
        &request.digest,
        &public_key,
    )?;
    current_member_for(state_directory, requester)?;
    Ok(SignedDigest {
        identity: SigningPublic {
            public_key,
            fingerprint: fingerprint(&public_key),
        },
        signature,
    })
}

fn current_member_for(state_directory: &Path, requester: crate::ids::NodeId) -> Result<(), VaultError> {
    let state = state::open_read_only(state_directory).map_err(|_| VaultError::MemberAuthority)?;
    if state.identity().root.is_none() || state.revocations().contains(&requester) {
        return Err(VaultError::MemberAuthority);
    }
    let certificate = state.membership(&requester).ok_or(VaultError::MemberAuthority)?;
    let now = super::unix_now();
    if certificate.certificate.issued_at > now {
        return Err(VaultError::MemberAuthority);
    }
    certificate
        .certificate
        .validate_time(now)
        .map_err(|_| VaultError::MemberAuthority)?;
    Ok(())
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

pub fn verify_signed(context: &str, digest: &[u8; 32], public_key: &[u8; 32], signature: &[u8; 64]) -> bool {
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    key.verify_strict(
        &framed_message(context, digest),
        &ed25519_dalek::Signature::from_bytes(signature),
    )
    .is_ok()
}

pub(super) fn fingerprint(public: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public))
}
