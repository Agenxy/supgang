//! Vault-held Ed25519 signing, without a private-key export path.

use std::{io, path::Path};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    Document, Enclave, Kind, Lock, MAX_SECRETS, VERSION, VaultError, append_audit, audit, load, open, save, seal,
    unix_now, validate_name, validate_note,
};
use crate::storage::validate_directory;

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
    let entry = seal(
        &document.public,
        name,
        note,
        unix_now(),
        seed.as_ref(),
        Kind::SigningEd25519,
        Some(public_key),
    )?;
    drop(seed);
    document.version = VERSION;
    document.entries.push(entry);
    document.entries.sort_by(|left, right| left.name.cmp(&right.name));
    save(&directory, &document)?;
    audit(&directory, "add-signing", name, None);
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
    let (seed, public) = open_signing_entry(state_directory, enclave, name, "public-key")?;
    drop(seed);
    Ok(public)
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
    let (seed, identity) = open_signing_entry(state_directory, enclave, name, "sign")?;
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(seed.as_slice().try_into().map_err(|_| VaultError::Corrupt)?);
    let key = SigningKey::from_bytes(&bytes);
    let signature = key.sign(&framed_message(context, digest)).to_bytes();
    drop(key);
    drop(bytes);
    drop(seed);
    Ok(SignedDigest { identity, signature })
}

fn open_signing_entry(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    purpose: &str,
) -> Result<(Zeroizing<Vec<u8>>, SigningPublic), VaultError> {
    validate_name(name)?;
    let directory = validate_directory(state_directory)?;
    append_audit(&directory, "read", name, Some(purpose)).map_err(|_| VaultError::Audit)?;
    let document = load(&directory)?.ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    let entry = document
        .entries
        .iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    if entry.kind != Kind::SigningEd25519 {
        return Err(VaultError::NotSigningKey);
    }
    let public_key = entry.signing_public.ok_or(VaultError::Corrupt)?;
    let shared = enclave.agree(&document.key, &entry.ephemeral)?;
    let seed = open(&shared, &document.public, entry)?;
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(seed.as_slice().try_into().map_err(|_| VaultError::Corrupt)?);
    let derived = SigningKey::from_bytes(&bytes).verifying_key().to_bytes();
    drop(bytes);
    if derived != public_key {
        return Err(VaultError::Corrupt);
    }
    Ok((
        seed,
        SigningPublic {
            public_key,
            fingerprint: fingerprint(&public_key),
        },
    ))
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
