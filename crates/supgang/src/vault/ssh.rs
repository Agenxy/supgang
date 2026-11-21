//! SSH-only Ed25519 keys and OpenSSH public identity encoding.

use std::path::Path;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{Enclave, Kind, Lock, VaultError, agent_audit, keys};
use crate::ids::NodeId;

/// OpenSSH public identity; no private seed is exposed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshPublic {
    /// Raw Ed25519 public key.
    pub public_key: [u8; 32],
    /// `ssh-ed25519 BASE64 name@supgang`.
    pub line: String,
    /// `SHA256:` followed by unpadded base64 of the key blob's SHA-256.
    pub fingerprint: String,
    /// Member that requested this key's creation on this device.
    pub remote_creator: Option<NodeId>,
}

/// A raw Ed25519 signature for the SSH agent response.
pub struct SshSigned {
    /// Identity that signed the bytes.
    pub identity: SshPublic,
    /// Raw 64-byte signature.
    pub signature: [u8; 64],
}

/// Creates an SSH-only key using OS randomness and vault sealing.
///
/// # Errors
/// Refuses overwrites, malformed names or notes, full vaults and storage failures.
pub fn ssh_keygen(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    note: &str,
) -> Result<SshPublic, VaultError> {
    let public_key = keys::generate(state_directory, enclave, name, note, Kind::SshEd25519)?;
    Ok(public(name, public_key, None))
}

/// Reads an authenticated SSH public key from the vault.
///
/// # Errors
/// Refuses a different key kind and any failed audit, decryption or verification.
pub fn ssh_public_key(state_directory: &Path, enclave: &dyn Enclave, name: &str) -> Result<SshPublic, VaultError> {
    let (seed, public_key, _policy, remote_creator) =
        keys::open_seed(state_directory, enclave, name, "ssh-public-key", Kind::SshEd25519)?;
    drop(seed);
    Ok(public(name, public_key, remote_creator))
}

/// Signs raw SSH client bytes after a durable vault read audit.
///
/// # Errors
/// Refuses data over 256 KiB, a different key kind or any failed audit/open.
pub fn ssh_sign(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    data: &[u8],
) -> Result<SshSigned, VaultError> {
    if data.len() > 256 * 1024 {
        return Err(VaultError::SshDataTooLarge);
    }
    let (directory, _lock) = Lock::acquire(state_directory)?;
    let (seed, public_key, policy, remote_creator) =
        keys::open_seed(state_directory, enclave, name, "ssh-sign", Kind::SshEd25519)?;
    if let Some(policy) = policy {
        agent_audit::ensure_activated(&directory, name, &policy.encode()?, &public_key)?;
    }
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(seed.as_slice().try_into().map_err(|_| VaultError::Corrupt)?);
    let key = SigningKey::from_bytes(&bytes);
    let signature = key.sign(data).to_bytes();
    drop(key);
    drop(bytes);
    drop(seed);
    Ok(SshSigned {
        identity: public(name, public_key, remote_creator),
        signature,
    })
}

/// Encodes an Ed25519 public key in the SSH wire format.
#[must_use]
pub fn ssh_key_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(51);
    blob.extend_from_slice(&11_u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32_u32.to_be_bytes());
    blob.extend_from_slice(public);
    blob
}

pub(super) fn fingerprint(public: &[u8; 32]) -> String {
    format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(ssh_key_blob(public)))
    )
}

pub(super) fn public(name: &str, public_key: [u8; 32], remote_creator: Option<NodeId>) -> SshPublic {
    let line = format!(
        "ssh-ed25519 {} {name}@supgang",
        STANDARD.encode(ssh_key_blob(&public_key))
    );
    SshPublic {
        public_key,
        line,
        fingerprint: fingerprint(&public_key),
        remote_creator,
    }
}
