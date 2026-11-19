//! Shared sealed Ed25519 seed operations for distinct vault key kinds.

use std::{io, path::Path};

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use super::{
    Document, Enclave, Kind, Lock, MAX_SECRETS, VERSION, VaultError, append_audit, audit, load, open, save, seal,
    unix_now, validate_name, validate_note,
};
use crate::storage::validate_directory;

pub(super) fn generate(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    note: &str,
    kind: Kind,
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
    let entry = seal(
        &document.public,
        name,
        note,
        unix_now(),
        seed.as_ref(),
        kind,
        Some(public_key),
    )?;
    drop(seed);
    document.version = VERSION;
    document.entries.push(entry);
    document.entries.sort_by(|left, right| left.name.cmp(&right.name));
    save(&directory, &document)?;
    audit(&directory, operation, name, None);
    Ok(public_key)
}

pub(super) fn open_seed(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    purpose: &str,
    required: Kind,
) -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), VaultError> {
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
    let shared = enclave.agree(&document.key, &entry.ephemeral)?;
    let seed = open(&shared, &document.public, entry)?;
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(seed.as_slice().try_into().map_err(|_| VaultError::Corrupt)?);
    let derived = SigningKey::from_bytes(&bytes).verifying_key().to_bytes();
    drop(bytes);
    if derived != public_key {
        return Err(VaultError::Corrupt);
    }
    Ok((seed, public_key))
}
