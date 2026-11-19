//! Owner-only secrets sealed to this computer's Secure Enclave.
//!
//! Each secret is encrypted to the vault's Secure Enclave key-agreement key
//! with a fresh ephemeral P-256 key, HKDF-SHA-256 and ChaCha20-Poly1305. The
//! file holds only ciphertext and the enclave's restore record, which no other
//! computer can use. Adding a secret needs only the public key; reading one
//! needs the enclave, without a prompt, so agents can use granted secrets.
//!
//! The boundary is this macOS user: any program running as the owner can ask
//! for any secret. The vault keeps secrets off disk in clear, out of iCloud
//! and out of keychain prompts, and records every use. It does not tell one
//! of the owner's programs from another.

use std::{
    fmt, fs,
    io::{self},
    path::{Path, PathBuf},
};

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use p256::{PublicKey, SecretKey, elliptic_curve::sec1::ToSec1Point};
use sha2::Digest;
use thiserror::Error;
use zeroize::Zeroizing;

mod audit;
mod backup;
mod format;
mod keys;
mod lms;
mod lms_rfc;
mod lock;
mod signing;
mod ssh;

use audit::{append_audit, audit};
use format::{decode, encode};
pub use lms::{
    LmsPublic, LmsSigned, Nc0Package, ReleaseLog, SignPreview, advance as lms_advance, keygen as lms_keygen,
    package as lms_package, preview as lms_preview, public_key as lms_public_key, sign as lms_sign,
};
use lock::Lock;
use signing::fingerprint;
#[cfg(test)]
use signing::{SIGN_DOMAIN, framed_message};
pub use signing::{SignedDigest, SigningPublic, keygen, public_key, sign, validate_context};
pub use ssh::{SshPublic, SshSigned, ssh_key_blob, ssh_keygen, ssh_public_key, ssh_sign};

use crate::{
    artifact,
    device_key::custody::{CustodyError, SealedKey},
    storage::{self, sync_directory, validate_directory},
};

/// The vault document inside protected state.
pub const VAULT_FILE_NAME: &str = "vault.cbor";
/// The bounded, owner-only record of every vault use.
pub const AUDIT_FILE_NAME: &str = "vault-audit.log";
/// Most secrets one vault holds.
pub const MAX_SECRETS: usize = 128;
/// Largest secret, in bytes.
pub const MAX_SECRET_BYTES: usize = 8 * 1024;
/// Longest secret name, in bytes.
pub const MAX_NAME_BYTES: usize = 64;
/// Longest note, in bytes.
pub const MAX_NOTE_BYTES: usize = 200;

const ENTRY_DOMAIN: &[u8] = b"supgang/vault-entry/v1\0";
const VERSION: u8 = 3;
const LOCK_FILE_NAME: &str = "vault.lock";
const AUDIT_LOCK_FILE_NAME: &str = "vault-audit.lock";
const PUBLIC_BYTES: usize = 33;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const MAX_KEY_RECORD_BYTES: usize = 4 * 1024 + 16;
const MAX_ENTRY_BYTES: usize = MAX_NAME_BYTES + MAX_NOTE_BYTES + PUBLIC_BYTES + NONCE_BYTES + MAX_SECRET_BYTES + 128;
const MAX_VAULT_BYTES: usize = MAX_KEY_RECORD_BYTES + PUBLIC_BYTES + MAX_SECRETS * MAX_ENTRY_BYTES + 64;
const MAX_AUDIT_BYTES: u64 = 256 * 1024;
const TEMPORARY_ATTEMPTS: usize = 8;

/// A vault refusal. Messages never include secret bytes.
#[derive(Debug, Error)]
pub enum VaultError {
    /// The name is empty, too long or uses other characters.
    #[error("secret names are 1 to 64 lowercase letters, digits, '.', '_' or '-', starting with a letter or digit")]
    InvalidName,
    /// The note is too long or contains control characters.
    #[error("notes are at most 200 bytes of printable text")]
    InvalidNote,
    /// The secret is empty or larger than the vault accepts.
    #[error("a secret must be 1 to 8192 bytes")]
    InvalidSecret,
    /// The signing request is malformed.
    #[error("signing context must be 1 to 64 ASCII bytes from [a-z0-9._-], and --sha256 must be 64 hex characters")]
    InvalidSigningRequest,
    /// Signing keys are never exportable.
    #[error("signing keys cannot be exported with vault get or vault run; use supgang sign")]
    SigningKeyNotExportable,
    /// SSH keys are never exportable.
    #[error("SSH keys cannot be exported with vault get or vault run; use supgang ssh-agent")]
    SshKeyNotExportable,
    /// LMS key material is never exported.
    #[error("LMS keys cannot be exported with vault get or vault run")]
    LmsKeyNotExportable,
    /// A key reserved for LMS cannot be overwritten or removed.
    #[error("LMS roots cannot be replaced or removed; retire the root and retain its reservation record")]
    LmsRootRetained,
    /// The entry is not an LMS root.
    #[error("the named vault entry is not an LMS root")]
    NotLmsKey,
    /// The NC0 package header, size, or contents are invalid.
    #[error("the NC0 format-2 package is invalid or changed while being read")]
    InvalidNc0Package,
    /// Local q records do not agree.
    #[error("LMS reservation records disagree; signing is refused")]
    LmsStateMismatch,
    /// The caller's independent release log does not support this q.
    #[error("LMS release-log evidence does not permit this q")]
    LmsReleaseLog,
    /// No LMS leaf remains.
    #[error("the LMS root has exhausted all 1048576 leaf numbers")]
    LmsExhausted,
    /// Forward-only recovery target is unsafe.
    #[error("LMS advance target must exceed both local records and the external release log")]
    LmsAdvanceRefused,
    /// The entry is not a signing key.
    #[error("the named vault entry is not an Ed25519 signing key")]
    NotSigningKey,
    /// The entry is not an SSH key.
    #[error("the named vault entry is not an ssh-ed25519 key")]
    NotSshKey,
    /// The SSH data is too large to sign.
    #[error("SSH agent signing data exceeds 256 KiB")]
    SshDataTooLarge,
    /// No secret has this name.
    #[error("no secret named {0} in this computer's vault")]
    NotFound(String),
    /// A secret already has this name and replacement was not requested.
    #[error("a vault entry named {0} already exists")]
    AlreadyExists(String),
    /// The vault holds its maximum number of secrets.
    #[error("the vault already holds 128 secrets; remove one first")]
    Full,
    /// Another vault change holds the lock.
    #[error("another vault change is in progress; retry the command")]
    Busy,
    /// The enclave key is unusable here, for the stated reason.
    #[error("the vault needs this Mac's Secure Enclave: {0}")]
    Enclave(#[from] CustodyError),
    /// The vault file is malformed, from another computer or tampered with.
    #[error("the vault file is invalid, belongs to another computer, or was altered")]
    Corrupt,
    /// The protected state directory failed validation.
    #[error(transparent)]
    Storage(#[from] storage::StorageError),
    /// A protected file failed validation.
    #[error(transparent)]
    Artifact(#[from] artifact::ArtifactError),
    /// The audit record could not be written, so the secret was not released.
    #[error("the vault could not record this read in vault-audit.log, so it released nothing")]
    Audit,
    /// The operating system rejected a vault-file operation.
    #[error("vault filesystem operation failed")]
    Io(#[from] io::Error),
}

/// The key-agreement key a vault is sealed to.
pub trait Enclave {
    /// Creates a new key, returning its restore record and compressed public key.
    ///
    /// # Errors
    /// Refuses when the platform key cannot be created.
    fn generate(&self) -> Result<(SealedKey, [u8; PUBLIC_BYTES]), VaultError>;
    /// The raw P-256 shared secret between the sealed key and `peer`.
    ///
    /// # Errors
    /// Refuses a record of another kind and any platform failure.
    fn agree(&self, sealed: &SealedKey, peer: &[u8; PUBLIC_BYTES]) -> Result<Zeroizing<[u8; 32]>, VaultError>;
}

/// This Mac's Secure Enclave, through the sibling helper.
#[derive(Clone, Copy, Debug)]
pub struct SecureEnclave;

#[cfg(target_os = "macos")]
impl Enclave for SecureEnclave {
    fn generate(&self) -> Result<(SealedKey, [u8; PUBLIC_BYTES]), VaultError> {
        let (sealed, public) = crate::device_key::secure_enclave::generate_agreement()?;
        Ok((sealed, compressed_point(&public)?))
    }
    fn agree(&self, sealed: &SealedKey, peer: &[u8; PUBLIC_BYTES]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        Ok(crate::device_key::secure_enclave::agree(sealed, peer)?)
    }
}

#[cfg(not(target_os = "macos"))]
impl Enclave for SecureEnclave {
    fn generate(&self) -> Result<(SealedKey, [u8; PUBLIC_BYTES]), VaultError> {
        Err(CustodyError::Unavailable(crate::device_key::custody::UnavailableReason::WrongPlatform).into())
    }
    fn agree(&self, _sealed: &SealedKey, _peer: &[u8; PUBLIC_BYTES]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        Err(CustodyError::Unavailable(crate::device_key::custody::UnavailableReason::WrongPlatform).into())
    }
}

/// What `list` shows about one secret: never its bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Summary {
    /// The secret's name.
    pub name: String,
    /// The owner's note.
    pub note: String,
    /// When the secret was last stored, in Unix seconds.
    pub stored_at: u64,
    /// Plaintext length in bytes.
    pub bytes: usize,
    /// Entry kind.
    pub kind: &'static str,
    /// Lowercase SHA-256 of the public key, when applicable.
    pub fingerprint: Option<String>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Kind {
    Secret,
    SigningEd25519,
    SshEd25519,
    LmsSha256H20W1,
}

impl Kind {
    const fn label(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::SigningEd25519 => "signing-ed25519",
            Self::SshEd25519 => "ssh-ed25519",
            Self::LmsSha256H20W1 => "lms-sha256-h20-w1",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
struct Entry {
    kind: Kind,
    signing_public: Option<[u8; 32]>,
    lms_public: Option<[u8; lms_rfc::PUBLIC_LEN]>,
    lms_next_q: Option<u32>,
    name: String,
    note: String,
    stored_at: u64,
    ephemeral: [u8; PUBLIC_BYTES],
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
}

impl Entry {
    fn summary(&self) -> Summary {
        Summary {
            name: self.name.clone(),
            note: self.note.clone(),
            stored_at: self.stored_at,
            bytes: self.ciphertext.len().saturating_sub(TAG_BYTES),
            kind: self.kind.label(),
            fingerprint: self
                .lms_public
                .map(|key| hex::encode(sha2::Sha256::digest(key)))
                .or_else(|| {
                    self.signing_public.map(|key| match self.kind {
                        Kind::SshEd25519 => ssh::fingerprint(&key),
                        Kind::Secret | Kind::SigningEd25519 | Kind::LmsSha256H20W1 => fingerprint(&key),
                    })
                }),
        }
    }
}

struct Document {
    version: u8,
    key: SealedKey,
    public: [u8; PUBLIC_BYTES],
    entries: Vec<Entry>,
}

impl fmt::Debug for Document {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Document")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Lists stored secrets without touching the enclave.
///
/// # Errors
/// Refuses unsafe storage and a malformed vault file.
pub fn list(state_directory: &Path) -> Result<Vec<Summary>, VaultError> {
    let directory = validate_directory(state_directory)?;
    Ok(load(&directory)?.map_or_else(Vec::new, |document| {
        document.entries.iter().map(Entry::summary).collect()
    }))
}

/// Stores `secret` under `name`, creating the vault key on first use.
///
/// # Errors
/// Refuses invalid names, notes or secrets, an existing name unless `replace`,
/// a full vault, a busy lock, an unavailable enclave and storage failures.
pub fn add(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    note: &str,
    secret: &[u8],
    replace: bool,
) -> Result<Summary, VaultError> {
    validate_name(name)?;
    validate_note(note)?;
    if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
        return Err(VaultError::InvalidSecret);
    }
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
    let existing = document.entries.iter().position(|entry| entry.name == name);
    if existing.is_some() && !replace {
        return Err(VaultError::AlreadyExists(name.to_owned()));
    }
    if existing
        .and_then(|index| document.entries.get(index))
        .is_some_and(|entry| entry.kind == Kind::LmsSha256H20W1)
    {
        return Err(VaultError::LmsRootRetained);
    }
    if existing.is_none() && document.entries.len() >= MAX_SECRETS {
        return Err(VaultError::Full);
    }
    let entry = seal(&document.public, name, note, unix_now(), secret, Kind::Secret, None)?;
    let summary = entry.summary();
    if let Some(index) = existing {
        document.entries.remove(index);
    }
    document.entries.push(entry);
    document.entries.sort_by(|left, right| left.name.cmp(&right.name));
    document.version = VERSION;
    save(&directory, &document)?;
    audit(
        &directory,
        if existing.is_some() { "replace" } else { "add" },
        name,
        None,
    );
    Ok(summary)
}

/// Decrypts one secret through the enclave and records the use.
///
/// `purpose` names the consuming program for the audit record, if known.
///
/// # Errors
/// Refuses unknown names, an unavailable enclave and a malformed or altered vault.
pub fn reveal(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    purpose: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    validate_name(name)?;
    let directory = validate_directory(state_directory)?;
    // Recorded before the secret leaves, so no read goes unrecorded.
    append_audit(&directory, "read", name, purpose).map_err(|_| VaultError::Audit)?;
    let result = (|| {
        let document = load(&directory)?.ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
        let entry = document
            .entries
            .iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
        match entry.kind {
            Kind::Secret => {}
            Kind::SigningEd25519 => return Err(VaultError::SigningKeyNotExportable),
            Kind::SshEd25519 => return Err(VaultError::SshKeyNotExportable),
            Kind::LmsSha256H20W1 => return Err(VaultError::LmsKeyNotExportable),
        }
        let shared = enclave.agree(&document.key, &entry.ephemeral)?;
        open(&shared, &document.public, entry)
    })();
    if result.is_err() {
        audit(&directory, "read-refused", name, purpose);
    }
    result
}

/// Removes one secret. The vault key stays, so later additions need no enclave.
///
/// # Errors
/// Refuses unknown names, a busy lock and storage failures.
pub fn remove(state_directory: &Path, name: &str) -> Result<(), VaultError> {
    validate_name(name)?;
    let (directory, _lock) = Lock::acquire(state_directory)?;
    let mut document = load(&directory)?.ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    let index = document
        .entries
        .iter()
        .position(|entry| entry.name == name)
        .ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    if document.entries.get(index).ok_or(VaultError::Corrupt)?.kind == Kind::LmsSha256H20W1 {
        return Err(VaultError::LmsRootRetained);
    }
    document.entries.remove(index);
    document.version = VERSION;
    save(&directory, &document)?;
    audit(&directory, "remove", name, None);
    Ok(())
}

/// Checks a secret name: `[a-z0-9][a-z0-9._-]{0,63}`.
///
/// # Errors
/// [`VaultError::InvalidName`] for anything else.
pub fn validate_name(name: &str) -> Result<(), VaultError> {
    let bytes = name.as_bytes();
    let allowed = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-');
    match bytes.first() {
        Some(first)
            if bytes.len() <= MAX_NAME_BYTES
                && (first.is_ascii_lowercase() || first.is_ascii_digit())
                && bytes.iter().all(allowed) =>
        {
            Ok(())
        }
        _ => Err(VaultError::InvalidName),
    }
}

fn validate_note(note: &str) -> Result<(), VaultError> {
    if note.len() > MAX_NOTE_BYTES || note.chars().any(char::is_control) {
        return Err(VaultError::InvalidNote);
    }
    Ok(())
}

fn compressed_point(bytes: &[u8]) -> Result<[u8; PUBLIC_BYTES], VaultError> {
    let array: [u8; PUBLIC_BYTES] = bytes.try_into().map_err(|_| VaultError::Corrupt)?;
    let point = PublicKey::from_sec1_bytes(&array).map_err(|_| VaultError::Corrupt)?;
    if point.to_sec1_point(true).as_bytes() != array {
        return Err(VaultError::Corrupt);
    }
    Ok(array)
}

fn seal(
    public: &[u8; PUBLIC_BYTES],
    name: &str,
    note: &str,
    stored_at: u64,
    secret: &[u8],
    kind: Kind,
    signing_public: Option<[u8; 32]>,
) -> Result<Entry, VaultError> {
    seal_entry(
        public,
        name,
        note,
        stored_at,
        secret,
        SealMetadata {
            kind,
            signing_public,
            lms_public: None,
            lms_next_q: None,
        },
    )
}

#[derive(Clone, Copy)]
struct SealMetadata {
    kind: Kind,
    signing_public: Option<[u8; 32]>,
    lms_public: Option<[u8; lms_rfc::PUBLIC_LEN]>,
    lms_next_q: Option<u32>,
}

fn seal_entry(
    public: &[u8; PUBLIC_BYTES],
    name: &str,
    note: &str,
    stored_at: u64,
    secret: &[u8],
    metadata: SealMetadata,
) -> Result<Entry, VaultError> {
    let recipient = PublicKey::from_sec1_bytes(public).map_err(|_| VaultError::Corrupt)?;
    let ephemeral_secret = random_secret_key()?;
    let ephemeral = compressed_point(ephemeral_secret.public_key().to_sec1_point(true).as_bytes())?;
    let shared = p256::ecdh::diffie_hellman(ephemeral_secret.to_nonzero_scalar(), recipient.as_affine());
    let mut raw = Zeroizing::new([0_u8; 32]);
    raw.copy_from_slice(shared.raw_secret_bytes());
    let cipher = cipher(&raw, &ephemeral, public, name)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    let aad = associated_data(name, note, stored_at, &ephemeral, &metadata);
    let ciphertext = cipher
        .encrypt(&nonce.into(), Payload { msg: secret, aad: &aad })
        .map_err(|_| VaultError::InvalidSecret)?;
    Ok(Entry {
        kind: metadata.kind,
        signing_public: metadata.signing_public,
        lms_public: metadata.lms_public,
        lms_next_q: metadata.lms_next_q,
        name: name.to_owned(),
        note: note.to_owned(),
        stored_at,
        ephemeral,
        nonce,
        ciphertext,
    })
}

/// A uniformly random scalar; an out-of-range draw is astronomically rare, and
/// repeated failure means the random source is broken, so it is refused.
fn random_secret_key() -> Result<SecretKey, VaultError> {
    for _attempt in 0..TEMPORARY_ATTEMPTS {
        let mut scalar = Zeroizing::new([0_u8; 32]);
        getrandom::fill(scalar.as_mut()).map_err(io::Error::other)?;
        if let Ok(key) = SecretKey::from_slice(scalar.as_ref()) {
            return Ok(key);
        }
    }
    Err(io::Error::other("the random source returned no valid P-256 scalar").into())
}

fn open(shared: &[u8; 32], public: &[u8; PUBLIC_BYTES], entry: &Entry) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let cipher = cipher(shared, &entry.ephemeral, public, &entry.name)?;
    let aad = associated_data(
        &entry.name,
        &entry.note,
        entry.stored_at,
        &entry.ephemeral,
        &SealMetadata {
            kind: entry.kind,
            signing_public: entry.signing_public,
            lms_public: entry.lms_public,
            lms_next_q: entry.lms_next_q,
        },
    );
    cipher
        .decrypt(
            &entry.nonce.into(),
            Payload {
                msg: &entry.ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| VaultError::Corrupt)
}

/// One key per secret: the shared secret, salted with both public keys and
/// bound to the name, so moving ciphertext between names fails to decrypt.
fn cipher(
    shared: &[u8; 32],
    ephemeral: &[u8; PUBLIC_BYTES],
    public: &[u8; PUBLIC_BYTES],
    name: &str,
) -> Result<ChaCha20Poly1305, VaultError> {
    let mut salt = [0_u8; 2 * PUBLIC_BYTES];
    let (left, right) = salt.split_at_mut(PUBLIC_BYTES);
    left.copy_from_slice(ephemeral);
    right.copy_from_slice(public);
    let mut info = Vec::with_capacity(ENTRY_DOMAIN.len() + name.len());
    info.extend_from_slice(ENTRY_DOMAIN);
    info.extend_from_slice(name.as_bytes());
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), shared)
        .expand(&info, key.as_mut())
        .map_err(|_| VaultError::Corrupt)?;
    ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| VaultError::Corrupt)
}

/// `domain || name || 0 || ephemeral || stored_at (big-endian) || note`: every
/// field of the entry except the ciphertext and nonce, so editing any fails.
/// Signing entries append `\0signing-ed25519\0 || public` to prevent decoding
/// them as exportable secrets. This suffix cannot be forged through `note`
/// because `validate_note`, called on both add and decode, forbids control
/// characters including NUL. Keep that restriction if the note grammar changes.
fn associated_data(
    name: &str,
    note: &str,
    stored_at: u64,
    ephemeral: &[u8; PUBLIC_BYTES],
    metadata: &SealMetadata,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENTRY_DOMAIN.len() + name.len() + 1 + PUBLIC_BYTES + 8 + note.len() + 48);
    aad.extend_from_slice(ENTRY_DOMAIN);
    aad.extend_from_slice(name.as_bytes());
    aad.push(0);
    aad.extend_from_slice(ephemeral);
    aad.extend_from_slice(&stored_at.to_be_bytes());
    aad.extend_from_slice(note.as_bytes());
    if metadata.kind != Kind::Secret {
        aad.push(0);
        aad.extend_from_slice(metadata.kind.label().as_bytes());
        aad.push(0);
        if let Some(public) = metadata.signing_public {
            aad.extend_from_slice(&public);
        }
        if let Some(public) = metadata.lms_public {
            aad.extend_from_slice(&public);
        }
        if let Some(next_q) = metadata.lms_next_q {
            aad.extend_from_slice(&next_q.to_be_bytes());
        }
    }
    aad
}

fn load(directory: &Path) -> Result<Option<Document>, VaultError> {
    let path = directory.join(VAULT_FILE_NAME);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let bytes = Zeroizing::new(artifact::read(&path, MAX_VAULT_BYTES)?);
    decode(&bytes).map(Some)
}

fn save(directory: &Path, document: &Document) -> Result<(), VaultError> {
    let bytes = encode(document)?;
    let temporary = temporary_path(directory)?;
    let result = (|| {
        artifact::write_new(&temporary, &bytes, MAX_VAULT_BYTES)?;
        let lms_present = document.entries.iter().any(|entry| entry.kind == Kind::LmsSha256H20W1);
        if lms_present {
            backup::exclude(&temporary, &document.key)?;
        }
        fs::rename(&temporary, directory.join(VAULT_FILE_NAME))?;
        sync_directory(directory)?;
        if lms_present {
            backup::exclude(&directory.join(VAULT_FILE_NAME), &document.key)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _cleanup = fs::remove_file(&temporary);
    }
    result
}

fn temporary_path(directory: &Path) -> Result<PathBuf, VaultError> {
    for _attempt in 0..TEMPORARY_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let candidate = directory.join(format!(".supgang-vault-{}.tmp", hex::encode(random)));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "could not allocate vault replacement").into())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
/// Shared test-only enclave and state fixture.
pub mod tests;
