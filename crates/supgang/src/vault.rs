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
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use minicbor::{Decoder, Encoder};
use p256::{PublicKey, SecretKey, elliptic_curve::sec1::ToSec1Point};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    artifact,
    device_key::custody::{CustodyError, SealedKey},
    storage::{self, no_follow_flag, sync_directory, validate_directory, validate_owner_file_metadata},
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
const VERSION: u8 = 1;
const LOCK_FILE_NAME: &str = "vault.lock";
const AUDIT_LOCK_FILE_NAME: &str = "vault-audit.lock";
const PUBLIC_BYTES: usize = 33;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const MAX_KEY_RECORD_BYTES: usize = 4 * 1024 + 16;
const MAX_ENTRY_BYTES: usize = MAX_NAME_BYTES + MAX_NOTE_BYTES + PUBLIC_BYTES + NONCE_BYTES + MAX_SECRET_BYTES + 64;
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
    /// No secret has this name.
    #[error("no secret named {0} in this computer's vault")]
    NotFound(String),
    /// A secret already has this name and replacement was not requested.
    #[error("a secret named {0} already exists; pass --replace to change it")]
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
}

#[derive(Clone, Eq, PartialEq)]
struct Entry {
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
        }
    }
}

struct Document {
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
    if existing.is_none() && document.entries.len() >= MAX_SECRETS {
        return Err(VaultError::Full);
    }
    let entry = seal(&document.public, name, note, unix_now(), secret)?;
    let summary = entry.summary();
    if let Some(index) = existing {
        document.entries.remove(index);
    }
    document.entries.push(entry);
    document.entries.sort_by(|left, right| left.name.cmp(&right.name));
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
    document.entries.remove(index);
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
    let aad = associated_data(name, note, stored_at, &ephemeral);
    let ciphertext = cipher
        .encrypt(&nonce.into(), Payload { msg: secret, aad: &aad })
        .map_err(|_| VaultError::InvalidSecret)?;
    Ok(Entry {
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
    let aad = associated_data(&entry.name, &entry.note, entry.stored_at, &entry.ephemeral);
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
fn associated_data(name: &str, note: &str, stored_at: u64, ephemeral: &[u8; PUBLIC_BYTES]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENTRY_DOMAIN.len() + name.len() + 1 + PUBLIC_BYTES + 8 + note.len());
    aad.extend_from_slice(ENTRY_DOMAIN);
    aad.extend_from_slice(name.as_bytes());
    aad.push(0);
    aad.extend_from_slice(ephemeral);
    aad.extend_from_slice(&stored_at.to_be_bytes());
    aad.extend_from_slice(note.as_bytes());
    aad
}

/// Canonical CBOR `[1, key-record, public, [[name, note, stored_at, ephemeral, nonce, ciphertext]...]]`.
fn encode(document: &Document) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let key = Zeroizing::new(document.key.encode()?);
    let mut e = Encoder::new(Vec::new());
    let entries = u64::try_from(document.entries.len()).map_err(|_| VaultError::Corrupt)?;
    let mut result = e
        .array(4)
        .and_then(|e| e.u8(VERSION))
        .and_then(|e| e.bytes(&key))
        .and_then(|e| e.bytes(&document.public))
        .and_then(|e| e.array(entries))
        .map(|_| ());
    for entry in &document.entries {
        result = result.and_then(|()| {
            e.array(6)
                .and_then(|e| e.str(&entry.name))
                .and_then(|e| e.str(&entry.note))
                .and_then(|e| e.u64(entry.stored_at))
                .and_then(|e| e.bytes(&entry.ephemeral))
                .and_then(|e| e.bytes(&entry.nonce))
                .and_then(|e| e.bytes(&entry.ciphertext))
                .map(|_| ())
        });
    }
    result.map_err(|_| VaultError::Corrupt)?;
    Ok(Zeroizing::new(e.into_writer()))
}

fn decode(bytes: &[u8]) -> Result<Document, VaultError> {
    let parse = || -> Result<Document, minicbor::decode::Error> {
        let invalid = |reason| minicbor::decode::Error::message(reason);
        let mut d = Decoder::new(bytes);
        if d.array()? != Some(4) || d.u8()? != VERSION {
            return Err(invalid("vault version"));
        }
        let key = SealedKey::decode(d.bytes()?).map_err(|_| invalid("vault key"))?;
        let public = compressed_point(d.bytes()?).map_err(|_| invalid("vault public key"))?;
        let count = d.array()?.ok_or_else(|| invalid("vault entries"))?;
        if count > MAX_SECRETS as u64 {
            return Err(invalid("vault entries"));
        }
        let mut entries = Vec::new();
        for _ in 0..count {
            if d.array()? != Some(6) {
                return Err(invalid("vault entry"));
            }
            let entry = Entry {
                name: d.str()?.to_owned(),
                note: d.str()?.to_owned(),
                stored_at: d.u64()?,
                ephemeral: compressed_point(d.bytes()?).map_err(|_| invalid("vault entry key"))?,
                nonce: d.bytes()?.try_into().map_err(|_| invalid("vault entry nonce"))?,
                ciphertext: d.bytes()?.to_vec(),
            };
            let length = entry.ciphertext.len();
            if validate_name(&entry.name).is_err()
                || validate_note(&entry.note).is_err()
                || !(TAG_BYTES + 1..=TAG_BYTES + MAX_SECRET_BYTES).contains(&length)
                || entries.last().is_some_and(|last: &Entry| last.name >= entry.name)
            {
                return Err(invalid("vault entry"));
            }
            entries.push(entry);
        }
        Ok(Document { key, public, entries })
    };
    let document = parse().map_err(|_| VaultError::Corrupt)?;
    if encode(&document)?.as_slice() != bytes {
        return Err(VaultError::Corrupt);
    }
    Ok(document)
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
        fs::rename(&temporary, directory.join(VAULT_FILE_NAME))?;
        sync_directory(directory)?;
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

/// Records a change after it is saved. Reads record first and refuse when the
/// record fails (see `reveal`); a change already saved is not undone.
fn audit(directory: &Path, operation: &str, name: &str, purpose: Option<&str>) {
    let _result = append_audit(directory, operation, name, purpose);
}

/// Appends one line, `unix-seconds operation name [program]`, under the audit
/// lock. At the bound it keeps the newest half of the newest 256 KiB.
fn append_audit(directory: &Path, operation: &str, name: &str, purpose: Option<&str>) -> Result<(), VaultError> {
    use std::io::{Seek, SeekFrom};
    let _lock = Lock::open(directory, AUDIT_LOCK_FILE_NAME, true)?;
    let path = directory.join(AUDIT_FILE_NAME);
    let existed = fs::symlink_metadata(&path).is_ok();
    let mut file = fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(no_follow_flag()?)
        .open(&path)?;
    if !existed {
        supgang_acl::clear_inherited_acl(&file)?;
    }
    validate_owner_file_metadata(&file)?;
    let program = purpose.map(sanitize_program);
    let line = program.map_or_else(
        || format!("{} {operation} {name}\n", unix_now()),
        |program| format!("{} {operation} {name} {program}\n", unix_now()),
    );
    let length = file.metadata()?.len();
    if length.saturating_add(line.len() as u64) <= MAX_AUDIT_BYTES {
        file.write_all(line.as_bytes())?;
        return Ok(());
    }
    file.seek(SeekFrom::Start(length.saturating_sub(MAX_AUDIT_BYTES)))?;
    let mut kept = Vec::new();
    Read::by_ref(&mut file).take(MAX_AUDIT_BYTES).read_to_end(&mut kept)?;
    let half = kept.len() / 2;
    let start = kept
        .iter()
        .skip(half)
        .position(|byte| *byte == b'\n')
        .map_or(kept.len(), |offset| half + offset + 1);
    let mut replacement = kept.get(start..).unwrap_or_default().to_vec();
    replacement.extend_from_slice(line.as_bytes());
    let temporary = temporary_path(directory)?;
    let result = (|| {
        artifact::write_new(
            &temporary,
            &replacement,
            usize::try_from(MAX_AUDIT_BYTES).unwrap_or(usize::MAX),
        )?;
        fs::rename(&temporary, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _cleanup = fs::remove_file(&temporary);
    }
    result
}

fn sanitize_program(program: &str) -> String {
    let base = program.rsplit('/').next().unwrap_or(program);
    base.chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
        .take(32)
        .collect()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

struct Lock {
    file: fs::File,
}

impl Lock {
    /// The vault's single-writer lock; a second writer is refused, not queued.
    fn acquire(state_directory: &Path) -> Result<(PathBuf, Self), VaultError> {
        let directory = validate_directory(state_directory)?;
        let lock = Self::open(&directory, LOCK_FILE_NAME, false)?;
        Ok((directory, lock))
    }

    /// `wait` blocks for the audit lock, which is held only for one append.
    fn open(directory: &Path, file_name: &str, wait: bool) -> Result<Self, VaultError> {
        let path = directory.join(file_name);
        let existed = fs::symlink_metadata(&path).is_ok();
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(no_follow_flag()?)
            .open(path)?;
        if !existed {
            supgang_acl::clear_inherited_acl(&file)?;
        }
        validate_owner_file_metadata(&file)?;
        let operation = if wait {
            rustix::fs::FlockOperation::LockExclusive
        } else {
            rustix::fs::FlockOperation::NonBlockingLockExclusive
        };
        match rustix::fs::flock(&file, operation) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::WOULDBLOCK => return Err(VaultError::Busy),
            Err(error) => return Err(io::Error::from_raw_os_error(error.raw_os_error()).into()),
        }
        Ok(Self { file })
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _result = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

#[cfg(test)]
mod tests;
