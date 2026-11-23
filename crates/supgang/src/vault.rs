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
use zeroize::Zeroizing;

mod aad;
mod agent_audit;
#[cfg(test)]
mod agent_tests;
mod audit;
mod backup;
mod enclave;
mod error;
mod format;
mod keys;
mod lms;
mod lms_rfc;
mod lock;
mod migration;
mod policy;
#[cfg(test)]
mod remote_ssh_tests;
mod removal;
mod signing;
mod ssh;

use aad::associated_data;
use audit::{append_audit, audit};
pub use enclave::{Enclave, SecureEnclave};
pub use error::VaultError;
use format::{decode, encode};
pub use lms::{
    LmsPublic, LmsSigned, Nc0Package, ReleaseLog, SignPreview, advance as lms_advance, keygen as lms_keygen,
    package as lms_package, preview as lms_preview, public_key as lms_public_key, sign as lms_sign,
};
use lock::Lock;
pub use migration::migrate_agent_policy;
pub use policy::AgentPolicy;
pub use removal::remove;
use signing::fingerprint;
pub(crate) use signing::sign_member;
pub(crate) use signing::verify_signed;
#[cfg(test)]
use signing::{SIGN_DOMAIN, framed_message};
pub use signing::{SignedDigest, SigningPublic, keygen, keygen_agent, public_key, sign, validate_context};
pub use ssh::{SshPublic, SshSigned, ssh_key_blob, ssh_keygen, ssh_public_key, ssh_sign};

/// Format public SSH identity returned by an authenticated remote creation.
#[must_use]
pub(crate) fn ssh_public_from(name: &str, public_key: [u8; 32]) -> SshPublic {
    ssh::public(name, public_key, None)
}

pub(crate) fn keygen_member(
    state_directory: &std::path::Path,
    enclave: &dyn Enclave,
    requester: crate::ids::NodeId,
    request: &crate::agent_keygen_protocol::KeygenRequest,
    session_current: impl Fn() -> bool,
    commit_lock: &std::sync::Mutex<()>,
    prepared: Option<PreparedVault>,
) -> Result<SigningPublic, VaultError> {
    if request.ssh {
        request
            .validate(unix_now())
            .map_err(|_| VaultError::InvalidSigningRequest)?;
        if !request.policy.admits_member(requester) {
            return Err(VaultError::AgentPolicyDenied);
        }
        let public_key = keys::generate_ssh_member(
            state_directory,
            enclave,
            request,
            requester,
            &session_current,
            commit_lock,
            prepared,
        )?;
        return Ok(SigningPublic {
            public_key,
            fingerprint: ssh::fingerprint(&public_key),
        });
    }
    signing::keygen_member(
        state_directory,
        enclave,
        requester,
        request,
        session_current,
        commit_lock,
        prepared,
    )
}

use crate::{
    artifact,
    device_key::custody::SealedKey,
    storage::{sync_directory, validate_directory},
};

/// In-memory Secure Enclave preparation for a first remote purpose key.
/// The restore record never leaves this process or becomes usable until the
/// state owner commits the key and its audit record together.
pub(crate) struct PreparedVault {
    key: SealedKey,
    public: [u8; PUBLIC_BYTES],
    nonce: [u8; 32],
}

/// Prepare a first vault agreement key without a durable write.
/// The potentially slow Secure Enclave operation runs off the service event
/// thread; the later authorized key commit remains on that thread.
pub(crate) fn prepare_member_vault(
    state_directory: &Path,
    enclave: &dyn Enclave,
    requester: crate::ids::NodeId,
    request: &crate::agent_keygen_protocol::KeygenRequest,
    session_current: impl Fn() -> bool,
) -> Result<Option<PreparedVault>, VaultError> {
    request
        .validate(unix_now())
        .map_err(|_| VaultError::InvalidSigningRequest)?;
    if !request.policy.admits_member(requester) || !session_current() {
        return Err(VaultError::MemberAuthority);
    }
    if request.ssh {
        let state = crate::state::open_read_only(state_directory).map_err(|_| VaultError::MemberAuthority)?;
        if state.identity().root.is_some() {
            return Err(VaultError::MemberAuthority);
        }
    }
    if request.ssh {
        signing::current_member_for_ssh_target(state_directory, requester)?;
    } else {
        signing::current_member_for(state_directory, requester)?;
    }
    let (directory, _lock) = Lock::acquire(state_directory)?;
    if load(&directory)?.is_some() {
        return Ok(None);
    }
    let (key, public) = enclave.generate()?;
    request
        .validate(unix_now())
        .map_err(|_| VaultError::InvalidSigningRequest)?;
    if !session_current() {
        return Err(VaultError::MemberAuthority);
    }
    if request.ssh {
        signing::current_member_for_ssh_target(state_directory, requester)?;
    } else {
        signing::current_member_for(state_directory, requester)?;
    }
    Ok(Some(PreparedVault {
        key,
        public,
        nonce: request.nonce,
    }))
}

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
const VERSION: u8 = 6;
const LOCK_FILE_NAME: &str = "vault.lock";
const AUDIT_LOCK_FILE_NAME: &str = "vault-audit.lock";
const PUBLIC_BYTES: usize = 33;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const MAX_KEY_RECORD_BYTES: usize = 4 * 1024 + 16;
const MAX_ENTRY_BYTES: usize = MAX_NAME_BYTES
    + MAX_NOTE_BYTES
    + PUBLIC_BYTES
    + NONCE_BYTES
    + MAX_SECRET_BYTES
    + policy::MAX_POLICY_BYTES
    + 4 * 1024
    + 256;
const MAX_VAULT_BYTES: usize = MAX_KEY_RECORD_BYTES + PUBLIC_BYTES + MAX_SECRETS * MAX_ENTRY_BYTES + 64;
const MAX_AUDIT_BYTES: u64 = 256 * 1024;
const TEMPORARY_ATTEMPTS: usize = 8;

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
    /// Member that requested creation on this device, for remote SSH keys.
    pub remote_creator: Option<crate::ids::NodeId>,
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
    policy: Option<Vec<u8>>,
    remote_creator: Option<crate::ids::NodeId>,
    lms_presence: Option<lms::PresenceWrap>,
}

impl Entry {
    fn summary(&self) -> Summary {
        Summary {
            name: self.name.clone(),
            note: self.note.clone(),
            stored_at: self.stored_at,
            bytes: if self.kind == Kind::LmsSha256H20W1 && self.lms_presence.is_some() {
                48
            } else {
                self.ciphertext.len().saturating_sub(TAG_BYTES)
            },
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
            remote_creator: self.remote_creator,
        }
    }
}

#[derive(Clone)]
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
            remote_creator: None,
            presence_digest: None,
        },
        None,
    )
}

#[derive(Clone, Copy)]
struct SealMetadata {
    kind: Kind,
    signing_public: Option<[u8; 32]>,
    lms_public: Option<[u8; lms_rfc::PUBLIC_LEN]>,
    lms_next_q: Option<u32>,
    remote_creator: Option<crate::ids::NodeId>,
    presence_digest: Option<[u8; 32]>,
}

fn seal_entry(
    public: &[u8; PUBLIC_BYTES],
    name: &str,
    note: &str,
    stored_at: u64,
    secret: &[u8],
    metadata: SealMetadata,
    policy: Option<&[u8]>,
) -> Result<Entry, VaultError> {
    if let Some(policy) = policy
        && (!matches!(metadata.kind, Kind::SigningEd25519 | Kind::SshEd25519)
            || AgentPolicy::decode(policy).is_err()
            || (metadata.kind == Kind::SshEd25519
                && AgentPolicy::decode(policy).is_ok_and(|policy| policy.contexts() != ["ssh.keygen"])))
    {
        return Err(VaultError::InvalidAgentPolicy);
    }
    if metadata.remote_creator.is_some() != (metadata.kind == Kind::SshEd25519 && policy.is_some()) {
        return Err(VaultError::InvalidAgentPolicy);
    }
    let recipient = PublicKey::from_sec1_bytes(public).map_err(|_| VaultError::Corrupt)?;
    let ephemeral_secret = random_secret_key()?;
    let ephemeral = compressed_point(ephemeral_secret.public_key().to_sec1_point(true).as_bytes())?;
    let shared = p256::ecdh::diffie_hellman(ephemeral_secret.to_nonzero_scalar(), recipient.as_affine());
    let mut raw = Zeroizing::new([0_u8; 32]);
    raw.copy_from_slice(shared.raw_secret_bytes());
    let cipher = cipher(&raw, &ephemeral, public, name)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    let aad = associated_data(name, note, stored_at, &ephemeral, &metadata, policy);
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
        policy: policy.map(<[u8]>::to_vec),
        remote_creator: metadata.remote_creator,
        lms_presence: None,
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
            remote_creator: entry.remote_creator,
            presence_digest: entry.lms_presence.as_ref().map(lms::PresenceWrap::digest),
        },
        entry.policy.as_deref(),
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

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
/// Shared test-only enclave and state fixture.
pub mod tests;
