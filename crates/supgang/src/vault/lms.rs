//! Single-purpose NC0 LMS root with crash-durable one-time q reservations.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    Document, Enclave, Kind, Lock, MAX_SECRETS, SealMetadata, VERSION, VaultError, append_audit, audit, backup,
    lms_rfc, load, open, save, seal_entry, unix_now, validate_name, validate_note,
};
use crate::{
    device_key::custody::SealedKey,
    storage::{no_follow_flag, sync_directory, validate_directory, validate_owner_file_metadata},
};

const MAX_Q: u32 = 1 << lms_rfc::HEIGHT;
const JOURNAL_MAGIC: &[u8; 8] = b"SG-LMS1\0";
const RECORD_BYTES: usize = 108;
const MAX_PACKAGE_BYTES: u64 = 0x1fff_ffff;

/// The fixed 56-byte LMS public key and its SHA-256 fingerprint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LmsPublic {
    /// RFC 8554 public key bytes, type 8 and OTS type 1.
    pub public_key: [u8; lms_rfc::PUBLIC_LEN],
    /// Lowercase SHA-256 over all 56 public bytes.
    pub fingerprint: String,
}

/// External release-log check required for each signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseLog {
    /// Only when both records prove that no q has ever been reserved.
    FirstSignature,
    /// Highest q already recorded in the independent release log.
    After(u32),
}

/// A bounded, validated NC0 unsigned package digest.
pub struct Nc0Package {
    digest: [u8; 32],
    bytes: u64,
}

impl Nc0Package {
    /// SHA-256 over the validated 64-byte header and payload.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Number of header and payload bytes, excluding the signature.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// State shown at the owner confirmation prompt.
pub struct SignPreview {
    /// Next q that signing would reserve.
    pub q: u32,
    /// Signatures remaining, including this one.
    pub remaining: u32,
    /// Public key identity of the LMS root.
    pub identity: LmsPublic,
}

/// A signature with the q consumed before it was released.
pub struct LmsSigned {
    /// The leaf number consumed by this signature.
    pub q: u32,
    /// Exactly 9164 RFC 8554 signature bytes.
    pub signature: Vec<u8>,
    /// The key used to sign.
    pub identity: LmsPublic,
}

struct JournalHead {
    next_q: u32,
    hash: [u8; 32],
    records: u32,
}

struct LmsPrivate {
    seed: Zeroizing<[u8; 32]>,
    id: Zeroizing<[u8; 16]>,
    identity: LmsPublic,
    next_q: u32,
}

fn identity(public: [u8; lms_rfc::PUBLIC_LEN]) -> LmsPublic {
    LmsPublic {
        public_key: public,
        fingerprint: hex::encode(Sha256::digest(public)),
    }
}

fn journal_path(directory: &Path, name: &str) -> PathBuf {
    directory.join(format!("vault-lms-{name}.journal"))
}

fn record(public: &[u8; lms_rfc::PUBLIC_LEN], next_q: u32, previous: &[u8; 32]) -> [u8; RECORD_BYTES] {
    let mut bytes = [0_u8; RECORD_BYTES];
    bytes[..8].copy_from_slice(JOURNAL_MAGIC);
    bytes[8..40].copy_from_slice(&Sha256::digest(public));
    bytes[40..44].copy_from_slice(&next_q.to_be_bytes());
    bytes[44..76].copy_from_slice(previous);
    let hash = Sha256::digest(&bytes[..76]);
    bytes[76..].copy_from_slice(&hash);
    bytes
}

fn read_journal(directory: &Path, name: &str, public: &[u8; lms_rfc::PUBLIC_LEN]) -> Result<JournalHead, VaultError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(no_follow_flag()?)
        .open(journal_path(directory, name))?;
    validate_owner_file_metadata(&file)?;
    let size = file.metadata()?.len();
    let max = u64::from(MAX_Q + 1) * RECORD_BYTES as u64;
    if size < RECORD_BYTES as u64 || size > max || size % RECORD_BYTES as u64 != 0 {
        return Err(VaultError::Corrupt);
    }
    let count = u32::try_from(size / RECORD_BYTES as u64).map_err(|_| VaultError::Corrupt)?;
    let mut reader = io::BufReader::new(file);
    let mut previous_hash = [0_u8; 32];
    let mut previous_q = 0_u32;
    for index in 0..count {
        let mut bytes = [0_u8; RECORD_BYTES];
        reader.read_exact(&mut bytes)?;
        let q = u32::from_be_bytes(bytes[40..44].try_into().map_err(|_| VaultError::Corrupt)?);
        let expected = record(public, q, &previous_hash);
        if bytes != expected || q > MAX_Q || (index == 0 && q != 0) || (index > 0 && q <= previous_q) {
            return Err(VaultError::Corrupt);
        }
        previous_hash.copy_from_slice(&bytes[76..]);
        previous_q = q;
    }
    Ok(JournalHead {
        next_q: previous_q,
        hash: previous_hash,
        records: count,
    })
}

fn create_journal(
    directory: &Path,
    name: &str,
    public: &[u8; lms_rfc::PUBLIC_LEN],
    key: &SealedKey,
) -> Result<(), VaultError> {
    let path = journal_path(directory, name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(no_follow_flag()?)
        .open(&path)?;
    let result = (|| {
        supgang_acl::clear_inherited_acl(&file)?;
        validate_owner_file_metadata(&file)?;
        file.write_all(&record(public, 0, &[0_u8; 32]))?;
        file.sync_all()?;
        sync_directory(directory)?;
        backup::exclude(&path, key)?;
        Ok(())
    })();
    drop(file);
    if let Err(error) = result {
        if fs::remove_file(&path).is_err() || sync_directory(directory).is_err() {
            return Err(VaultError::LmsOrphanCleanup);
        }
        return Err(error);
    }
    Ok(())
}

fn recover_pristine_orphan(directory: &Path, name: &str) -> Result<(), VaultError> {
    let path = journal_path(directory, name);
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(no_follow_flag()?)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    validate_owner_file_metadata(&file)?;
    if file.metadata()?.len() != RECORD_BYTES as u64 {
        return Err(VaultError::Corrupt);
    }
    let mut bytes = [0_u8; RECORD_BYTES];
    file.read_exact(&mut bytes)?;
    if bytes[..8] != *JOURNAL_MAGIC
        || bytes[40..44] != 0_u32.to_be_bytes()
        || bytes[44..76].iter().any(|byte| *byte != 0)
        || bytes[76..] != Sha256::digest(&bytes[..76])[..]
    {
        return Err(VaultError::Corrupt);
    }
    drop(file);
    append_audit(directory, "replace-pristine-lms-orphan", name, None).map_err(|_| VaultError::Audit)?;
    fs::remove_file(&path).map_err(|_| VaultError::LmsOrphanCleanup)?;
    sync_directory(directory).map_err(|_| VaultError::LmsOrphanCleanup)?;
    Ok(())
}

fn save_or_cleanup(
    directory: &Path,
    name: &str,
    public: &[u8; lms_rfc::PUBLIC_LEN],
    result: Result<(), VaultError>,
) -> Result<(), VaultError> {
    let Err(error) = result else { return Ok(()) };
    let committed = match load(directory) {
        Ok(Some(document)) => match document.entries.iter().find(|entry| entry.name == name) {
            Some(entry) if entry.lms_public.as_ref() == Some(public) => true,
            Some(_) => return Err(VaultError::LmsOrphanCleanup),
            None => false,
        },
        Ok(None) => false,
        Err(_) => return Err(VaultError::LmsOrphanCleanup),
    };
    if !committed {
        fs::remove_file(journal_path(directory, name)).map_err(|_| VaultError::LmsOrphanCleanup)?;
        sync_directory(directory).map_err(|_| VaultError::LmsOrphanCleanup)?;
    }
    Err(error)
}

fn append_journal(
    directory: &Path,
    name: &str,
    public: &[u8; lms_rfc::PUBLIC_LEN],
    head: &JournalHead,
    target: u32,
    key: &SealedKey,
) -> Result<(), VaultError> {
    if target <= head.next_q || target > MAX_Q {
        return Err(VaultError::Corrupt);
    }
    let path = journal_path(directory, name);
    let mut file = OpenOptions::new()
        .append(true)
        .custom_flags(no_follow_flag()?)
        .open(&path)?;
    validate_owner_file_metadata(&file)?;
    let expected_len = u64::from(head.records) * RECORD_BYTES as u64;
    if file.metadata()?.len() != expected_len {
        return Err(VaultError::Corrupt);
    }
    file.write_all(&record(public, target, &head.hash))?;
    file.sync_all()?;
    sync_directory(directory)?;
    backup::exclude(&path, key)?;
    Ok(())
}

fn entry_index(document: &Document, name: &str) -> Result<usize, VaultError> {
    let index = document
        .entries
        .iter()
        .position(|entry| entry.name == name)
        .ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    if document.entries.get(index).ok_or(VaultError::Corrupt)?.kind != Kind::LmsSha256H20W1 {
        return Err(VaultError::NotLmsKey);
    }
    Ok(index)
}

fn open_private(document: &Document, index: usize, enclave: &dyn Enclave) -> Result<LmsPrivate, VaultError> {
    let entry = document.entries.get(index).ok_or(VaultError::Corrupt)?;
    let public = entry.lms_public.ok_or(VaultError::Corrupt)?;
    let next_q = entry.lms_next_q.ok_or(VaultError::Corrupt)?;
    let shared = enclave.agree(&document.key, &entry.ephemeral)?;
    let secret = open(&shared, &document.public, entry)?;
    if secret.len() != 48 || public.get(8..24) != secret.get(32..48) {
        return Err(VaultError::Corrupt);
    }
    let (seed_bytes, id_bytes) = secret.split_at(32);
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(seed_bytes);
    let mut id = Zeroizing::new([0_u8; 16]);
    id.copy_from_slice(id_bytes);
    Ok(LmsPrivate {
        seed,
        id,
        identity: identity(public),
        next_q,
    })
}

const fn check_external(log: ReleaseLog, q: u32, head: &JournalHead) -> Result<(), VaultError> {
    match log {
        ReleaseLog::FirstSignature if q == 0 && head.records == 1 => Ok(()),
        ReleaseLog::After(previous) if q > previous => Ok(()),
        _ => Err(VaultError::LmsReleaseLog),
    }
}

fn reseal_next_q(document: &mut Document, index: usize, private: &LmsPrivate, next_q: u32) -> Result<(), VaultError> {
    let entry = document.entries.get(index).ok_or(VaultError::Corrupt)?;
    let name = entry.name.clone();
    let note = entry.note.clone();
    let stored_at = entry.stored_at;
    let mut secret = Zeroizing::new([0_u8; 48]);
    let (seed_bytes, id_bytes) = secret.split_at_mut(32);
    seed_bytes.copy_from_slice(private.seed.as_ref());
    id_bytes.copy_from_slice(private.id.as_ref());
    let replacement = seal_entry(
        &document.public,
        &name,
        &note,
        stored_at,
        secret.as_ref(),
        SealMetadata {
            kind: Kind::LmsSha256H20W1,
            signing_public: None,
            lms_public: Some(private.identity.public_key),
            lms_next_q: Some(next_q),
        },
        None,
    )?;
    *document.entries.get_mut(index).ok_or(VaultError::Corrupt)? = replacement;
    document.version = VERSION;
    Ok(())
}

/// Generate an H20/W1 root using streaming treehash, then seal SEED and I.
///
/// # Errors
/// Refuses invalid names, collisions, unavailable custody and storage errors.
pub fn keygen(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    note: &str,
    progress: impl FnMut(u32, u32),
) -> Result<LmsPublic, VaultError> {
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
    recover_pristine_orphan(&directory, name)?;
    if document.entries.len() >= MAX_SECRETS {
        return Err(VaultError::Full);
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    let mut id = Zeroizing::new([0_u8; 16]);
    getrandom::fill(seed.as_mut()).map_err(io::Error::other)?;
    getrandom::fill(id.as_mut()).map_err(io::Error::other)?;
    let (root, _) = lms_rfc::tree(&seed, &id, lms_rfc::HEIGHT, lms_rfc::WIDTH, None, progress)?;
    let identity = identity(lms_rfc::public_key(&id, &root));
    let mut private = Zeroizing::new([0_u8; 48]);
    let (seed_bytes, id_bytes) = private.split_at_mut(32);
    seed_bytes.copy_from_slice(seed.as_ref());
    id_bytes.copy_from_slice(id.as_ref());
    let entry = seal_entry(
        &document.public,
        name,
        note,
        unix_now(),
        private.as_ref(),
        SealMetadata {
            kind: Kind::LmsSha256H20W1,
            signing_public: None,
            lms_public: Some(identity.public_key),
            lms_next_q: Some(0),
        },
        None,
    )?;
    document.version = VERSION;
    document.entries.push(entry);
    document.entries.sort_by(|left, right| left.name.cmp(&right.name));
    create_journal(&directory, name, &identity.public_key, &document.key)?;
    save_or_cleanup(&directory, name, &identity.public_key, save(&directory, &document))?;
    audit(&directory, "add-lms", name, None);
    Ok(identity)
}

/// Read the authenticated 56-byte LMS public key.
///
/// # Errors
/// Refuses unknown or malformed entries and unavailable custody.
pub fn public_key(state_directory: &Path, enclave: &dyn Enclave, name: &str) -> Result<LmsPublic, VaultError> {
    validate_name(name)?;
    let directory = validate_directory(state_directory)?;
    let document = load(&directory)?.ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    let index = entry_index(&document, name)?;
    Ok(open_private(&document, index, enclave)?.identity)
}

/// Validate and hash an unsigned format-2 NC0 package. No raw-digest API exists.
///
/// # Errors
/// Refuses malformed, oversized, or changing files.
pub fn package(path: &Path) -> Result<Nc0Package, VaultError> {
    let mut file = File::open(path)?;
    let bytes = file.metadata()?.len();
    let sig_bytes = u64::try_from(lms_rfc::SIGNATURE_LEN).map_err(|_| VaultError::InvalidNc0Package)?;
    if !(65..=MAX_PACKAGE_BYTES - sig_bytes).contains(&bytes) {
        return Err(VaultError::InvalidNc0Package);
    }
    let mut header = [0_u8; 64];
    file.read_exact(&mut header)?;
    let mut words = [0_u32; 16];
    for (word, chunk) in words.iter_mut().zip(header.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }
    let [
        magic,
        format,
        scheme,
        header_len,
        total_len,
        payload_len,
        flags,
        signature_len,
        helper_offset,
        reserved,
        helper_len,
        _security_version,
        zero_12,
        zero_13,
        zero_14,
        zero_15,
    ] = words;
    let payload = bytes - 64;
    if magic != 0x0400_006f
        || format != 2
        || scheme != 3
        || header_len != 64
        || u64::from(total_len) != bytes + sig_bytes
        || u64::from(payload_len) != payload
        || payload_len == 0
        || flags & !1 != 0
        || signature_len != u32::try_from(lms_rfc::SIGNATURE_LEN).map_err(|_| VaultError::InvalidNc0Package)?
        || [helper_offset, reserved, helper_len, zero_12, zero_13, zero_14, zero_15]
            .iter()
            .any(|word| *word != 0)
    {
        return Err(VaultError::InvalidNc0Package);
    }
    let mut hasher = Sha256::new();
    hasher.update(header);
    let mut buffer = [0_u8; 8 * 1024];
    let mut remaining = payload;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| VaultError::InvalidNc0Package)?;
        let read = file.read(buffer.get_mut(..count).ok_or(VaultError::InvalidNc0Package)?)?;
        if read == 0 {
            return Err(VaultError::InvalidNc0Package);
        }
        hasher.update(buffer.get(..read).ok_or(VaultError::InvalidNc0Package)?);
        remaining -= read as u64;
    }
    if file.read(&mut [0_u8; 1])? != 0 {
        return Err(VaultError::InvalidNc0Package);
    }
    Ok(Nc0Package {
        digest: hasher.finalize().into(),
        bytes,
    })
}

/// Verify both local records and external release-log evidence before prompting.
///
/// # Errors
/// Refuses any mismatch, exhausted root or stale external log.
pub fn preview(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    log: ReleaseLog,
) -> Result<SignPreview, VaultError> {
    validate_name(name)?;
    let directory = validate_directory(state_directory)?;
    let document = load(&directory)?.ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    let index = entry_index(&document, name)?;
    let private = open_private(&document, index, enclave)?;
    let head = read_journal(&directory, name, &private.identity.public_key)?;
    if private.next_q != head.next_q {
        return Err(VaultError::LmsStateMismatch);
    }
    if private.next_q >= MAX_Q {
        return Err(VaultError::LmsExhausted);
    }
    check_external(log, private.next_q, &head)?;
    Ok(SignPreview {
        q: private.next_q,
        remaining: MAX_Q - private.next_q,
        identity: private.identity,
    })
}

/// Reserve q durably, recompute its path, then sign the validated NC0 digest.
///
/// # Errors
/// Refuses stale previews, record disagreement, exhausted q, or storage failure.
pub fn sign(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    package: &Nc0Package,
    log: ReleaseLog,
    expected_q: u32,
    progress: impl FnMut(u32, u32),
) -> Result<LmsSigned, VaultError> {
    validate_name(name)?;
    let (directory, _lock) = Lock::acquire(state_directory)?;
    append_audit(&directory, "lms-sign", name, None).map_err(|_| VaultError::Audit)?;
    let (private, q) = reserve_locked(&directory, enclave, name, log, expected_q)?;
    let (root, path) = lms_rfc::tree(
        &private.seed,
        &private.id,
        lms_rfc::HEIGHT,
        lms_rfc::WIDTH,
        Some(q),
        progress,
    )?;
    if private.identity.public_key.get(24..) != Some(root.as_slice()) {
        return Err(VaultError::Corrupt);
    }
    let mut randomizer = [0_u8; 32];
    getrandom::fill(&mut randomizer).map_err(io::Error::other)?;
    let signature = lms_rfc::sign_with_path(&private.seed, &private.id, q, &package.digest, &randomizer, &path)?;
    if signature.len() != lms_rfc::SIGNATURE_LEN
        || !lms_rfc::verify_fixed(&private.identity.public_key, &package.digest, &signature)
    {
        return Err(VaultError::Corrupt);
    }
    Ok(LmsSigned {
        q,
        signature,
        identity: private.identity,
    })
}

fn reserve_locked(
    directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    log: ReleaseLog,
    expected_q: u32,
) -> Result<(LmsPrivate, u32), VaultError> {
    let mut document = load(directory)?.ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    let index = entry_index(&document, name)?;
    let private = open_private(&document, index, enclave)?;
    let q = private.next_q;
    let head = read_journal(directory, name, &private.identity.public_key)?;
    if q != head.next_q || q != expected_q {
        return Err(VaultError::LmsStateMismatch);
    }
    if q >= MAX_Q {
        return Err(VaultError::LmsExhausted);
    }
    check_external(log, q, &head)?;
    append_journal(
        directory,
        name,
        &private.identity.public_key,
        &head,
        q + 1,
        &document.key,
    )?;
    reseal_next_q(&mut document, index, &private, q + 1)?;
    save(directory, &document)?;
    Ok((private, q))
}

/// Burn all q below `target`, even when readable local records disagree.
///
/// # Errors
/// Refuses unreadable records, backward targets, or stale release-log evidence.
pub fn advance(
    state_directory: &Path,
    enclave: &dyn Enclave,
    name: &str,
    target: u32,
    after_q: u32,
) -> Result<LmsPublic, VaultError> {
    validate_name(name)?;
    let (directory, _lock) = Lock::acquire(state_directory)?;
    let mut document = load(&directory)?.ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    let index = entry_index(&document, name)?;
    let private = open_private(&document, index, enclave)?;
    let head = read_journal(&directory, name, &private.identity.public_key)?;
    if target <= private.next_q.max(head.next_q) || target <= after_q || target > MAX_Q {
        return Err(VaultError::LmsAdvanceRefused);
    }
    append_journal(
        &directory,
        name,
        &private.identity.public_key,
        &head,
        target,
        &document.key,
    )?;
    reseal_next_q(&mut document, index, &private, target)?;
    save(&directory, &document)?;
    audit(&directory, "lms-advance", name, None);
    Ok(private.identity)
}

#[cfg(test)]
mod tests;
