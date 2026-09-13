//! Crash-safe, checksummed append-only storage for authoritative state.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::{fs::OpenOptionsExt, prelude::MetadataExt},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use thiserror::Error;

mod witness;

use witness::JournalWitness;

/// Maximum payload accepted in one journal frame.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Maximum journal size before compaction is required.
pub const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

const JOURNAL_MAGIC: &[u8; 8] = b"SUPGJNL1";
const CHECKSUM_BYTES: usize = 32;
const LENGTH_BYTES: usize = 4;
const CHECKSUM_DOMAIN: &[u8] = b"supgang/journal-frame/v1\0";

/// A durable append-only journal owned by one Supgang service process.
#[derive(Debug)]
pub struct Journal {
    file: File,
    path: PathBuf,
    witness_path: PathBuf,
    hasher: Sha256,
    frame_count: u64,
}

/// A journal open, validation, or persistence failure.
#[derive(Debug, Error)]
pub enum JournalError {
    /// The operating system rejected a filesystem operation.
    #[error("journal filesystem operation failed")]
    Io(#[from] io::Error),
    /// The target exists but is not a regular file.
    #[error("journal path is not a regular file")]
    NotRegularFile,
    /// The journal is owned by another operating-system user.
    #[error("journal is not owned by the current user")]
    WrongOwner,
    /// The journal is readable or writable by another user.
    #[error("journal permissions must be 0600")]
    InsecurePermissions,
    /// An extended ACL grants access beyond the owner-only mode policy.
    #[error("journal has a non-owner ACL grant")]
    InsecureAcl,
    /// The journal does not start with the expected format marker.
    #[error("journal header is invalid")]
    InvalidHeader,
    /// A complete frame failed its cryptographic checksum.
    #[error("journal frame checksum is invalid at byte offset {offset}")]
    Checksum {
        /// Byte offset at which the corrupt frame began.
        offset: u64,
    },
    /// A frame claimed more bytes than the protocol permits.
    #[error("journal frame exceeds the fixed size limit at byte offset {offset}")]
    OversizedFrame {
        /// Byte offset at which the oversized frame began.
        offset: u64,
    },
    /// The journal reached its fixed storage ceiling.
    #[error("journal reached its size limit and must be compacted")]
    JournalFull,
    /// The journal is older than, or inconsistent with, its last committed head.
    #[error("journal rollback or ambiguous compaction requires explicit recovery")]
    Rollback,
    /// The caller attempted to append an empty or oversized payload.
    #[error("journal payload must contain between 1 and 65536 bytes")]
    InvalidPayload,
}

impl Journal {
    /// Opens or creates a journal, validates every complete frame, and removes
    /// only an incomplete final frame left by an interrupted append.
    ///
    /// The parent directory must already exist and be protected by the caller.
    ///
    /// # Errors
    ///
    /// Rejects symlinks, non-regular files, foreign ownership, permissive file
    /// modes, invalid headers, oversized frames, and checksum corruption.
    pub fn open(path: impl AsRef<Path>) -> Result<(Self, Vec<Vec<u8>>), JournalError> {
        let path = path.as_ref().to_path_buf();
        let no_follow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).map_err(|_| JournalError::InvalidHeader)?;
        let mut create_options = OpenOptions::new();
        create_options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(no_follow);
        let (mut file, created) = match create_options.open(&path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(no_follow)
                    .open(&path)?,
                false,
            ),
            Err(error) => return Err(error.into()),
        };
        if created {
            supgang_acl::clear_inherited_acl(&file)?;
        }
        validate_metadata(&file)?;

        let length = file.metadata()?.len();
        if length == 0 {
            file.write_all(JOURNAL_MAGIC)?;
            file.sync_all()?;
        }

        let ReadFrames {
            mut frames,
            mut valid_length,
            actual_length,
            bytes,
        } = read_frames(&mut file)?;
        let witness_path = witness::path_for(&path)?;
        let current = journal_witness(
            bytes
                .get(..usize::try_from(valid_length).map_err(|_| JournalError::JournalFull)?)
                .ok_or(JournalError::Rollback)?,
            frames.len(),
        )?;
        match witness::read(&witness_path)? {
            None => {
                if valid_length != actual_length {
                    return Err(JournalError::Rollback);
                }
                witness::write(&witness_path, &current)?;
            }
            Some(expected) if expected == current => {}
            Some(expected) if expected.length <= valid_length => {
                let prefix = bytes
                    .get(..usize::try_from(expected.length).map_err(|_| JournalError::Rollback)?)
                    .ok_or(JournalError::Rollback)?;
                let (prefix_frames, prefix_length) = parse_frames(prefix)?;
                if prefix_length != expected.length || journal_witness(prefix, prefix_frames.len())? != expected {
                    return Err(JournalError::Rollback);
                }
                frames = prefix_frames;
                valid_length = expected.length;
            }
            Some(_) => return Err(JournalError::Rollback),
        }
        if valid_length < actual_length {
            file.set_len(valid_length)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::End(0))?;
        let committed = bytes
            .get(..usize::try_from(valid_length).map_err(|_| JournalError::JournalFull)?)
            .ok_or(JournalError::Rollback)?;
        let mut hasher = Sha256::new();
        hasher.update(committed);

        Ok((
            Self {
                file,
                path,
                witness_path,
                hasher,
                frame_count: u64::try_from(frames.len()).map_err(|_| JournalError::JournalFull)?,
            },
            frames,
        ))
    }

    /// Reads and validates an existing journal without creating or repairing it.
    ///
    /// An incomplete final frame is ignored in the returned snapshot but is
    /// deliberately left untouched for the exclusive writer to recover.
    ///
    /// # Errors
    ///
    /// Rejects missing, unsafe, oversized, corrupt, or malformed journals.
    pub fn read(path: impl AsRef<Path>) -> Result<Vec<Vec<u8>>, JournalError> {
        let path = path.as_ref();
        let no_follow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).map_err(|_| JournalError::InvalidHeader)?;
        let mut file = OpenOptions::new().read(true).custom_flags(no_follow).open(path)?;
        validate_metadata(&file)?;
        let ReadFrames {
            frames,
            valid_length,
            bytes,
            ..
        } = read_frames(&mut file)?;
        let witness_path = witness::path_for(path)?;
        let expected = witness::read(&witness_path)?.ok_or(JournalError::Rollback)?;
        let current = journal_witness(
            bytes
                .get(..usize::try_from(valid_length).map_err(|_| JournalError::JournalFull)?)
                .ok_or(JournalError::Rollback)?,
            frames.len(),
        )?;
        if expected == current {
            return Ok(frames);
        }
        let prefix = bytes
            .get(..usize::try_from(expected.length).map_err(|_| JournalError::Rollback)?)
            .ok_or(JournalError::Rollback)?;
        let (prefix_frames, prefix_length) = parse_frames(prefix)?;
        if prefix_length == expected.length && journal_witness(prefix, prefix_frames.len())? == expected {
            Ok(prefix_frames)
        } else {
            Err(JournalError::Rollback)
        }
    }

    /// Appends and synchronizes one complete frame before returning.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized payloads and a journal that would exceed its
    /// fixed storage ceiling. I/O errors are returned only after the operation
    /// has stopped; callers must reopen and validate before retrying.
    pub fn append(&mut self, payload: &[u8]) -> Result<(), JournalError> {
        if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
            return Err(JournalError::InvalidPayload);
        }
        let payload_length = u32::try_from(payload.len()).map_err(|_| JournalError::InvalidPayload)?;
        let length_bytes = payload_length.to_be_bytes();
        let checksum = checksum(length_bytes, payload);
        let frame_length =
            u64::try_from(LENGTH_BYTES + payload.len() + CHECKSUM_BYTES).map_err(|_| JournalError::JournalFull)?;
        let current_length = self.file.seek(SeekFrom::End(0))?;
        if current_length.saturating_add(frame_length) > MAX_JOURNAL_BYTES {
            return Err(JournalError::JournalFull);
        }

        self.file.write_all(&length_bytes)?;
        self.file.write_all(payload)?;
        self.file.write_all(&checksum)?;
        self.file.sync_data()?;
        let mut next_hasher = self.hasher.clone();
        next_hasher.update(length_bytes);
        next_hasher.update(payload);
        next_hasher.update(checksum);
        let next_count = self.frame_count.checked_add(1).ok_or(JournalError::JournalFull)?;
        witness::write(
            &self.witness_path,
            &JournalWitness::new(
                current_length.saturating_add(frame_length),
                next_count,
                next_hasher.clone().finalize().into(),
            ),
        )?;
        self.hasher = next_hasher;
        self.frame_count = next_count;
        Ok(())
    }

    /// Appends a bounded group of frames with one durability synchronization.
    pub(crate) fn append_batch(&mut self, payloads: &[Vec<u8>]) -> Result<(), JournalError> {
        let additional_length = payloads.iter().try_fold(0_u64, |total, payload| {
            if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
                return Err(JournalError::InvalidPayload);
            }
            let frame_length =
                u64::try_from(LENGTH_BYTES + payload.len() + CHECKSUM_BYTES).map_err(|_| JournalError::JournalFull)?;
            total.checked_add(frame_length).ok_or(JournalError::JournalFull)
        })?;
        let current_length = self.file.seek(SeekFrom::End(0))?;
        if current_length.saturating_add(additional_length) > MAX_JOURNAL_BYTES {
            return Err(JournalError::JournalFull);
        }
        for payload in payloads {
            write_frame(&mut self.file, payload)?;
        }
        self.file.sync_data()?;
        let next_count = self
            .frame_count
            .checked_add(u64::try_from(payloads.len()).map_err(|_| JournalError::JournalFull)?)
            .ok_or(JournalError::JournalFull)?;
        let mut next_hasher = self.hasher.clone();
        for payload in payloads {
            update_frame_hash(&mut next_hasher, payload)?;
        }
        witness::write(
            &self.witness_path,
            &JournalWitness::new(
                current_length.saturating_add(additional_length),
                next_count,
                next_hasher.clone().finalize().into(),
            ),
        )?;
        self.hasher = next_hasher;
        self.frame_count = next_count;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn append_repeated_until_len_for_test(
        &mut self,
        payload: &[u8],
        minimum_length: u64,
    ) -> Result<usize, JournalError> {
        if payload.is_empty() || payload.len() > MAX_FRAME_BYTES || minimum_length > MAX_JOURNAL_BYTES {
            return Err(JournalError::InvalidPayload);
        }
        let frame_length =
            u64::try_from(LENGTH_BYTES + payload.len() + CHECKSUM_BYTES).map_err(|_| JournalError::JournalFull)?;
        let current_length = self.file.seek(SeekFrom::End(0))?;
        let missing = minimum_length.saturating_sub(current_length);
        let repeats = missing.saturating_add(frame_length.saturating_sub(1)) / frame_length;
        if current_length.saturating_add(repeats.saturating_mul(frame_length)) > MAX_JOURNAL_BYTES {
            return Err(JournalError::JournalFull);
        }
        for _ in 0..repeats {
            write_frame(&mut self.file, payload)?;
        }
        self.file.sync_data()?;
        let next_count = self.frame_count.checked_add(repeats).ok_or(JournalError::JournalFull)?;
        let mut next_hasher = self.hasher.clone();
        for _ in 0..repeats {
            update_frame_hash(&mut next_hasher, payload)?;
        }
        witness::write(
            &self.witness_path,
            &JournalWitness::new(
                current_length.saturating_add(repeats.saturating_mul(frame_length)),
                next_count,
                next_hasher.clone().finalize().into(),
            ),
        )?;
        self.hasher = next_hasher;
        self.frame_count = next_count;
        usize::try_from(repeats).map_err(|_| JournalError::JournalFull)
    }

    /// Atomically replaces the journal with a compact canonical frame set.
    ///
    /// The replacement is written to a new owner-only sibling, synchronized,
    /// renamed over the validated journal, and followed by a parent-directory
    /// sync. The current handle is replaced only after the rename succeeds.
    ///
    /// # Errors
    ///
    /// Rejects any invalid payload or replacement above the fixed journal
    /// ceiling. Filesystem and entropy failures leave the original journal or
    /// the complete replacement at the canonical path; callers must stop and
    /// reopen after an error.
    pub fn compact(&mut self, payloads: &[Vec<u8>]) -> Result<(), JournalError> {
        let replacement_size = payloads.iter().try_fold(
            u64::try_from(JOURNAL_MAGIC.len()).map_err(|_| JournalError::JournalFull)?,
            |total, payload| {
                if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
                    return Err(JournalError::InvalidPayload);
                }
                let frame_size = u64::try_from(LENGTH_BYTES + payload.len() + CHECKSUM_BYTES)
                    .map_err(|_| JournalError::JournalFull)?;
                total.checked_add(frame_size).ok_or(JournalError::JournalFull)
            },
        )?;
        if replacement_size > MAX_JOURNAL_BYTES {
            return Err(JournalError::JournalFull);
        }

        let temporary = temporary_sibling(&self.path)?;
        let result = (|| {
            let no_follow =
                i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).map_err(|_| JournalError::InvalidHeader)?;
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(no_follow);
            let mut replacement = options.open(&temporary)?;
            supgang_acl::clear_inherited_acl(&replacement)?;
            validate_metadata(&replacement)?;
            let mut hasher = Sha256::new();
            replacement.write_all(JOURNAL_MAGIC)?;
            hasher.update(JOURNAL_MAGIC);
            for payload in payloads {
                write_frame(&mut replacement, payload)?;
                update_frame_hash(&mut hasher, payload)?;
            }
            replacement.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            sync_parent(&self.path)?;
            let frame_count = u64::try_from(payloads.len()).map_err(|_| JournalError::JournalFull)?;
            witness::write(
                &self.witness_path,
                &JournalWitness::new(replacement_size, frame_count, hasher.clone().finalize().into()),
            )?;
            replacement.seek(SeekFrom::End(0))?;
            Ok((replacement, hasher, frame_count))
        })();
        match result {
            Ok((replacement, hasher, frame_count)) => {
                self.file = replacement;
                self.hasher = hasher;
                self.frame_count = frame_count;
                Ok(())
            }
            Err(error) => {
                let _cleanup = fs::remove_file(&temporary);
                Err(error)
            }
        }
    }

    /// Returns the current validated journal length.
    ///
    /// # Errors
    ///
    /// Returns a filesystem failure if metadata cannot be read.
    pub fn byte_len(&self) -> Result<u64, JournalError> {
        self.file.metadata().map(|metadata| metadata.len()).map_err(Into::into)
    }

    /// Returns the journal path for diagnostics without exposing its content.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

struct ReadFrames {
    frames: Vec<Vec<u8>>,
    valid_length: u64,
    actual_length: u64,
    bytes: Vec<u8>,
}

fn read_frames(file: &mut File) -> Result<ReadFrames, JournalError> {
    let declared_length = file.metadata()?.len();
    if declared_length > MAX_JOURNAL_BYTES {
        return Err(JournalError::JournalFull);
    }
    let capacity = usize::try_from(declared_length).map_err(|_| JournalError::JournalFull)?;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_JOURNAL_BYTES.saturating_add(1)).read_to_end(&mut bytes)?;
    let actual_length = u64::try_from(bytes.len()).map_err(|_| JournalError::JournalFull)?;
    if actual_length > MAX_JOURNAL_BYTES {
        return Err(JournalError::JournalFull);
    }
    if bytes.len() < JOURNAL_MAGIC.len() || bytes.get(..JOURNAL_MAGIC.len()) != Some(JOURNAL_MAGIC) {
        return Err(JournalError::InvalidHeader);
    }
    let (frames, valid_length) = parse_frames(&bytes)?;
    Ok(ReadFrames {
        frames,
        valid_length,
        actual_length,
        bytes,
    })
}

fn write_frame(file: &mut File, payload: &[u8]) -> Result<(), JournalError> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(JournalError::InvalidPayload);
    }
    let payload_length = u32::try_from(payload.len()).map_err(|_| JournalError::InvalidPayload)?;
    let length_bytes = payload_length.to_be_bytes();
    file.write_all(&length_bytes)?;
    file.write_all(payload)?;
    file.write_all(&checksum(length_bytes, payload))?;
    Ok(())
}

fn update_frame_hash(hasher: &mut Sha256, payload: &[u8]) -> Result<(), JournalError> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(JournalError::InvalidPayload);
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| JournalError::InvalidPayload)?
        .to_be_bytes();
    hasher.update(length);
    hasher.update(payload);
    hasher.update(checksum(length, payload));
    Ok(())
}

fn journal_witness(bytes: &[u8], frame_count: usize) -> Result<JournalWitness, JournalError> {
    Ok(JournalWitness::new(
        u64::try_from(bytes.len()).map_err(|_| JournalError::JournalFull)?,
        u64::try_from(frame_count).map_err(|_| JournalError::JournalFull)?,
        Sha256::digest(bytes).into(),
    ))
}

fn temporary_sibling(path: &Path) -> Result<PathBuf, JournalError> {
    let parent = path.parent().ok_or(JournalError::InvalidHeader)?;
    for _attempt in 0..8 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let candidate = parent.join(format!(".supgang-journal-{}.tmp", hex::encode(random)));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "could not allocate journal replacement").into())
}

fn sync_parent(path: &Path) -> Result<(), JournalError> {
    let parent = path.parent().ok_or(JournalError::InvalidHeader)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn validate_metadata(file: &File) -> Result<(), JournalError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(JournalError::NotRegularFile);
    }
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(JournalError::WrongOwner);
    }
    if metadata.mode() & 0o777 != 0o600 {
        return Err(JournalError::InsecurePermissions);
    }
    supgang_acl::reject_non_owner_grants(file).map_err(|error| {
        if error.kind() == io::ErrorKind::PermissionDenied {
            JournalError::InsecureAcl
        } else {
            JournalError::Io(error)
        }
    })?;
    Ok(())
}

fn parse_frames(bytes: &[u8]) -> Result<(Vec<Vec<u8>>, u64), JournalError> {
    let mut frames = Vec::new();
    let mut cursor = JOURNAL_MAGIC.len();

    while cursor < bytes.len() {
        let frame_offset = u64::try_from(cursor).unwrap_or(u64::MAX);
        let Some(length_slice) = bytes.get(cursor..cursor.saturating_add(LENGTH_BYTES)) else {
            break;
        };
        let length_bytes: [u8; LENGTH_BYTES] = length_slice.try_into().map_err(|_| JournalError::InvalidHeader)?;
        let payload_length = usize::try_from(u32::from_be_bytes(length_bytes)).unwrap_or(usize::MAX);
        if payload_length == 0 || payload_length > MAX_FRAME_BYTES {
            return Err(JournalError::OversizedFrame { offset: frame_offset });
        }
        let payload_start = cursor.saturating_add(LENGTH_BYTES);
        let checksum_start = payload_start.saturating_add(payload_length);
        let frame_end = checksum_start.saturating_add(CHECKSUM_BYTES);
        let Some(payload) = bytes.get(payload_start..checksum_start) else {
            break;
        };
        let Some(stored_checksum) = bytes.get(checksum_start..frame_end) else {
            break;
        };
        if checksum(length_bytes, payload).as_slice() != stored_checksum {
            return Err(JournalError::Checksum { offset: frame_offset });
        }
        frames.push(payload.to_vec());
        cursor = frame_end;
    }

    Ok((frames, u64::try_from(cursor).unwrap_or(u64::MAX)))
}

fn checksum(length: [u8; LENGTH_BYTES], payload: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(length);
    hasher.update(payload);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };

    use super::{Journal, JournalError};

    #[test]
    fn append_reopen_and_recover_partial_tail() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("state.journal");
        let (mut journal, empty) = Journal::open(&path)?;
        assert!(empty.is_empty());
        journal.append(b"first")?;
        journal.append(b"second")?;
        drop(journal);

        let mut raw = OpenOptions::new().append(true).open(&path)?;
        raw.write_all(&4_u32.to_be_bytes())?;
        raw.write_all(b"pa")?;
        raw.sync_all()?;
        drop(raw);

        let original_len = fs::metadata(&path)?.len();
        let (mut recovered, frames) = Journal::open(&path)?;
        assert_eq!(frames, [b"first".to_vec(), b"second".to_vec()]);
        assert!(fs::metadata(&path)?.len() < original_len);
        recovered.append(b"third")?;
        drop(recovered);
        let (_, frames) = Journal::open(&path)?;
        assert_eq!(frames, [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]);
        Ok(())
    }

    #[test]
    fn compaction_atomically_retains_only_requested_frames() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("state.journal");
        let (mut journal, empty) = Journal::open(&path)?;
        assert!(empty.is_empty());
        journal.append(b"old")?;
        journal.append(b"latest")?;
        let before = journal.byte_len()?;
        journal.compact(&[b"latest".to_vec()])?;
        assert!(journal.byte_len()? < before);
        drop(journal);

        let (_reopened, frames) = Journal::open(path)?;
        assert_eq!(frames, vec![b"latest".to_vec()]);
        Ok(())
    }

    #[test]
    fn complete_corruption_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("state.journal");
        let (mut journal, _) = Journal::open(&path)?;
        journal.append(b"important")?;
        drop(journal);

        let mut bytes = fs::read(&path)?;
        let payload_byte = bytes.get_mut(12).ok_or("test journal was unexpectedly short")?;
        *payload_byte ^= 1;
        fs::write(&path, bytes)?;
        assert!(matches!(Journal::open(&path), Err(JournalError::Checksum { .. })));
        Ok(())
    }

    #[test]
    fn committed_tail_truncation_is_detected_instead_of_repaired() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("state.journal");
        let (mut journal, _) = Journal::open(&path)?;
        journal.append(b"first")?;
        let first_length = journal.byte_len()?;
        journal.append(b"security revocation")?;
        drop(journal);

        OpenOptions::new().write(true).open(&path)?.set_len(first_length)?;
        assert!(matches!(Journal::open(&path), Err(JournalError::Rollback)));
        Ok(())
    }

    #[test]
    fn symlink_and_permissive_mode_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&target)?;
        file.write_all(b"SUPGJNL1")?;
        drop(file);
        std::os::unix::fs::symlink(&target, &link)?;
        assert!(Journal::open(&link).is_err());

        fs::set_permissions(&target, fs::Permissions::from_mode(0o644))?;
        assert!(matches!(Journal::open(&target), Err(JournalError::InsecurePermissions)));
        Ok(())
    }
}
