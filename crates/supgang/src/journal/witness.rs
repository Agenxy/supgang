//! Fixed-size durable journal-head witness.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::{JournalError, temporary_sibling};

const MAGIC: &[u8; 8] = b"SUPGHD01";
const DOMAIN: &[u8] = b"supgang/journal-head/v1\0";
const DIGEST_BYTES: usize = 32;
const CONTENT_BYTES: usize = MAGIC.len() + 8 + 8 + DIGEST_BYTES;
const FILE_BYTES: usize = CONTENT_BYTES + DIGEST_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct JournalWitness {
    pub(super) length: u64,
    pub(super) frame_count: u64,
    pub(super) journal_digest: [u8; DIGEST_BYTES],
}

impl JournalWitness {
    pub(super) const fn new(length: u64, frame_count: u64, journal_digest: [u8; DIGEST_BYTES]) -> Self {
        Self {
            length,
            frame_count,
            journal_digest,
        }
    }
}

pub(super) fn path_for(journal: &Path) -> Result<PathBuf, JournalError> {
    let name = journal
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(JournalError::InvalidHeader)?;
    Ok(journal.with_file_name(format!(".{name}.head")))
}

pub(super) fn read(path: &Path) -> Result<Option<JournalWitness>, JournalError> {
    let no_follow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).map_err(|_| JournalError::InvalidHeader)?;
    let mut file = match OpenOptions::new().read(true).custom_flags(no_follow).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    super::validate_metadata(&file)?;
    let mut bytes = Vec::with_capacity(FILE_BYTES.saturating_add(1));
    Read::by_ref(&mut file)
        .take(u64::try_from(FILE_BYTES.saturating_add(1)).map_err(|_| JournalError::Rollback)?)
        .read_to_end(&mut bytes)?;
    decode(&bytes).map(Some)
}

pub(super) fn write(path: &Path, value: &JournalWitness) -> Result<(), JournalError> {
    let bytes = encode(value);
    let temporary = temporary_sibling(path)?;
    let result = (|| {
        let no_follow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).map_err(|_| JournalError::InvalidHeader)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(no_follow)
            .open(&temporary)?;
        supgang_acl::clear_inherited_acl(&file)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(path.parent().ok_or(JournalError::InvalidHeader)?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _cleanup = fs::remove_file(&temporary);
    }
    result
}

fn encode(value: &JournalWitness) -> Vec<u8> {
    let mut output = Vec::with_capacity(FILE_BYTES);
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&value.length.to_be_bytes());
    output.extend_from_slice(&value.frame_count.to_be_bytes());
    output.extend_from_slice(&value.journal_digest);
    let checksum: [u8; DIGEST_BYTES] = Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(&output)
        .finalize()
        .into();
    output.extend_from_slice(&checksum);
    output
}

fn decode(bytes: &[u8]) -> Result<JournalWitness, JournalError> {
    if bytes.len() != FILE_BYTES || bytes.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(JournalError::Rollback);
    }
    let checksum: [u8; DIGEST_BYTES] = Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(bytes.get(..CONTENT_BYTES).ok_or(JournalError::Rollback)?)
        .finalize()
        .into();
    if bytes.get(CONTENT_BYTES..) != Some(checksum.as_slice()) {
        return Err(JournalError::Rollback);
    }
    let length = u64::from_be_bytes(
        bytes
            .get(MAGIC.len()..MAGIC.len() + 8)
            .ok_or(JournalError::Rollback)?
            .try_into()
            .map_err(|_| JournalError::Rollback)?,
    );
    let frame_count = u64::from_be_bytes(
        bytes
            .get(MAGIC.len() + 8..MAGIC.len() + 16)
            .ok_or(JournalError::Rollback)?
            .try_into()
            .map_err(|_| JournalError::Rollback)?,
    );
    let journal_digest = bytes
        .get(MAGIC.len() + 16..CONTENT_BYTES)
        .ok_or(JournalError::Rollback)?
        .try_into()
        .map_err(|_| JournalError::Rollback)?;
    Ok(JournalWitness {
        length,
        frame_count,
        journal_digest,
    })
}
