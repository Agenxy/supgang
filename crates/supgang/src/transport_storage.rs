//! Protected persistence for the certificate-pinned QUIC transport identity.

use std::{
    fs::OpenOptions,
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    storage::{StorageError, no_follow_flag, sync_directory, validate_directory, validate_owner_file_metadata},
    transport::{MAX_TRANSPORT_CERTIFICATE_BYTES, MAX_TRANSPORT_PRIVATE_KEY_BYTES, TransportError, TransportIdentity},
};

/// Name of the owner-only transport identity file.
pub const TRANSPORT_IDENTITY_FILE_NAME: &str = "transport.key";

const MAGIC: &[u8; 8] = b"SUPGTLS1";
const DOMAIN: &[u8] = b"supgang/transport-identity-file/v1\0";
const LENGTH_BYTES: usize = 4;
const CHECKSUM_BYTES: usize = 32;
const HEADER_BYTES: usize = MAGIC.len() + 2 * LENGTH_BYTES;
const MAX_FILE_BYTES: usize =
    HEADER_BYTES + MAX_TRANSPORT_CERTIFICATE_BYTES + MAX_TRANSPORT_PRIVATE_KEY_BYTES + CHECKSUM_BYTES;

/// A protected transport-key storage failure.
#[derive(Debug, Error)]
pub enum TransportStorageError {
    /// State-directory ownership or permissions failed validation.
    #[error("protected state directory failed validation")]
    Storage(#[from] StorageError),
    /// The operating system rejected a file operation.
    #[error("transport identity filesystem operation failed")]
    Io(#[from] io::Error),
    /// Certificate or key generation or validation failed.
    #[error("transport identity cryptographic validation failed")]
    Transport(#[from] TransportError),
    /// The file marker, lengths, checksum, or contents were invalid.
    #[error("protected transport identity file is invalid or corrupt")]
    InvalidFile,
}

/// Loads the stable local transport identity or creates it exactly once.
///
/// # Errors
///
/// Rejects unsafe state directories, symlinks, foreign ownership, permissive
/// file modes, corruption, invalid keys, and persistence failures.
pub fn load_or_create(state_directory: impl AsRef<Path>) -> Result<TransportIdentity, TransportStorageError> {
    let directory = validate_directory(state_directory.as_ref())?;
    let path = directory.join(TRANSPORT_IDENTITY_FILE_NAME);
    match load_file(&path) {
        Ok(identity) => Ok(identity),
        Err(TransportStorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            let identity = TransportIdentity::generate()?;
            write_new(&path, &identity)?;
            sync_directory(&directory)?;
            Ok(identity)
        }
        Err(error) => Err(error),
    }
}

/// Loads an existing protected transport identity without creating one.
///
/// # Errors
///
/// Applies the same ownership, mode, symlink, bounds, and integrity checks as
/// [`load_or_create`].
pub fn load(state_directory: impl AsRef<Path>) -> Result<TransportIdentity, TransportStorageError> {
    let directory = validate_directory(state_directory.as_ref())?;
    load_file(&directory.join(TRANSPORT_IDENTITY_FILE_NAME))
}

fn load_file(path: &Path) -> Result<TransportIdentity, TransportStorageError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(no_follow_flag()?)
        .open(path)?;
    validate_owner_file_metadata(&file)?;
    let length = usize::try_from(file.metadata()?.len()).map_err(|_| TransportStorageError::InvalidFile)?;
    if !(HEADER_BYTES + CHECKSUM_BYTES..=MAX_FILE_BYTES).contains(&length) {
        return Err(TransportStorageError::InvalidFile);
    }
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)?;
    let decoded = decode(&bytes);
    bytes.zeroize();
    decoded
}

fn write_new(path: &Path, identity: &TransportIdentity) -> Result<(), TransportStorageError> {
    let mut bytes = encode(identity)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(no_follow_flag()?)
            .open(path)?;
        validate_owner_file_metadata(&file)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    bytes.zeroize();
    result
}

fn encode(identity: &TransportIdentity) -> Result<Vec<u8>, TransportStorageError> {
    let certificate_length =
        u32::try_from(identity.certificate_der().len()).map_err(|_| TransportStorageError::InvalidFile)?;
    let key_length = u32::try_from(identity.private_key_der().len()).map_err(|_| TransportStorageError::InvalidFile)?;
    let mut output = Vec::with_capacity(
        HEADER_BYTES
            .saturating_add(identity.certificate_der().len())
            .saturating_add(identity.private_key_der().len())
            .saturating_add(CHECKSUM_BYTES),
    );
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&certificate_length.to_be_bytes());
    output.extend_from_slice(&key_length.to_be_bytes());
    output.extend_from_slice(identity.certificate_der());
    output.extend_from_slice(identity.private_key_der());
    output.extend_from_slice(&checksum(&output));
    Ok(output)
}

fn decode(bytes: &[u8]) -> Result<TransportIdentity, TransportStorageError> {
    if bytes.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(TransportStorageError::InvalidFile);
    }
    let certificate_length = read_length(bytes, MAGIC.len())?;
    let key_length = read_length(bytes, MAGIC.len() + LENGTH_BYTES)?;
    if certificate_length == 0
        || certificate_length > MAX_TRANSPORT_CERTIFICATE_BYTES
        || key_length == 0
        || key_length > MAX_TRANSPORT_PRIVATE_KEY_BYTES
    {
        return Err(TransportStorageError::InvalidFile);
    }
    let data_end = HEADER_BYTES
        .checked_add(certificate_length)
        .and_then(|value| value.checked_add(key_length))
        .ok_or(TransportStorageError::InvalidFile)?;
    let expected_length = data_end
        .checked_add(CHECKSUM_BYTES)
        .ok_or(TransportStorageError::InvalidFile)?;
    if bytes.len() != expected_length
        || checksum(bytes.get(..data_end).ok_or(TransportStorageError::InvalidFile)?).as_slice()
            != bytes.get(data_end..).ok_or(TransportStorageError::InvalidFile)?
    {
        return Err(TransportStorageError::InvalidFile);
    }
    let certificate_end = HEADER_BYTES + certificate_length;
    let certificate = bytes
        .get(HEADER_BYTES..certificate_end)
        .ok_or(TransportStorageError::InvalidFile)?
        .to_vec();
    let key = bytes
        .get(certificate_end..data_end)
        .ok_or(TransportStorageError::InvalidFile)?
        .to_vec();
    TransportIdentity::from_der(certificate, key).map_err(Into::into)
}

fn read_length(bytes: &[u8], offset: usize) -> Result<usize, TransportStorageError> {
    let end = offset
        .checked_add(LENGTH_BYTES)
        .ok_or(TransportStorageError::InvalidFile)?;
    let encoded: [u8; LENGTH_BYTES] = bytes
        .get(offset..end)
        .ok_or(TransportStorageError::InvalidFile)?
        .try_into()
        .map_err(|_| TransportStorageError::InvalidFile)?;
    usize::try_from(u32::from_be_bytes(encoded)).map_err(|_| TransportStorageError::InvalidFile)
}

fn checksum(data: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::{TransportStorageError, load, load_or_create};
    use crate::state;

    #[test]
    fn identity_is_stable_owner_only_and_corruption_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("state");
        let _state = state::initialize(&directory)?;
        let first = load_or_create(&directory)?;
        let expected = first.key_id();
        drop(first);
        assert_eq!(load(&directory)?.key_id(), expected);

        let path = directory.join(super::TRANSPORT_IDENTITY_FILE_NAME);
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        let mut bytes = fs::read(&path)?;
        let last = bytes.last_mut().ok_or("empty transport identity")?;
        *last ^= 1;
        fs::write(&path, bytes)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert!(matches!(load(&directory), Err(TransportStorageError::InvalidFile)));
        Ok(())
    }

    #[test]
    fn symlink_is_never_followed() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("state");
        let _state = state::initialize(&directory)?;
        let target = temporary.path().join("target");
        fs::write(&target, b"not a key")?;
        std::os::unix::fs::symlink(&target, directory.join(super::TRANSPORT_IDENTITY_FILE_NAME))?;
        assert!(load_or_create(&directory).is_err());
        Ok(())
    }
}
