//! Protected persistence for the certificate-pinned QUIC transport identity.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    storage::{StorageError, sync_directory, validate_directory, validate_owner_file_metadata},
    transport::{MAX_TRANSPORT_CERTIFICATE_BYTES, MAX_TRANSPORT_PRIVATE_KEY_BYTES, TransportError, TransportIdentity},
};

/// Name of the owner-only transport identity file.
pub const TRANSPORT_IDENTITY_FILE_NAME: &str = "transport.key";

const MAGIC: &[u8; 8] = b"SUPGTLS2";
const LEGACY_MAGIC: &[u8; 8] = b"SUPGTLS1";
const DOMAIN: &[u8] = b"supgang/transport-identity-file/v2\0";
const LEGACY_DOMAIN: &[u8] = b"supgang/transport-identity-file/v1\0";
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

/// Loads or creates the product-named transport identity.
///
/// Version-one certificates are replaced once with a named certificate. The
/// certificate pin changes: peers must receive a new signed contact. Membership
/// keys, peer records, settings and names are not removed. Production callers
/// hold the state lock before invoking this function, including publication.
///
/// # Errors
///
/// Rejects unsafe state directories, symlinks, foreign ownership, permissive
/// file modes, corruption, invalid keys, and persistence failures.
pub fn load_or_create(state_directory: impl AsRef<Path>) -> Result<TransportIdentity, TransportStorageError> {
    let directory = validate_directory(state_directory.as_ref())?;
    let _lock = migration::lock(&directory)?;
    let path = directory.join(TRANSPORT_IDENTITY_FILE_NAME);
    match load_file(&path) {
        Ok((identity, false)) => Ok(identity),
        Ok((legacy, true)) => {
            drop(legacy);
            let identity = TransportIdentity::generate()?;
            migration::replace(&directory, &path, &identity)?;
            Ok(identity)
        }
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
    load_file(&directory.join(TRANSPORT_IDENTITY_FILE_NAME)).map(|(identity, _legacy)| identity)
}

mod migration;

fn no_follow_flag() -> Result<i32, TransportStorageError> {
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
    i32::try_from(flags.bits()).map_err(|_| TransportStorageError::InvalidFile)
}

fn load_file(path: &Path) -> Result<(TransportIdentity, bool), TransportStorageError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(no_follow_flag()?)
        .open(path)?;
    validate_owner_file_metadata(&file)?;
    let length = usize::try_from(file.metadata()?.len()).map_err(|_| TransportStorageError::InvalidFile)?;
    if !(HEADER_BYTES + CHECKSUM_BYTES..=MAX_FILE_BYTES).contains(&length) {
        return Err(TransportStorageError::InvalidFile);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(length.saturating_add(1)));
    file.take(u64::try_from(MAX_FILE_BYTES.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    decode(&bytes)
}

fn write_new(path: &Path, identity: &TransportIdentity) -> Result<(), TransportStorageError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(no_follow_flag()?)
        .open(path)?;
    write_file(file, identity)
}

fn write_file(mut file: File, identity: &TransportIdentity) -> Result<(), TransportStorageError> {
    let mut bytes = encode(identity)?;
    let result = (|| {
        supgang_acl::clear_inherited_acl(&file)?;
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

fn decode(bytes: &[u8]) -> Result<(TransportIdentity, bool), TransportStorageError> {
    let legacy = bytes.get(..MAGIC.len()) == Some(LEGACY_MAGIC);
    if !legacy && bytes.get(..MAGIC.len()) != Some(MAGIC) {
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
        || checksum_with_domain(
            bytes.get(..data_end).ok_or(TransportStorageError::InvalidFile)?,
            if legacy { LEGACY_DOMAIN } else { DOMAIN },
        )
        .as_slice()
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
    TransportIdentity::from_der(certificate, key)
        .map(|identity| (identity, legacy))
        .map_err(Into::into)
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
    checksum_with_domain(data, DOMAIN)
}

fn checksum_with_domain(data: &[u8], domain: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::{TransportStorageError, load, load_or_create};
    use crate::state;

    fn legacy_file(directory: &std::path::Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let certified = rcgen::generate_simple_self_signed(["supgang.invalid".to_owned()])?;
        let identity = crate::transport::TransportIdentity::from_der(
            certified.cert.der().to_vec(),
            certified.signing_key.serialize_der(),
        )?;
        let mut bytes = super::encode(&identity)?;
        bytes
            .get_mut(..super::MAGIC.len())
            .ok_or("missing file header")?
            .copy_from_slice(super::LEGACY_MAGIC);
        let end = bytes
            .len()
            .checked_sub(super::CHECKSUM_BYTES)
            .ok_or("missing checksum")?;
        let digest = super::checksum_with_domain(bytes.get(..end).ok_or("missing payload")?, super::LEGACY_DOMAIN);
        bytes.get_mut(end..).ok_or("missing checksum")?.copy_from_slice(&digest);
        crate::artifact::write_new(
            directory.join(super::TRANSPORT_IDENTITY_FILE_NAME),
            &bytes,
            super::MAX_FILE_BYTES,
        )?;
        Ok(bytes)
    }

    #[test]
    fn legacy_identity_is_replaced_once_without_replacing_membership() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("state");
        let local = state::initialize(&directory)?;
        let node = local.identity().device.node_id();
        let legacy_bytes = legacy_file(&directory)?;
        let old_pin = load(&directory)?.key_id();
        assert_eq!(
            fs::read(directory.join(super::TRANSPORT_IDENTITY_FILE_NAME))?,
            legacy_bytes
        );
        let current = load_or_create(&directory)?;
        assert_ne!(current.key_id(), old_pin);
        assert!(!current.certificate_der().windows(5).any(|value| value == b"rcgen"));
        assert_eq!(load_or_create(&directory)?.key_id(), current.key_id());
        let path = directory.join(super::TRANSPORT_IDENTITY_FILE_NAME);
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        assert!(fs::read(&path)?.starts_with(super::MAGIC));
        drop(local);
        assert_eq!(state::open(&directory)?.identity().device.node_id(), node);
        Ok(())
    }

    #[test]
    fn corruption_and_lock_contention_do_not_trigger_replacement() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("state");
        let _local = state::initialize(&directory)?;
        let mut bytes = legacy_file(&directory)?;
        let path = directory.join(super::TRANSPORT_IDENTITY_FILE_NAME);
        let lock = super::migration::lock(&directory)?;
        assert!(load_or_create(&directory).is_err());
        assert_eq!(fs::read(&path)?, bytes);
        drop(lock);
        *bytes.last_mut().ok_or("missing checksum")? ^= 1;
        fs::write(&path, &bytes)?;
        assert!(load_or_create(&directory).is_err());
        assert_eq!(fs::read(path)?, bytes);
        Ok(())
    }

    #[test]
    fn unsafe_legacy_permissions_do_not_authorize_migration() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("state");
        let _local = state::initialize(&directory)?;
        let bytes = legacy_file(&directory)?;
        let path = directory.join(super::TRANSPORT_IDENTITY_FILE_NAME);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(load_or_create(&directory).is_err());
        assert_eq!(fs::read(path)?, bytes);
        Ok(())
    }

    #[test]
    fn transport_pipe_is_rejected_without_waiting_for_a_writer() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("state");
        let _local = state::initialize(&directory)?;
        let path = directory.join(super::TRANSPORT_IDENTITY_FILE_NAME);
        assert!(std::process::Command::new("mkfifo").arg(&path).status()?.success());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert!(load_or_create(&directory).is_err());
        Ok(())
    }

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

    #[test]
    fn transport_key_file_rejects_trailing_growth() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("state");
        let _state = state::initialize(&directory)?;
        drop(load_or_create(&directory)?);
        let path = directory.join(super::TRANSPORT_IDENTITY_FILE_NAME);
        let mut bytes = fs::read(&path)?;
        bytes.extend_from_slice(&[0; 8]);
        fs::write(&path, bytes)?;
        assert!(matches!(load(&directory), Err(TransportStorageError::InvalidFile)));
        Ok(())
    }
}
