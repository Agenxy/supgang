//! TUF-verified, owner-controlled software update staging.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tough::{ExpirationEnforcement, Limits, RepositoryLoader, TargetName};
use url::Url;

use crate::{artifact, storage};

mod authorization;
mod carriage;
pub(crate) mod delivery_queue;
mod download;
mod error;
mod executable;
mod filesystem_transport;
mod lifecycle;
mod lock;
mod root_state;
mod supervisor;
mod transaction;
mod tuf_state;

pub(crate) use authorization::{
    UpdateAuthorization, decode_authorization, encode_authorization, reserve_authorization,
};
pub(crate) use carriage::{incoming_bundle, outbound_bundle, prepare_outbound};
pub(crate) use delivery_queue::{
    QueuedPeerDelivery, finish_peer_delivery, load_peer_deliveries, prune_expired_peer_deliveries, queue_peer_delivery,
};
pub use error::UpdateError;
pub use lifecycle::{UpdateStatus, activate_staged, cancel_activation, initialize_installed, status};
pub(crate) use lifecycle::{
    activation_pending, initialize_installed_unlocked, preflight_local_install_unlocked,
    preflight_local_refresh_unlocked,
};
pub(crate) use lock::UpdateLock;
pub use supervisor::{SupervisorError, SupervisorOptions, run_supervisor};
pub use transaction::verify_and_stage;
pub(crate) use transaction::verify_and_stage_locked;

/// Maximum complete update bundle accepted from disk or a peer.
pub const MAX_UPDATE_BUNDLE_BYTES: u64 = 160 * 1024 * 1024;
/// Maximum signed executable target accepted after TUF verification.
pub const MAX_UPDATE_TARGET_BYTES: u64 = 128 * 1024 * 1024;
/// Exact bytes in a SHA-256 digest.
pub const UPDATE_DIGEST_BYTES: usize = 32;
const BUNDLE_MAGIC: &[u8; 8] = b"SUPGUPD1";
const BUNDLE_SCHEMA: &str = "supgang.update-bundle/v1";
const TRUSTED_ROOT_FILE: &str = "trusted-root.json";
const UPDATE_DIRECTORY: &str = "updates";
const SLOTS_DIRECTORY: &str = "slots";
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_METADATA_BYTES: u64 = 256 * 1024;
const MAX_BUNDLE_ENTRIES: usize = 64;
const MAX_ROOT_UPDATES: u64 = 32;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
/// A verified release staged in an immutable content-addressed slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StagedUpdate {
    /// Semantic-version release identity signed into the TUF target name.
    pub version: String,
    /// SHA-256 target digest authorized by TUF.
    pub digest: String,
    /// Owner-only executable path selected by the supervisor.
    pub executable: PathBuf,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct BundleManifest {
    schema: String,
    target: String,
    entries: Vec<BundleEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct BundleEntry {
    area: BundleArea,
    name: String,
    length: u64,
    sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
enum BundleArea {
    Metadata,
    Targets,
}

struct OpenEntry {
    manifest: BundleEntry,
    file: File,
}

/// Pins a self-signed TUF root through an explicit local-only action.
///
/// The first root is an unavoidable trust-on-first-use ceremony. It is never
/// accepted from a peer, and an existing root is never overwritten.
///
/// # Errors
///
/// Rejects unsafe storage, invalid or non-self-signed root metadata, an
/// existing pinned root, or a concurrent update operation.
pub fn trust_root(state_directory: &Path, root_file: &Path) -> Result<(), UpdateError> {
    let bytes = artifact::read(
        root_file,
        usize::try_from(MAX_METADATA_BYTES).map_err(|_| UpdateError::InvalidBundle)?,
    )?;
    let root: tough::schema::Signed<tough::schema::Root> =
        serde_json::from_slice(&bytes).map_err(|_| UpdateError::InvalidTrustRoot)?;
    root.signed
        .verify_role(&root)
        .map_err(|_| UpdateError::InvalidTrustRoot)?;
    let _lock = lock::UpdateLock::acquire(state_directory)?;
    let updates = updates_directory(state_directory, true)?;
    root_state::pin(&updates, &bytes, &root)
}

/// Packages one already-signed local TUF repository for offline or peer carriage.
///
/// This operation does not sign anything. The receiver always ignores this
/// manifest as authority and independently validates the enclosed repository.
///
/// # Errors
///
/// Rejects unsafe repository entries, invalid target naming, capacity bounds,
/// an existing output, or an operating-system write failure.
pub fn pack_repository(
    metadata_directory: &Path,
    targets_directory: &Path,
    target: &str,
    output: &Path,
) -> Result<String, UpdateError> {
    validate_target_name(target)?;
    let mut entries = open_repository_entries(metadata_directory, targets_directory)?;
    if entries.is_empty() || entries.len() > MAX_BUNDLE_ENTRIES {
        return Err(UpdateError::InvalidBundle);
    }
    entries.sort_by(|left, right| left.manifest.cmp(&right.manifest));
    let manifest = BundleManifest {
        schema: BUNDLE_SCHEMA.to_owned(),
        target: target.to_owned(),
        entries: entries.iter().map(|entry| entry.manifest.clone()).collect(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|_| UpdateError::InvalidBundle)?;
    if manifest_bytes.is_empty() || manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(UpdateError::InvalidBundle);
    }
    let mut destination = create_new_owner_file(output, 0o600)?;
    let mut cleanup = carriage::OutputGuard::new(output);
    destination.write_all(BUNDLE_MAGIC)?;
    destination.write_all(
        &u32::try_from(manifest_bytes.len())
            .map_err(|_| UpdateError::InvalidBundle)?
            .to_be_bytes(),
    )?;
    destination.write_all(&manifest_bytes)?;
    let mut bundle_hasher = Sha256::new();
    bundle_hasher.update(BUNDLE_MAGIC);
    bundle_hasher.update(
        u32::try_from(manifest_bytes.len())
            .map_err(|_| UpdateError::InvalidBundle)?
            .to_be_bytes(),
    );
    bundle_hasher.update(&manifest_bytes);
    let mut total =
        u64::try_from(BUNDLE_MAGIC.len() + 4 + manifest_bytes.len()).map_err(|_| UpdateError::InvalidBundle)?;
    for entry in &mut entries {
        entry.file.rewind()?;
        copy_exact_hashed(
            &mut entry.file,
            &mut destination,
            entry.manifest.length,
            &mut bundle_hasher,
        )?;
        total = total
            .checked_add(entry.manifest.length)
            .ok_or(UpdateError::InvalidBundle)?;
        if total > MAX_UPDATE_BUNDLE_BYTES {
            return Err(UpdateError::InvalidBundle);
        }
    }
    destination.sync_all()?;
    sync_parent(output)?;
    cleanup.commit();
    Ok(hex::encode(bundle_hasher.finalize()))
}

/// Returns the SHA-256 identity of one safe, bounded owner-only bundle.
///
/// # Errors
///
/// Rejects an unsafe, empty, oversized, or unreadable bundle.
pub fn bundle_digest(bundle: &Path) -> Result<[u8; UPDATE_DIGEST_BYTES], UpdateError> {
    let mut file = open_owner_file(bundle, 0o600, MAX_UPDATE_BUNDLE_BYTES)?;
    let length = file.metadata()?.len();
    hash_exact(&mut file, length)
}

fn trusted_root_valid(updates: &Path) -> Result<bool, UpdateError> {
    root_state::valid(updates)
}

pub(super) struct MaterializedBundle {
    state_directory: PathBuf,
    work_directory: PathBuf,
    metadata_directory: PathBuf,
    targets_directory: PathBuf,
    target: String,
}

pub(super) async fn verify_materialized(bundle: &MaterializedBundle) -> Result<StagedUpdate, UpdateError> {
    let updates = updates_directory(&bundle.state_directory, true)?;
    let trust = root_state::load(&updates)?;
    let root = trust.current_bytes()?;
    let datastore = ensure_child(&bundle.work_directory, "tuf-datastore")?;
    tuf_state::seed(&updates, &datastore)?;
    let metadata_url = directory_url(&bundle.metadata_directory)?;
    let targets_url = directory_url(&bundle.targets_directory)?;
    let transport = filesystem_transport::ProtectedFilesystemTransport::new(
        &metadata_url,
        &bundle.metadata_directory,
        MAX_METADATA_BYTES,
        &targets_url,
        &bundle.targets_directory,
        MAX_UPDATE_TARGET_BYTES,
    )?;
    let repository = RepositoryLoader::new(&root, metadata_url, targets_url)
        .transport(transport)
        .limits(Limits {
            max_root_size: MAX_METADATA_BYTES,
            max_targets_size: MAX_METADATA_BYTES,
            max_timestamp_size: MAX_METADATA_BYTES,
            max_snapshot_size: MAX_METADATA_BYTES,
            max_root_updates: MAX_ROOT_UPDATES,
        })
        .datastore(&datastore)
        .expiration_enforcement(ExpirationEnforcement::Safe)
        .load()
        .await
        .map_err(map_tough_load_error)?;
    let target_name = TargetName::new(bundle.target.clone()).map_err(|_| UpdateError::InvalidTargetName)?;
    let version = validate_target_name(target_name.raw())?;
    ensure_version_advances(&updates, &version)?;
    let target = repository
        .all_targets()
        .find(|(name, _)| *name == &target_name)
        .map(|(_, target)| target)
        .ok_or(UpdateError::Tuf)?;
    if target.length == 0 || target.length > MAX_UPDATE_TARGET_BYTES || target.hashes.sha256.as_ref().len() != 32 {
        return Err(UpdateError::Tuf);
    }
    let digest = hex::encode(target.hashes.sha256.as_ref());
    let active = lifecycle::read_active(&bundle.state_directory)?;
    let slots = ensure_child(&updates, SLOTS_DIRECTORY)?;
    let slot = ensure_child(&slots, &digest)?;
    let executable = slot.join("supgang");
    match fs::symlink_metadata(&executable) {
        Ok(_) => {
            executable::validate_staged(&executable, target.hashes.sha256.as_ref())?;
            executable::validate_compatible_identity(&active.executable, &executable)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let stream = repository
                .read_target(&target_name)
                .await
                .map_err(|_| UpdateError::Tuf)?
                .ok_or(UpdateError::Tuf)?;
            download::stage_stream(
                stream,
                &slot,
                &executable,
                target.length,
                target.hashes.sha256.as_ref(),
                &active.executable,
            )
            .await?;
        }
        Err(error) => return Err(error.into()),
    }
    let staged = StagedUpdate {
        version: version.to_string(),
        digest,
        executable,
    };
    root_state::promote(&updates, trust, repository.root())?;
    tuf_state::commit(&updates, &datastore)?;
    lifecycle::persist_staged(&updates, &staged)?;
    Ok(staged)
}

fn map_tough_load_error(error: tough::error::Error) -> UpdateError {
    match error {
        tough::error::Error::DatastoreInit { source, .. }
        | tough::error::Error::DatastoreCreate { source, .. }
        | tough::error::Error::DatastoreOpen { source, .. }
        | tough::error::Error::DatastoreRemove { source, .. } => UpdateError::Io(source),
        _ => UpdateError::Tuf,
    }
}

fn validate_target_name(target: &str) -> Result<Version, UpdateError> {
    let prefix = "supgang-";
    let suffix = format!("-{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let version = target
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(&suffix))
        .ok_or(UpdateError::WrongPlatform)?;
    if version.is_empty() || target.len() > 128 || !target.bytes().all(is_target_byte) {
        return Err(UpdateError::InvalidTargetName);
    }
    Version::parse(version).map_err(|_| UpdateError::InvalidTargetName)
}

const fn is_target_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
}

fn ensure_version_advances(updates: &Path, candidate: &Version) -> Result<(), UpdateError> {
    if candidate <= &lifecycle::effective_version_floor(updates)? {
        return Err(UpdateError::Rollback);
    }
    Ok(())
}

pub(super) fn materialize_bundle(state_directory: &Path, bundle: &Path) -> Result<MaterializedBundle, UpdateError> {
    let updates = updates_directory(state_directory, true)?;
    let work = create_random_child(&updates, ".verify-")?;
    let result = (|| {
        let metadata = ensure_child(&work, "metadata")?;
        let targets = ensure_child(&work, "targets")?;
        let mut source = open_owner_file(bundle, 0o600, MAX_UPDATE_BUNDLE_BYTES)?;
        let mut magic = [0_u8; 8];
        source.read_exact(&mut magic)?;
        if &magic != BUNDLE_MAGIC {
            return Err(UpdateError::InvalidBundle);
        }
        let manifest_length = read_u32(&mut source)?;
        let manifest_length = usize::try_from(manifest_length).map_err(|_| UpdateError::InvalidBundle)?;
        if !(1..=MAX_MANIFEST_BYTES).contains(&manifest_length) {
            return Err(UpdateError::InvalidBundle);
        }
        let mut bytes = vec![0_u8; manifest_length];
        source.read_exact(&mut bytes)?;
        let manifest: BundleManifest = serde_json::from_slice(&bytes).map_err(|_| UpdateError::InvalidBundle)?;
        if serde_json::to_vec(&manifest).map_err(|_| UpdateError::InvalidBundle)? != bytes
            || manifest.schema != BUNDLE_SCHEMA
            || manifest.entries.is_empty()
            || manifest.entries.len() > MAX_BUNDLE_ENTRIES
        {
            return Err(UpdateError::InvalidBundle);
        }
        validate_target_name(&manifest.target)?;
        let mut previous = None;
        for entry in &manifest.entries {
            validate_entry(entry)?;
            if previous.as_ref().is_some_and(|value| value >= entry) {
                return Err(UpdateError::InvalidBundle);
            }
            previous = Some(entry.clone());
            let parent = match entry.area {
                BundleArea::Metadata => &metadata,
                BundleArea::Targets => &targets,
            };
            extract_entry(&mut source, parent, entry)?;
        }
        let mut trailing = [0_u8; 1];
        if source.read(&mut trailing)? != 0 {
            return Err(UpdateError::InvalidBundle);
        }
        Ok(MaterializedBundle {
            state_directory: state_directory.to_path_buf(),
            work_directory: work.clone(),
            metadata_directory: metadata,
            targets_directory: targets,
            target: manifest.target,
        })
    })();
    if result.is_err() {
        let _cleanup = remove_work_directory(&work);
    }
    result
}

fn open_repository_entries(metadata: &Path, targets: &Path) -> Result<Vec<OpenEntry>, UpdateError> {
    let mut entries = Vec::new();
    collect_entries(metadata, BundleArea::Metadata, MAX_METADATA_BYTES, &mut entries)?;
    collect_entries(targets, BundleArea::Targets, MAX_UPDATE_TARGET_BYTES, &mut entries)?;
    if !entries
        .iter()
        .any(|entry| entry.manifest.area == BundleArea::Metadata && entry.manifest.name == "root.json")
        || !entries
            .iter()
            .any(|entry| entry.manifest.area == BundleArea::Metadata && entry.manifest.name == "targets.json")
    {
        return Err(UpdateError::InvalidBundle);
    }
    let total = entries.iter().try_fold(0_u64, |sum, entry| {
        sum.checked_add(entry.manifest.length).ok_or(UpdateError::InvalidBundle)
    })?;
    if total > MAX_UPDATE_BUNDLE_BYTES {
        return Err(UpdateError::InvalidBundle);
    }
    Ok(entries)
}

fn collect_entries(
    directory: &Path,
    area: BundleArea,
    maximum: u64,
    output: &mut Vec<OpenEntry>,
) -> Result<(), UpdateError> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(UpdateError::InvalidBundle);
    }
    for entry in fs::read_dir(directory)? {
        if output.len() >= MAX_BUNDLE_ENTRIES {
            return Err(UpdateError::InvalidBundle);
        }
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| UpdateError::InvalidBundle)?;
        if !valid_entry_name(&name) {
            return Err(UpdateError::InvalidBundle);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(no_follow()?)
            .open(entry.path())?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.len() == 0
            || metadata.len() > maximum
        {
            return Err(UpdateError::InvalidBundle);
        }
        supgang_acl::reject_non_owner_grants(&file)?;
        let digest = hash_exact(&mut file, metadata.len())?;
        output.push(OpenEntry {
            manifest: BundleEntry {
                area,
                name,
                length: metadata.len(),
                sha256: hex::encode(digest),
            },
            file,
        });
    }
    Ok(())
}

fn validate_entry(entry: &BundleEntry) -> Result<(), UpdateError> {
    let maximum = match entry.area {
        BundleArea::Metadata => MAX_METADATA_BYTES,
        BundleArea::Targets => MAX_UPDATE_TARGET_BYTES,
    };
    if !valid_entry_name(&entry.name)
        || entry.length == 0
        || entry.length > maximum
        || entry.sha256.len() != 64
        || hex::decode(&entry.sha256).map_or(true, |value| value.len() != 32)
    {
        return Err(UpdateError::InvalidBundle);
    }
    Ok(())
}

fn valid_entry_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && name.bytes().all(is_target_byte) && !matches!(name, "." | "..")
}

fn extract_entry(source: &mut File, directory: &Path, entry: &BundleEntry) -> Result<(), UpdateError> {
    let path = directory.join(&entry.name);
    let mut destination = create_new_owner_file(&path, 0o600)?;
    let expected = hex::decode(&entry.sha256).map_err(|_| UpdateError::InvalidBundle)?;
    let mut remaining = entry.length;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        let wanted =
            usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64)).map_err(|_| UpdateError::InvalidBundle)?;
        let count = source.read(buffer.get_mut(..wanted).ok_or(UpdateError::InvalidBundle)?)?;
        if count == 0 {
            return Err(UpdateError::InvalidBundle);
        }
        let bytes = buffer.get(..count).ok_or(UpdateError::InvalidBundle)?;
        destination.write_all(bytes)?;
        hasher.update(bytes);
        remaining = remaining
            .checked_sub(u64::try_from(count).map_err(|_| UpdateError::InvalidBundle)?)
            .ok_or(UpdateError::InvalidBundle)?;
    }
    if hasher.finalize().as_slice() != expected {
        return Err(UpdateError::InvalidBundle);
    }
    destination.sync_all()?;
    sync_parent(&path)?;
    Ok(())
}

fn updates_directory(state_directory: &Path, create: bool) -> Result<PathBuf, UpdateError> {
    let state = storage::validate_directory(state_directory)?;
    let path = state.join(UPDATE_DIRECTORY);
    if create {
        ensure_child(&state, UPDATE_DIRECTORY)
    } else {
        storage::validate_trusted_owner_directory(&path).map_err(Into::into)
    }
}

fn ensure_child(parent: &Path, name: &str) -> Result<PathBuf, UpdateError> {
    storage::validate_trusted_owner_directory(parent)?;
    if !valid_entry_name(name) {
        return Err(UpdateError::InvalidBundle);
    }
    let path = parent.join(name);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            storage::validate_trusted_owner_directory(&path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            supgang_acl::clear_inherited_acl(&File::open(&path)?)?;
            storage::validate_trusted_owner_directory(&path)?;
            File::open(parent)?.sync_all()?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(path)
}

fn create_random_child(parent: &Path, prefix: &str) -> Result<PathBuf, UpdateError> {
    for _ in 0..8 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| UpdateError::InvalidBundle)?;
        let path = parent.join(format!("{prefix}{}", hex::encode(random)));
        match fs::create_dir(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                supgang_acl::clear_inherited_acl(&File::open(&path)?)?;
                storage::validate_trusted_owner_directory(&path)?;
                File::open(parent)?.sync_all()?;
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(UpdateError::InvalidBundle)
}

pub(super) fn remove_work_directory(path: &Path) -> Result<(), UpdateError> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(UpdateError::InvalidBundle)?;
    if !name.starts_with(".verify-") {
        return Err(UpdateError::InvalidBundle);
    }
    let parent = path.parent().ok_or(UpdateError::InvalidBundle)?;
    storage::validate_trusted_owner_directory(parent)?;
    storage::validate_trusted_owner_directory(path)?;
    fs::remove_dir_all(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn open_owner_file(path: &Path, mode: u32, maximum: u64) -> Result<File, UpdateError> {
    let file = OpenOptions::new().read(true).custom_flags(no_follow()?).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o777 != mode
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(UpdateError::InvalidBundle);
    }
    supgang_acl::reject_non_owner_grants(&file).map_err(UpdateError::Io)?;
    Ok(file)
}

fn artifact_like_read(path: &Path, maximum: u64, mode: u32) -> Result<Vec<u8>, UpdateError> {
    let mut file = open_owner_file(path, mode, maximum)?;
    let length = usize::try_from(file.metadata()?.len()).map_err(|_| UpdateError::InvalidBundle)?;
    let mut bytes = Vec::with_capacity(length);
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() != length {
        return Err(UpdateError::InvalidBundle);
    }
    Ok(bytes)
}

fn create_new_owner_file(path: &Path, mode: u32) -> Result<File, UpdateError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(no_follow()?)
        .open(path)?;
    supgang_acl::clear_inherited_acl(&file)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o777 != mode
    {
        return Err(UpdateError::InvalidBundle);
    }
    Ok(file)
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), UpdateError> {
    let mut file = create_new_owner_file(path, mode)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<(), UpdateError> {
    File::open(path.parent().ok_or(UpdateError::InvalidBundle)?)?.sync_all()?;
    Ok(())
}

fn directory_url(path: &Path) -> Result<Url, UpdateError> {
    Url::from_directory_path(path).map_err(|()| UpdateError::InvalidBundle)
}

fn read_u32(file: &mut File) -> Result<u32, UpdateError> {
    let mut bytes = [0_u8; 4];
    file.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn hash_exact(file: &mut File, length: u64) -> Result<[u8; 32], UpdateError> {
    file.rewind()?;
    let mut hasher = Sha256::new();
    let mut remaining = length;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        let wanted =
            usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64)).map_err(|_| UpdateError::InvalidBundle)?;
        let count = file.read(buffer.get_mut(..wanted).ok_or(UpdateError::InvalidBundle)?)?;
        if count == 0 {
            return Err(UpdateError::InvalidBundle);
        }
        hasher.update(buffer.get(..count).ok_or(UpdateError::InvalidBundle)?);
        remaining = remaining
            .checked_sub(u64::try_from(count).map_err(|_| UpdateError::InvalidBundle)?)
            .ok_or(UpdateError::InvalidBundle)?;
    }
    Ok(hasher.finalize().into())
}

fn copy_exact_hashed(
    source: &mut File,
    destination: &mut File,
    length: u64,
    bundle_hasher: &mut Sha256,
) -> Result<(), UpdateError> {
    let mut remaining = length;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        let wanted =
            usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64)).map_err(|_| UpdateError::InvalidBundle)?;
        let count = source.read(buffer.get_mut(..wanted).ok_or(UpdateError::InvalidBundle)?)?;
        if count == 0 {
            return Err(UpdateError::InvalidBundle);
        }
        let bytes = buffer.get(..count).ok_or(UpdateError::InvalidBundle)?;
        destination.write_all(bytes)?;
        bundle_hasher.update(bytes);
        remaining = remaining
            .checked_sub(u64::try_from(count).map_err(|_| UpdateError::InvalidBundle)?)
            .ok_or(UpdateError::InvalidBundle)?;
    }
    Ok(())
}

fn no_follow() -> Result<i32, UpdateError> {
    i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits())
        .map_err(|_| UpdateError::InvalidBundle)
}

#[cfg(test)]
mod tests;
