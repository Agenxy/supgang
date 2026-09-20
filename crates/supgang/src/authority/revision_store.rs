//! Small protected file store for library tests and future authority providers.
//!
//! One locked, atomically replaced state file holds the committed manifest,
//! reservation watermark, pending content hash and lifetime id history. Each
//! replacement is fsynced before rename and the directory is fsynced afterward.
//! A failed write poisons the open handle; reopening reads the durable outcome.
//! This does not defend against restoring the entire directory from a backup.

use minicbor::{Decoder, Encoder, data::Type};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
};

use super::{AuthorityContent, AuthorityError, AuthorityManifest, CertificateId, MAX_USED_IDS, codec};
use crate::{device_key::DevicePublicKey, ids::HiveId, state_lock::StateLock, storage};

const MAX_STORE_BYTES: usize = 96 * 1024;

/// Durable authority revision reservation and atomic publication contract.
///
/// Implementations must serialize writers; bind a store to one hive and device;
/// compare `current` to their committed head; reject historical id reuse; flush
/// the reservation before returning; and commit exactly its reserved content
/// once. A crash must burn the reservation, even when no manifest was committed.
pub trait RevisionStore {
    /// Reserves the next revision, replacing `proposed.revision` durably.
    ///
    /// # Errors
    /// Refuses a stale predecessor, used id, exhausted bound or failed flush.
    fn reserve(
        &mut self,
        current: Option<&AuthorityManifest>,
        proposed: &mut AuthorityContent,
    ) -> Result<(), AuthorityError>;
    /// Commits the reserved, signed content before it may be returned to a caller.
    ///
    /// # Errors
    /// Refuses another payload, a repeated commit, invalid signature or failed I/O.
    fn commit(&mut self, manifest: &AuthorityManifest) -> Result<(), AuthorityError>;
}

#[derive(Clone)]
struct State {
    epoch: u64,
    revision: u64,
    current: Option<AuthorityManifest>,
    used: Vec<CertificateId>,
    pending: Option<[u8; 32]>,
}

/// A file-backed revision store, holding an exclusive directory lock until drop.
///
/// Storage is bounded to 96 KiB and 4096 lifetime ids. At exhaustion issuance
/// fails closed; advancing an epoch does not forget lifetime id history.
pub struct FileRevisionStore {
    directory: PathBuf,
    hive: HiveId,
    key: DevicePublicKey,
    state: State,
    poisoned: bool,
    _lock: StateLock,
}

impl FileRevisionStore {
    /// Opens or creates a protected store bound to a hive and device.
    ///
    /// # Errors
    /// Refuses unsafe files, concurrent ownership, invalid state or a different
    /// hive/key binding. Existing malformed state is never reset automatically.
    pub fn open(path: impl AsRef<Path>, hive: HiveId, key: DevicePublicKey) -> Result<Self, AuthorityError> {
        let directory = storage::prepare_directory(path.as_ref())?;
        let lock = StateLock::acquire(&directory)?;
        let path = directory.join("authority.state");
        let state = match OpenOptions::new()
            .read(true)
            .custom_flags(storage::no_follow_flag()?)
            .open(path)
        {
            Ok(file) => {
                storage::validate_owner_file_metadata(&file)?;
                if file.metadata()?.len() > codec::length(MAX_STORE_BYTES)? {
                    return Err(AuthorityError::Bound);
                }
                let mut bytes = Vec::new();
                file.take(codec::length(MAX_STORE_BYTES.saturating_add(1))?)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > MAX_STORE_BYTES {
                    return Err(AuthorityError::Bound);
                }
                decode_state(&bytes, hive, key)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State {
                epoch: 0,
                revision: 0,
                current: None,
                used: Vec::new(),
                pending: None,
            },
            Err(e) => return Err(e.into()),
        };
        let mut store = Self {
            directory,
            hive,
            key,
            state,
            poisoned: false,
            _lock: lock,
        };
        // A reservation belongs to the process that made it. A recovered
        // reservation is consumed forever, even if its old signature survived.
        if store.state.pending.is_some() {
            let mut state = store.state.clone();
            state.pending = None;
            store.persist(state)?;
        }
        Ok(store)
    }

    /// Recovers the last committed manifest after reopening, excluding reservations.
    #[must_use]
    pub const fn current(&self) -> Option<&AuthorityManifest> {
        self.state.current.as_ref()
    }

    fn persist(&mut self, state: State) -> Result<(), AuthorityError> {
        let bytes = encode_state(&state, self.hive, self.key)?;
        self.poisoned = true;
        let temporary = self.directory.join("authority.pending");
        // A prior interrupted rename can leave this fixed temporary file. Only
        // remove it while the protected directory's exclusive lock is held.
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(storage::no_follow_flag()?)
            .open(&temporary)?;
        supgang_acl::clear_inherited_acl(&file)?;
        storage::validate_owner_file_metadata(&file)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temporary, self.directory.join("authority.state"))?;
        storage::sync_directory(&self.directory)?;
        self.state = state;
        self.poisoned = false;
        Ok(())
    }
}

impl RevisionStore for FileRevisionStore {
    fn reserve(
        &mut self,
        current: Option<&AuthorityManifest>,
        proposed: &mut AuthorityContent,
    ) -> Result<(), AuthorityError> {
        if self.poisoned || current.map(|m| &m.content) != self.state.current.as_ref().map(|m| &m.content) {
            return Err(AuthorityError::StoreConflict);
        }
        if let Some(manifest) = current {
            manifest.verify(self.hive, self.key)?;
        }
        proposed.validate()?;
        let old_epoch = current.map_or(0, |m| m.content.epoch);
        if proposed.epoch < self.state.epoch
            || proposed.epoch < old_epoch
            || proposed.epoch > old_epoch.checked_add(1).ok_or(AuthorityError::Bound)?
        {
            return Err(AuthorityError::Older);
        }
        if let Some(current) = current {
            if proposed.issued_at < current.content.issued_at {
                return Err(AuthorityError::Older);
            }
            if proposed.epoch == old_epoch {
                proposed.revocations.extends(&current.content.revocations)?;
            }
        }
        let mut state = self.state.clone();
        for certificate in &proposed.certificates {
            let claims = &certificate.claims;
            if claims.hive != self.hive || claims.issuer != super::device_node_id(self.key) {
                return Err(AuthorityError::Issuer);
            }
            let retained = current.is_some_and(|m| m.content.certificates.iter().any(|old| old == certificate));
            if !retained && state.used.binary_search(&claims.id).is_ok() {
                return Err(AuthorityError::ReusedId);
            }
            remember(&mut state.used, claims.id)?;
        }
        for id in &proposed.revocations.ids {
            remember(&mut state.used, *id)?;
        }
        proposed.revision = if proposed.epoch == state.epoch {
            state.revision.checked_add(1).ok_or(AuthorityError::Bound)?
        } else {
            1
        };
        state.epoch = proposed.epoch;
        state.revision = proposed.revision;
        state.pending = Some(Sha256::digest(codec::content_bytes(proposed)?).into());
        self.persist(state)
    }

    fn commit(&mut self, manifest: &AuthorityManifest) -> Result<(), AuthorityError> {
        if self.poisoned {
            return Err(AuthorityError::StoreConflict);
        }
        manifest.verify(self.hive, self.key)?;
        let digest: [u8; 32] = Sha256::digest(codec::content_bytes(&manifest.content)?).into();
        if self.state.pending != Some(digest) {
            return Err(AuthorityError::StoreConflict);
        }
        let mut state = self.state.clone();
        state.current = Some(manifest.clone());
        state.pending = None;
        self.persist(state)
    }
}

fn remember(used: &mut Vec<CertificateId>, id: CertificateId) -> Result<(), AuthorityError> {
    if let Err(position) = used.binary_search(&id) {
        if used.len() == MAX_USED_IDS {
            return Err(AuthorityError::Bound);
        }
        used.insert(position, id);
    }
    Ok(())
}

fn encode_state(state: &State, hive: HiveId, key: DevicePublicKey) -> Result<Vec<u8>, AuthorityError> {
    let mut e = Encoder::new(Vec::new());
    e.array(9)?
        .u8(1)?
        .bytes(hive.as_bytes())?
        .bytes(&key.to_bytes())?
        .u64(state.epoch)?
        .u64(state.revision)?;
    if let Some(manifest) = &state.current {
        e.bytes(&manifest.encode()?)?;
    } else {
        e.null()?;
    }
    e.array(codec::length(state.used.len())?)?;
    for id in &state.used {
        e.bytes(id)?;
    }
    if let Some(pending) = state.pending {
        e.bytes(&pending)?;
    } else {
        e.null()?;
    }
    // Reserved for store format flags, explicitly present and currently zero.
    e.u8(0)?;
    let bytes = e.into_writer();
    if bytes.len() > MAX_STORE_BYTES {
        return Err(AuthorityError::Bound);
    }
    Ok(bytes)
}

fn decode_state(bytes: &[u8], hive: HiveId, key: DevicePublicKey) -> Result<State, AuthorityError> {
    let mut d = Decoder::new(bytes);
    codec::array(&mut d, 9)?;
    codec::version(&mut d)?;
    if d.bytes()? != hive.as_bytes() || d.bytes()? != key.to_bytes() {
        return Err(AuthorityError::Issuer);
    }
    let epoch = d.u64()?;
    let revision = d.u64()?;
    let current = if d.datatype()? == Type::Null {
        d.null()?;
        None
    } else {
        Some(AuthorityManifest::decode(d.bytes()?)?)
    };
    let count = codec::count(&mut d, MAX_USED_IDS)?;
    let mut used = Vec::with_capacity(count);
    for _ in 0..count {
        used.push(codec::fixed(&mut d)?);
    }
    let pending = if d.datatype()? == Type::Null {
        d.null()?;
        None
    } else {
        Some(codec::fixed(&mut d)?)
    };
    if d.u8()? != 0 || !used.is_sorted_by(|a, b| a < b) {
        return Err(AuthorityError::Invalid);
    }
    codec::finish(&d, bytes)?;
    if let Some(manifest) = &current {
        manifest.verify(hive, key)?;
        if (manifest.content.epoch, manifest.content.revision) > (epoch, revision) {
            return Err(AuthorityError::StoreConflict);
        }
        for id in manifest
            .content
            .certificates
            .iter()
            .map(|c| &c.claims.id)
            .chain(&manifest.content.revocations.ids)
        {
            if used.binary_search(id).is_err() {
                return Err(AuthorityError::StoreConflict);
            }
        }
    }
    let result = State {
        epoch,
        revision,
        current,
        used,
        pending,
    };
    if encode_state(&result, hive, key)? != bytes {
        return Err(AuthorityError::NonCanonical);
    }
    Ok(result)
}
