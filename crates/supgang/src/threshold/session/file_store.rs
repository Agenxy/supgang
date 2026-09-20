//! Protected atomic snapshots, bounded reads and exclusive directory ownership.

use minicbor::{Decoder, Encoder, data::Type};
use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
};

use super::{Binding, Phase, Record, SessionStore, Snapshot};
use crate::{
    state_lock::StateLock,
    storage,
    threshold::{Error, MAX_RECORDS, array, canonical, count, fixed, length, step::RootStep},
};

const MAX_STORE_BYTES: usize = 5 * 1024 * 1024;

/// Owner-only, exclusively locked file store for disposable prototype sessions.
///
/// Atomic replacement fsyncs both the file and parent directory. Nonce secrets
/// never enter this file. A failed write poisons the handle until reopen.
pub struct FileSessionStore {
    directory: PathBuf,
    binding: Binding,
    state: Snapshot,
    poisoned: bool,
    _lock: StateLock,
}

impl FileSessionStore {
    /// Creates or reopens a store, refusing concurrent ownership and wrong scope.
    ///
    /// # Errors
    /// Refuses symlinks, unsafe permissions, corrupted files, bounds and I/O.
    pub fn open(path: impl AsRef<Path>, binding: Binding) -> Result<Self, Error> {
        binding.group.encode()?;
        if binding.participant == 0 || usize::from(binding.participant) > binding.group.participants.len() {
            return Err(Error::Authority);
        }
        let directory = storage::prepare_directory(path.as_ref())?;
        let lock = StateLock::acquire(&directory)?;
        let path = directory.join("threshold.state");
        let state = match OpenOptions::new()
            .read(true)
            .custom_flags(storage::no_follow_flag()?)
            .open(path)
        {
            Ok(file) => {
                storage::validate_owner_file_metadata(&file)?;
                if file.metadata()?.len() > length(MAX_STORE_BYTES)? {
                    return Err(Error::Bound);
                }
                let mut bytes = Vec::new();
                file.take(length(MAX_STORE_BYTES + 1)?).read_to_end(&mut bytes)?;
                if bytes.len() > MAX_STORE_BYTES {
                    return Err(Error::Bound);
                }
                decode(&bytes, &binding)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Snapshot::default(),
            Err(error) => return Err(error.into()),
        };
        let mut store = Self {
            directory,
            binding,
            state,
            poisoned: false,
            _lock: lock,
        };
        // Persist the scope even if no session is ever proposed.
        store.persist(&store.state.clone())?;
        Ok(store)
    }

    fn persist(&mut self, next: &Snapshot) -> Result<(), Error> {
        let bytes = encode(next, &self.binding)?;
        self.poisoned = true;
        let temporary = self.directory.join("threshold.pending");
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
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
        fs::rename(temporary, self.directory.join("threshold.state"))?;
        storage::sync_directory(&self.directory)?;
        self.poisoned = false;
        Ok(())
    }
}

impl SessionStore for FileSessionStore {
    fn binding(&self) -> &Binding {
        &self.binding
    }
    fn snapshot(&self) -> &Snapshot {
        &self.state
    }

    fn replace(&mut self, expected: u64, next: Snapshot) -> Result<(), Error> {
        if self.poisoned
            || expected != self.state.revision
            || next.revision != expected.checked_add(1).ok_or(Error::Bound)?
            || next.last_time < self.state.last_time
            || next.records.len() < self.state.records.len()
            || next.records.len() > self.state.records.len() + 1
        {
            return Err(Error::Store);
        }
        for (old, new) in self.state.records.iter().zip(&next.records) {
            if old.id != new.id
                || old.step != new.step
                || old.step_digest != new.step_digest
                || (old.permanent && !new.permanent)
                || (old.package_digest.is_some() && old.package_digest != new.package_digest)
                || (old.cached_share.is_some() && old.cached_share != new.cached_share)
                || (old.commitment.is_some() && old.commitment != new.commitment)
                || (old.phase != Phase::Proposed && old.committed_at != new.committed_at)
                || !valid_transition(old.phase, new.phase)
            {
                return Err(Error::Store);
            }
        }
        self.persist(&next)?;
        self.state = next;
        Ok(())
    }
}

const fn valid_transition(old: Phase, new: Phase) -> bool {
    matches!(
        (old, new),
        (Phase::Proposed, Phase::Proposed | Phase::Committed | Phase::Discarded)
            | (
                Phase::Committed,
                Phase::Committed | Phase::NoncesIssued | Phase::Discarded
            )
            | (
                Phase::NoncesIssued,
                Phase::NoncesIssued | Phase::NoncesConsumed | Phase::Discarded
            )
            | (
                Phase::NoncesConsumed,
                Phase::NoncesConsumed | Phase::Signed | Phase::Discarded
            )
            | (Phase::Signed, Phase::Signed | Phase::Discarded)
            | (Phase::Discarded, Phase::Discarded)
    )
}

fn encode(state: &Snapshot, binding: &Binding) -> Result<Vec<u8>, Error> {
    if state.records.len() > MAX_RECORDS {
        return Err(Error::Bound);
    }
    let mut e = Encoder::new(Vec::new());
    e.array(7)?
        .u8(1)?
        .bytes(binding.hive.as_bytes())?
        .bytes(&binding.group.encode()?)?;
    e.u16(binding.participant)?
        .u64(state.revision)?
        .u64(state.last_time)?
        .array(length(state.records.len())?)?;
    let mut ids = std::collections::BTreeSet::new();
    for record in &state.records {
        validate_record(record, binding)?;
        if !ids.insert(record.id) {
            return Err(Error::Invalid);
        }
        e.array(10)?
            .bytes(&record.id)?
            .bytes(&record.step.encode()?)?
            .bytes(&record.step_digest)?;
        e.u8(match record.phase {
            Phase::Proposed => 0,
            Phase::Committed => 1,
            Phase::NoncesIssued => 2,
            Phase::NoncesConsumed => 3,
            Phase::Signed => 4,
            Phase::Discarded => 5,
        })?;
        e.u64(record.committed_at)?.bool(record.permanent)?;
        optional(&mut e, record.commitment.as_deref())?;
        optional(&mut e, record.package_digest.as_ref().map(<[u8; 32]>::as_slice))?;
        optional(&mut e, record.cached_share.as_deref())?;
        e.u8(0)?;
    }
    let bytes = e.into_writer();
    if bytes.len() > MAX_STORE_BYTES {
        return Err(Error::Bound);
    }
    Ok(bytes)
}

fn decode(bytes: &[u8], binding: &Binding) -> Result<Snapshot, Error> {
    let mut d = Decoder::new(bytes);
    array(&mut d, 7)?;
    if d.u8()? != 1
        || d.bytes()? != binding.hive.as_bytes()
        || d.bytes()? != binding.group.encode()?
        || d.u16()? != binding.participant
    {
        return Err(Error::Authority);
    }
    let revision = d.u64()?;
    let last_time = d.u64()?;
    let size = count(&mut d, MAX_RECORDS)?;
    let mut records = Vec::with_capacity(size);
    for _ in 0..size {
        array(&mut d, 10)?;
        let id = fixed(&mut d)?;
        let step = RootStep::decode(d.bytes()?)?;
        let step_digest = fixed(&mut d)?;
        let phase = match d.u8()? {
            0 => Phase::Proposed,
            1 => Phase::Committed,
            2 => Phase::NoncesIssued,
            3 => Phase::NoncesConsumed,
            4 => Phase::Signed,
            5 => Phase::Discarded,
            _ => return Err(Error::Invalid),
        };
        let committed_at = d.u64()?;
        let permanent = d.bool()?;
        let commitment = read_optional(&mut d, 256)?;
        let package_digest = read_optional(&mut d, 32)?
            .map(|v| v.try_into().map_err(|_| Error::Invalid))
            .transpose()?;
        let cached_share = read_optional(&mut d, 32)?;
        if d.u8()? != 0 {
            return Err(Error::Invalid);
        }
        records.push(Record {
            id,
            step,
            step_digest,
            phase,
            committed_at,
            permanent,
            commitment,
            package_digest,
            cached_share,
        });
    }
    let state = Snapshot {
        revision,
        last_time,
        records,
    };
    canonical(bytes, &encode(&state, binding)?)?;
    Ok(state)
}

fn validate_record(record: &Record, binding: &Binding) -> Result<(), Error> {
    if record.step.hive != binding.hive
        || record.step_digest != record.step.digest()?
        || record.permanent != record.package_digest.is_some()
        || (record.cached_share.is_some() && !record.permanent)
        || (matches!(
            record.phase,
            Phase::NoncesIssued | Phase::NoncesConsumed | Phase::Signed
        ) && record.commitment.is_none())
        || (matches!(record.phase, Phase::NoncesConsumed | Phase::Signed) && !record.permanent)
        || (record.phase == Phase::Signed && record.cached_share.is_none())
    {
        return Err(Error::Invalid);
    }
    if let Some(bytes) = &record.commitment {
        if bytes.len() > 256 {
            return Err(Error::Bound);
        }
        frost_ed25519::round1::SigningCommitments::deserialize(bytes)?;
    }
    if let Some(bytes) = &record.cached_share {
        if bytes.len() != 32 {
            return Err(Error::Invalid);
        }
        frost_ed25519::round2::SignatureShare::deserialize(bytes)?;
    }
    Ok(())
}

fn optional(e: &mut Encoder<Vec<u8>>, bytes: Option<&[u8]>) -> Result<(), Error> {
    if let Some(bytes) = bytes {
        e.bytes(bytes)?;
    } else {
        e.null()?;
    }
    Ok(())
}

fn read_optional(d: &mut Decoder<'_>, maximum: usize) -> Result<Option<Vec<u8>>, Error> {
    if d.datatype()? == Type::Null {
        d.null()?;
        return Ok(None);
    }
    let bytes = d.bytes()?;
    if bytes.len() > maximum {
        return Err(Error::Bound);
    }
    Ok(Some(bytes.to_vec()))
}
