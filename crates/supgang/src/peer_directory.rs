//! Bounded durable cache of cryptographically verified peer contacts.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::Path,
};

use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use crate::{
    candidate::CandidateKind,
    contact::{ContactError, PeerContact, decode_contact, encode_contact},
    ids::NodeId,
    journal::{Journal, JournalError},
    merge::{self, MergeDecision},
    reachability::{ReachabilityClaim, ReachabilityError},
    revocation::{RevocationError, SignedRevocationList},
    settings::{DEFAULT_ADDRESS_HISTORY, MAX_ADDRESS_HISTORY, MIN_ADDRESS_HISTORY},
    state::MAX_HIVE_MEMBERS,
    storage::{StorageError, validate_directory},
};

/// Name of the protected peer-contact journal.
pub const PEER_DIRECTORY_FILE_NAME: &str = "peers.journal";
/// Journal size at which only live peer state is atomically retained.
pub const PEER_COMPACTION_THRESHOLD_BYTES: u64 = 8 * 1024 * 1024;

mod import_batch;
mod reachability;

/// Result of attempting to merge a verified peer contact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportDecision {
    /// This was the first contact for the node and was persisted.
    AcceptedFirst,
    /// This record advanced the node's sequence and was persisted.
    AcceptedNewer,
    /// The exact contact was already retained.
    Duplicate,
    /// The record was valid but older than the retained value.
    RejectedStale,
}

/// One node's retained endpoint state and optional equivocation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerEntry {
    current: PeerContact,
    history: Vec<PeerContact>,
    conflict: Option<PeerContact>,
}

/// One authenticated record plus only the addresses that remain useful to try.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerDialHint<'a> {
    contact: &'a PeerContact,
    addresses: Vec<SocketAddr>,
}

impl PeerDialHint<'_> {
    /// Returns the signed contact used to authenticate the attempted peer.
    #[must_use]
    pub const fn contact(&self) -> &PeerContact {
        self.contact
    }

    /// Returns the deduplicated addresses eligible for this signed contact.
    #[must_use]
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

impl PeerEntry {
    /// Returns the most recent contact seen before any conflict.
    #[must_use]
    pub const fn current(&self) -> &PeerContact {
        &self.current
    }

    /// Returns conflicting same-version evidence, if present.
    #[must_use]
    pub const fn conflict(&self) -> Option<&PeerContact> {
        self.conflict.as_ref()
    }

    /// Returns changed historical dial records, newest first.
    #[must_use]
    pub fn history(&self) -> &[PeerContact] {
        &self.history
    }

    /// Reports whether automatic dialing and propagation are stopped.
    #[must_use]
    pub const fn is_conflicted(&self) -> bool {
        self.conflict.is_some()
    }
}

/// Verified peer state with one append owner.
pub struct PeerDirectory {
    root_key: VerifyingKey,
    local_node: NodeId,
    entries: BTreeMap<NodeId, PeerEntry>,
    revocations: SignedRevocationList,
    reachability: BTreeMap<(NodeId, SocketAddr, NodeId), ReachabilityClaim>,
    history_address_limit: usize,
    journal: Option<Journal>,
}

impl core::fmt::Debug for PeerDirectory {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PeerDirectory")
            .field("root_key", &"<public>")
            .field("local_node", &self.local_node)
            .field("peer_count", &self.entries.len())
            .field("revocation_serial", &self.revocations.list.serial)
            .field("reachability_count", &self.reachability.len())
            .field("history_address_limit", &self.history_address_limit)
            .field(
                "conflict_count",
                &self.entries.values().filter(|entry| entry.is_conflicted()).count(),
            )
            .field("journal", &"<protected>")
            .finish()
    }
}

/// A durable peer-directory validation or merge failure.
#[derive(Debug, Error)]
pub enum PeerDirectoryError {
    /// Protected state-directory validation failed.
    #[error("protected state directory failed validation")]
    Storage(#[from] StorageError),
    /// Peer journal integrity or persistence failed.
    #[error("peer directory journal failed validation")]
    Journal(#[from] JournalError),
    /// A mutating operation was attempted through a read-only snapshot.
    #[error("read-only peer directory cannot be modified")]
    ReadOnlySnapshot,
    /// A contact failed canonical or cryptographic validation.
    #[error("peer contact failed validation")]
    Contact(#[from] ContactError),
    /// Root-signed revocation validation failed.
    #[error("peer revocation state failed validation")]
    Revocation(#[from] RevocationError),
    /// A revocation snapshot attempted to restore older authority.
    #[error("peer revocation state attempted to roll back authority")]
    RevocationRollback,
    /// A different snapshot reused an already accepted revocation serial.
    #[error("peer revocation state equivocation was detected")]
    RevocationEquivocation,
    /// A contact attempted to add the local node as its own peer.
    #[error("the local computer cannot be imported as a peer")]
    LocalNode,
    /// A short-lived reachability claim failed provenance or signature checks.
    #[error("peer reachability claim failed validation")]
    Reachability(#[from] ReachabilityError),
    /// The personal-hive peer budget was reached.
    #[error("peer directory reached its 255-peer limit")]
    DirectoryFull,
    /// Same-version, different signed content was retained as evidence.
    #[error("peer endpoint equivocation detected; automatic use is stopped")]
    Equivocation,
    /// Generation changes require a separately root-authorized transition.
    #[error("peer endpoint generation transition lacks root authorization")]
    GenerationTransitionRequired,
    /// The contact belongs to a root-revoked device.
    #[error("peer device identity is revoked")]
    Revoked,
    /// The requested historical-address budget is outside fixed safety bounds.
    #[error("peer address history must be from 8 through 64")]
    InvalidHistoryLimit,
}

impl PeerDirectory {
    /// Opens and cryptographically replays the protected peer cache.
    ///
    /// # Errors
    ///
    /// Rejects unsafe storage, corrupt frames, invalid historical signatures,
    /// generation changes, and inconsistent replay.
    pub fn open(
        state_directory: impl AsRef<Path>,
        root_key: VerifyingKey,
        local_node: NodeId,
        revocations: &SignedRevocationList,
    ) -> Result<Self, PeerDirectoryError> {
        Self::open_with_history_limit(
            state_directory,
            root_key,
            local_node,
            revocations,
            DEFAULT_ADDRESS_HISTORY,
        )
    }

    /// Opens the protected cache with an explicit bounded reconnection history.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits and every error documented by [`Self::open`].
    pub fn open_with_history_limit(
        state_directory: impl AsRef<Path>,
        root_key: VerifyingKey,
        local_node: NodeId,
        revocations: &SignedRevocationList,
        history_address_limit: usize,
    ) -> Result<Self, PeerDirectoryError> {
        validate_history_limit(history_address_limit)?;
        let directory = validate_directory(state_directory.as_ref())?;
        let (journal, frames) = Journal::open(directory.join(PEER_DIRECTORY_FILE_NAME))?;
        revocations.verify(&root_key)?;
        let mut result = Self {
            root_key,
            local_node,
            entries: BTreeMap::new(),
            revocations: revocations.clone(),
            reachability: BTreeMap::new(),
            history_address_limit,
            journal: Some(journal),
        };
        let replayed_frame_count = frames.len();
        for frame in frames {
            let contact = decode_contact(&frame)?;
            contact.verify_historical(&result.root_key)?;
            result.apply(contact, false)?;
        }
        if replayed_frame_count == result.canonical_frame_count() {
            result.compact_if_needed()?;
        } else {
            result.compact()?;
        }
        Ok(result)
    }

    /// Reads and verifies the peer cache without creating or repairing it.
    ///
    /// # Errors
    ///
    /// Rejects unsafe storage, corrupt frames, invalid historical signatures,
    /// generation changes, and inconsistent replay.
    pub fn open_read_only(
        state_directory: impl AsRef<Path>,
        root_key: VerifyingKey,
        local_node: NodeId,
        revocations: &SignedRevocationList,
    ) -> Result<Self, PeerDirectoryError> {
        Self::open_read_only_with_history_limit(
            state_directory,
            root_key,
            local_node,
            revocations,
            DEFAULT_ADDRESS_HISTORY,
        )
    }

    /// Reads the protected cache with an explicit bounded reconnection history.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits and every error documented by [`Self::open_read_only`].
    pub fn open_read_only_with_history_limit(
        state_directory: impl AsRef<Path>,
        root_key: VerifyingKey,
        local_node: NodeId,
        revocations: &SignedRevocationList,
        history_address_limit: usize,
    ) -> Result<Self, PeerDirectoryError> {
        validate_history_limit(history_address_limit)?;
        let directory = validate_directory(state_directory.as_ref())?;
        let frames = match Journal::read(directory.join(PEER_DIRECTORY_FILE_NAME)) {
            Ok(frames) => frames,
            Err(JournalError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        revocations.verify(&root_key)?;
        let mut result = Self {
            root_key,
            local_node,
            entries: BTreeMap::new(),
            revocations: revocations.clone(),
            reachability: BTreeMap::new(),
            history_address_limit,
            journal: None,
        };
        for frame in frames {
            let contact = decode_contact(&frame)?;
            contact.verify_historical(&result.root_key)?;
            result.apply(contact, false)?;
        }
        Ok(result)
    }

    /// Returns every retained peer entry in stable node-id order.
    #[must_use]
    pub const fn entries(&self) -> &BTreeMap<NodeId, PeerEntry> {
        &self.entries
    }

    /// Reports whether the current root-signed snapshot denies this device.
    #[must_use]
    pub fn is_revoked(&self, node_id: &NodeId) -> bool {
        self.revocations.contains(node_id)
    }

    /// Returns a peer only when it is fresh and has no equivocation evidence.
    #[must_use]
    pub fn usable(&self, node_id: &NodeId, now: u64) -> Option<&PeerContact> {
        let entry = self.entries.get(node_id)?;
        if entry.is_conflicted()
            || self.revocations.contains(node_id)
            || entry.current.verify(&self.root_key, now).is_err()
        {
            None
        } else {
            Some(&entry.current)
        }
    }

    /// Returns stable identity and transport-pin authority for recovery only.
    ///
    /// The returned contact may be expired. Callers may use it only to pin an
    /// ephemeral address attempt and must require a fresh contact in the new
    /// authenticated session before importing or exposing peer state.
    #[must_use]
    pub fn recovery_authority(&self, node_id: &NodeId) -> Option<&PeerContact> {
        let entry = self.entries.get(node_id)?;
        if entry.is_conflicted()
            || self.revocations.contains(node_id)
            || entry.current.verify_historical(&self.root_key).is_err()
        {
            None
        } else {
            Some(&entry.current)
        }
    }

    /// Returns fresh, non-conflicted contacts in stable order.
    #[must_use]
    pub fn usable_contacts(&self, now: u64) -> Vec<&PeerContact> {
        self.entries
            .values()
            .filter(|entry| {
                !entry.is_conflicted()
                    && !self.revocations.contains(&entry.current.endpoint.record.node_id)
                    && entry.current.verify(&self.root_key, now).is_ok()
            })
            .map(PeerEntry::current)
            .collect()
    }

    /// Returns historically authenticated, non-conflicted contacts as dial hints.
    ///
    /// Expired addresses may fail and are never returned by `resolve`, but trying
    /// one can recover a fresh record from a peer after an offline interval.
    #[must_use]
    pub fn dial_hints(&self, now: u64) -> Vec<PeerDialHint<'_>> {
        let mut contacts = Vec::new();
        for entry in self.entries.values() {
            if entry.is_conflicted() || self.revocations.contains(&entry.current.endpoint.record.node_id) {
                continue;
            }
            let mut seen = BTreeSet::<SocketAddr>::new();
            let mut current_addresses =
                self.reachability_addresses(entry.current.endpoint.record.node_id, now, &mut seen);
            current_addresses.extend(unique_addresses(entry.current(), &mut seen, usize::MAX));
            if !current_addresses.is_empty() {
                contacts.push(PeerDialHint {
                    contact: entry.current(),
                    addresses: current_addresses,
                });
            }
            let mut historical_addresses = 0_usize;
            for historical in entry.history() {
                let remaining = self.history_address_limit.saturating_sub(historical_addresses);
                if remaining == 0 {
                    break;
                }
                let addresses = unique_addresses(historical, &mut seen, remaining);
                if addresses.is_empty() {
                    continue;
                }
                historical_addresses = historical_addresses.saturating_add(addresses.len());
                contacts.push(PeerDialHint {
                    contact: historical,
                    addresses,
                });
            }
        }
        contacts
    }

    /// Verifies, merges, and durably appends a contact before returning it.
    ///
    /// # Errors
    ///
    /// Rejects stale authorization, the local node, a full directory,
    /// unapproved generation changes, equivocation, and persistence failure.
    pub fn import(&mut self, contact: PeerContact, now: u64) -> Result<ImportDecision, PeerDirectoryError> {
        contact.verify(&self.root_key, now)?;
        if self.revocations.contains(&contact.endpoint.record.node_id) {
            return Err(PeerDirectoryError::Revoked);
        }
        let result = self.apply(contact, true);
        let compacted = self.compact_if_needed();
        match (result, compacted) {
            (_, Err(error)) => Err(error),
            (result, Ok(())) => result,
        }
    }

    /// Replaces the verified revocation view used for dialing and resolution.
    ///
    /// # Errors
    ///
    /// Rejects a snapshot not signed by this directory's hive root, rollback,
    /// removal of an existing revocation, or same-serial equivocation.
    pub fn set_revocations(&mut self, revocations: &SignedRevocationList) -> Result<(), PeerDirectoryError> {
        revocations.verify(&self.root_key)?;
        match revocations.list.serial.cmp(&self.revocations.list.serial) {
            core::cmp::Ordering::Less => return Err(PeerDirectoryError::RevocationRollback),
            core::cmp::Ordering::Equal => {
                if revocations == &self.revocations {
                    return Ok(());
                }
                return Err(PeerDirectoryError::RevocationEquivocation);
            }
            core::cmp::Ordering::Greater => {}
        }
        if revocations.list.issued_at < self.revocations.list.issued_at
            || self
                .revocations
                .list
                .revoked_nodes
                .iter()
                .any(|node_id| !revocations.contains(node_id))
        {
            return Err(PeerDirectoryError::RevocationRollback);
        }
        self.revocations = revocations.clone();
        self.reachability.retain(|_, claim| {
            !self.revocations.contains(&claim.subject) && !self.revocations.contains(&claim.reporter)
        });
        Ok(())
    }

    /// Atomically replaces historical updates with current records and retained
    /// equivocation evidence.
    ///
    /// # Errors
    ///
    /// Returns canonical encoding or durable journal replacement failures.
    pub fn compact(&mut self) -> Result<(), PeerDirectoryError> {
        let frames = self.canonical_frames()?;
        self.journal_mut()?.compact(&frames)?;
        Ok(())
    }

    fn canonical_frames(&self) -> Result<Vec<Vec<u8>>, PeerDirectoryError> {
        let mut frames = Vec::with_capacity(self.canonical_frame_count());
        for entry in self.entries.values() {
            for historical in entry.history.iter().rev() {
                frames.push(encode_contact(historical)?);
            }
            frames.push(encode_contact(&entry.current)?);
            if let Some(conflict) = &entry.conflict {
                frames.push(encode_contact(conflict)?);
            }
        }
        Ok(frames)
    }

    fn canonical_frame_count(&self) -> usize {
        self.entries.values().fold(0_usize, |count, entry| {
            count
                .saturating_add(1)
                .saturating_add(entry.history.len())
                .saturating_add(usize::from(entry.conflict.is_some()))
        })
    }

    fn compact_if_needed(&mut self) -> Result<(), PeerDirectoryError> {
        if self
            .journal
            .as_ref()
            .ok_or(PeerDirectoryError::ReadOnlySnapshot)?
            .byte_len()?
            >= PEER_COMPACTION_THRESHOLD_BYTES
        {
            self.compact()?;
        }
        Ok(())
    }

    fn persist_contact(&mut self, contact: &PeerContact) -> Result<(), PeerDirectoryError> {
        let encoded = encode_contact(contact)?;
        if self
            .journal
            .as_ref()
            .ok_or(PeerDirectoryError::ReadOnlySnapshot)?
            .byte_len()?
            >= PEER_COMPACTION_THRESHOLD_BYTES
        {
            self.compact()?;
        }
        match self.journal_mut()?.append(&encoded) {
            Ok(()) => Ok(()),
            Err(JournalError::JournalFull) => {
                self.compact()?;
                self.journal_mut()?.append(&encoded)?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn apply(&mut self, contact: PeerContact, persist: bool) -> Result<ImportDecision, PeerDirectoryError> {
        let node_id = contact.endpoint.record.node_id;
        if node_id == self.local_node {
            return Err(PeerDirectoryError::LocalNode);
        }
        let current = self.entries.get(&node_id).map(PeerEntry::current);
        match merge::decide(current.map(|value| &value.endpoint), &contact.endpoint) {
            MergeDecision::AcceptFirst => {
                if self.entries.len() >= MAX_HIVE_MEMBERS.saturating_sub(1) {
                    return Err(PeerDirectoryError::DirectoryFull);
                }
                if persist {
                    self.persist_contact(&contact)?;
                }
                self.entries.insert(
                    node_id,
                    PeerEntry {
                        current: contact,
                        history: Vec::new(),
                        conflict: None,
                    },
                );
                Ok(ImportDecision::AcceptedFirst)
            }
            MergeDecision::AcceptNewer => {
                let conflicted = self
                    .entries
                    .get(&node_id)
                    .ok_or(PeerDirectoryError::DirectoryFull)?
                    .is_conflicted();
                if conflicted {
                    return Err(PeerDirectoryError::Equivocation);
                }
                if persist {
                    self.persist_contact(&contact)?;
                }
                let entry = self
                    .entries
                    .get_mut(&node_id)
                    .ok_or(PeerDirectoryError::DirectoryFull)?;
                let previous = core::mem::replace(&mut entry.current, contact);
                if dial_state_changed(&previous, &entry.current) {
                    entry.history.insert(0, previous);
                    trim_history(entry, self.history_address_limit);
                }
                Ok(ImportDecision::AcceptedNewer)
            }
            MergeDecision::Duplicate => Ok(ImportDecision::Duplicate),
            MergeDecision::RejectStale => Ok(ImportDecision::RejectedStale),
            MergeDecision::Equivocation => {
                let already_quarantined = self
                    .entries
                    .get(&node_id)
                    .ok_or(PeerDirectoryError::DirectoryFull)?
                    .is_conflicted();
                if already_quarantined {
                    return if persist {
                        Err(PeerDirectoryError::Equivocation)
                    } else {
                        Ok(ImportDecision::RejectedStale)
                    };
                }
                if persist {
                    self.persist_contact(&contact)?;
                }
                self.entries
                    .get_mut(&node_id)
                    .ok_or(PeerDirectoryError::DirectoryFull)?
                    .conflict = Some(contact);
                if persist {
                    Err(PeerDirectoryError::Equivocation)
                } else {
                    Ok(ImportDecision::RejectedStale)
                }
            }
            MergeDecision::GenerationTransitionRequired => Err(PeerDirectoryError::GenerationTransitionRequired),
        }
    }

    fn journal_mut(&mut self) -> Result<&mut Journal, PeerDirectoryError> {
        self.journal.as_mut().ok_or(PeerDirectoryError::ReadOnlySnapshot)
    }
}

fn validate_history_limit(limit: usize) -> Result<(), PeerDirectoryError> {
    if !(MIN_ADDRESS_HISTORY..=MAX_ADDRESS_HISTORY).contains(&limit) {
        return Err(PeerDirectoryError::InvalidHistoryLimit);
    }
    Ok(())
}

fn dial_state_changed(previous: &PeerContact, current: &PeerContact) -> bool {
    previous.endpoint.record.transport_key_id != current.endpoint.record.transport_key_id
        || previous.endpoint.record.candidates != current.endpoint.record.candidates
}

fn trim_history(entry: &mut PeerEntry, address_limit: usize) {
    let mut retained_addresses = BTreeSet::<SocketAddr>::new();
    entry.history.retain(|contact| {
        let remaining = address_limit.saturating_sub(retained_addresses.len());
        if remaining == 0 {
            return false;
        }
        !unique_addresses(contact, &mut retained_addresses, remaining).is_empty()
    });
}

fn unique_addresses(contact: &PeerContact, seen: &mut BTreeSet<SocketAddr>, limit: usize) -> Vec<SocketAddr> {
    contact
        .endpoint
        .record
        .candidates
        .iter()
        .filter(|candidate| !matches!(candidate.kind(), CandidateKind::Local | CandidateKind::Reflexive))
        .map(crate::candidate::EndpointCandidate::address)
        .filter(|address| seen.insert(*address))
        .take(limit)
        .collect()
}

#[cfg(test)]
mod tests;
