//! Bounded durable cache of cryptographically verified peer contacts.

use std::{collections::BTreeMap, path::Path};

use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use crate::{
    contact::{ContactError, PeerContact, decode_contact, encode_contact},
    ids::NodeId,
    journal::{Journal, JournalError},
    merge::{self, MergeDecision},
    revocation::{RevocationError, SignedRevocationList},
    state::MAX_HIVE_MEMBERS,
    storage::{StorageError, validate_directory},
};

/// Name of the protected peer-contact journal.
pub const PEER_DIRECTORY_FILE_NAME: &str = "peers.journal";
/// Journal size at which only live peer state is atomically retained.
pub const PEER_COMPACTION_THRESHOLD_BYTES: u64 = 8 * 1024 * 1024;

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
    conflict: Option<PeerContact>,
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
    journal: Journal,
}

impl core::fmt::Debug for PeerDirectory {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PeerDirectory")
            .field("root_key", &"<public>")
            .field("local_node", &self.local_node)
            .field("peer_count", &self.entries.len())
            .field("revocation_serial", &self.revocations.list.serial)
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
    /// A contact failed canonical or cryptographic validation.
    #[error("peer contact failed validation")]
    Contact(#[from] ContactError),
    /// Root-signed revocation validation failed.
    #[error("peer revocation state failed validation")]
    Revocation(#[from] RevocationError),
    /// A contact attempted to add the local node as its own peer.
    #[error("the local computer cannot be imported as a peer")]
    LocalNode,
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
        let directory = validate_directory(state_directory.as_ref())?;
        let (journal, frames) = Journal::open(directory.join(PEER_DIRECTORY_FILE_NAME))?;
        revocations.verify(&root_key)?;
        let mut result = Self {
            root_key,
            local_node,
            entries: BTreeMap::new(),
            revocations: revocations.clone(),
            journal,
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
    pub fn dial_hints(&self) -> Vec<&PeerContact> {
        self.entries
            .values()
            .filter(|entry| {
                !entry.is_conflicted() && !self.revocations.contains(&entry.current.endpoint.record.node_id)
            })
            .map(PeerEntry::current)
            .collect()
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
        let decision = self.apply(contact, true)?;
        self.compact_if_needed()?;
        Ok(decision)
    }

    /// Replaces the verified revocation view used for dialing and resolution.
    ///
    /// # Errors
    ///
    /// Rejects a snapshot not signed by this directory's hive root.
    pub fn set_revocations(&mut self, revocations: &SignedRevocationList) -> Result<(), PeerDirectoryError> {
        revocations.verify(&self.root_key)?;
        self.revocations = revocations.clone();
        Ok(())
    }

    /// Atomically replaces historical updates with current records and retained
    /// equivocation evidence.
    ///
    /// # Errors
    ///
    /// Returns canonical encoding or durable journal replacement failures.
    pub fn compact(&mut self) -> Result<(), PeerDirectoryError> {
        let mut frames = Vec::with_capacity(self.entries.len().saturating_mul(2));
        for entry in self.entries.values() {
            frames.push(encode_contact(&entry.current)?);
            if let Some(conflict) = &entry.conflict {
                frames.push(encode_contact(conflict)?);
            }
        }
        self.journal.compact(&frames)?;
        Ok(())
    }

    fn compact_if_needed(&mut self) -> Result<(), PeerDirectoryError> {
        if self.journal.byte_len()? >= PEER_COMPACTION_THRESHOLD_BYTES {
            self.compact()?;
        }
        Ok(())
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
                    self.journal.append(&encode_contact(&contact)?)?;
                }
                self.entries.insert(
                    node_id,
                    PeerEntry {
                        current: contact,
                        conflict: None,
                    },
                );
                Ok(ImportDecision::AcceptedFirst)
            }
            MergeDecision::AcceptNewer => {
                let entry = self
                    .entries
                    .get_mut(&node_id)
                    .ok_or(PeerDirectoryError::DirectoryFull)?;
                if entry.is_conflicted() {
                    return Err(PeerDirectoryError::Equivocation);
                }
                if persist {
                    self.journal.append(&encode_contact(&contact)?)?;
                }
                entry.current = contact;
                Ok(ImportDecision::AcceptedNewer)
            }
            MergeDecision::Duplicate => Ok(ImportDecision::Duplicate),
            MergeDecision::RejectStale => Ok(ImportDecision::RejectedStale),
            MergeDecision::Equivocation => {
                let entry = self
                    .entries
                    .get_mut(&node_id)
                    .ok_or(PeerDirectoryError::DirectoryFull)?;
                if entry.conflict.as_ref() == Some(&contact) {
                    return Err(PeerDirectoryError::Equivocation);
                }
                if persist {
                    self.journal.append(&encode_contact(&contact)?)?;
                }
                if entry.conflict.is_none() {
                    entry.conflict = Some(contact);
                }
                if persist {
                    Err(PeerDirectoryError::Equivocation)
                } else {
                    Ok(ImportDecision::RejectedStale)
                }
            }
            MergeDecision::GenerationTransitionRequired => Err(PeerDirectoryError::GenerationTransitionRequired),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{ImportDecision, PeerDirectory, PeerDirectoryError};
    use crate::{
        candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
        contact::PeerContact,
        identity::DeviceIdentity,
        record::Capabilities,
        state,
    };

    fn contact(
        founder: &mut state::LocalState,
        device: &DeviceIdentity,
        sequence: u64,
        port: u16,
    ) -> Result<PeerContact, Box<dyn std::error::Error>> {
        let membership = founder.issue_membership(
            &device.verifying_key(),
            crate::membership::MembershipRoles::DEVICE,
            [u8::try_from(sequence)?; 32],
            10,
            1_000,
        )?;
        let endpoint = crate::record::SignedEndpointRecord::sign(
            crate::record::EndpointRecord {
                protocol_version: crate::record::ENDPOINT_RECORD_VERSION,
                hive_id: founder.identity().hive_id,
                node_id: device.node_id(),
                transport_key_id: crate::ids::TransportKeyId::from_public_material(b"transport"),
                generation: 0,
                sequence,
                issued_at: 20,
                expires_at: 100,
                candidates: vec![EndpointCandidate::new(
                    CandidateKind::Local,
                    CandidateTransport::QuicV1,
                    SocketAddr::from(([127, 0, 0, 1], port)),
                )?],
                capabilities: Capabilities::NONE,
            },
            device,
        )?;
        Ok(PeerContact { membership, endpoint })
    }

    #[test]
    fn imports_replays_and_stops_on_equivocation() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state_path = temporary.path().join("state");
        let mut founder = state::initialize(&state_path)?;
        let peer = DeviceIdentity::generate()?;
        let first = contact(&mut founder, &peer, 1, 4_433)?;
        let mut directory = PeerDirectory::open(
            &state_path,
            founder.identity().root_verifying_key,
            founder.identity().device.node_id(),
            founder.revocations(),
        )?;
        assert_eq!(directory.import(first.clone(), 50)?, ImportDecision::AcceptedFirst);
        assert_eq!(directory.import(first.clone(), 50)?, ImportDecision::Duplicate);

        let mut conflict = first.clone();
        conflict.endpoint = crate::record::SignedEndpointRecord::sign(
            crate::record::EndpointRecord {
                candidates: vec![EndpointCandidate::new(
                    CandidateKind::Local,
                    CandidateTransport::QuicV1,
                    SocketAddr::from(([127, 0, 0, 1], 4_434)),
                )?],
                ..first.endpoint.record
            },
            &peer,
        )?;
        assert!(matches!(
            directory.import(conflict, 50),
            Err(PeerDirectoryError::Equivocation)
        ));
        drop(directory);

        let reopened = PeerDirectory::open(
            &state_path,
            founder.identity().root_verifying_key,
            founder.identity().device.node_id(),
            founder.revocations(),
        )?;
        let entry = reopened.entries().get(&peer.node_id()).ok_or("peer missing")?;
        assert!(entry.is_conflicted());
        assert!(reopened.usable(&peer.node_id(), 50).is_none());
        drop(reopened);
        let mut compacted = PeerDirectory::open(
            &state_path,
            founder.identity().root_verifying_key,
            founder.identity().device.node_id(),
            founder.revocations(),
        )?;
        compacted.compact()?;
        drop(compacted);
        let reopened = PeerDirectory::open(
            &state_path,
            founder.identity().root_verifying_key,
            founder.identity().device.node_id(),
            founder.revocations(),
        )?;
        assert!(
            reopened
                .entries()
                .get(&peer.node_id())
                .ok_or("peer missing after compaction")?
                .is_conflicted()
        );
        Ok(())
    }

    #[test]
    fn revocation_immediately_removes_every_automatic_use() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state_path = temporary.path().join("state");
        let mut founder = state::initialize(&state_path)?;
        let peer = DeviceIdentity::generate()?;
        let signed_contact = contact(&mut founder, &peer, 1, 4_433)?;
        let mut directory = PeerDirectory::open(
            &state_path,
            founder.identity().root_verifying_key,
            founder.identity().device.node_id(),
            founder.revocations(),
        )?;
        assert_eq!(
            directory.import(signed_contact.clone(), 50)?,
            ImportDecision::AcceptedFirst
        );

        let revocation_time = founder.revocations().list.issued_at;
        let revocations = founder.revoke(peer.node_id(), revocation_time)?;
        directory.set_revocations(&revocations)?;
        assert!(directory.is_revoked(&peer.node_id()));
        assert!(directory.usable(&peer.node_id(), 50).is_none());
        assert!(directory.usable_contacts(50).is_empty());
        assert!(directory.dial_hints().is_empty());
        assert!(matches!(
            directory.import(signed_contact, 50),
            Err(PeerDirectoryError::Revoked)
        ));
        Ok(())
    }
}
