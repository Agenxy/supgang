//! Verified replay and durable monotonic state transitions.

use std::{collections::BTreeMap, time::SystemTime};

use ed25519_dalek::VerifyingKey;
use minicbor::{decode, encode};
use thiserror::Error;

use crate::{
    candidate::EndpointCandidate,
    ids::{NodeId, TransportKeyId},
    invitation::{InvitationError, JoinBundle, JoinRequest},
    journal::{Journal, JournalError},
    membership::{
        MAX_MEMBERSHIP_LIFETIME_SECONDS, MEMBERSHIP_VERSION, MembershipCertificate, MembershipError, MembershipRoles,
        SignedMembership,
    },
    record::{Capabilities, ENDPOINT_RECORD_VERSION, EndpointRecord, RecordError, SignedEndpointRecord},
    revocation::{REVOCATION_VERSION, RevocationError, RevocationList, SignedRevocationList},
    state_lock::{StateLock, StateLockError},
    storage::{self, LocalIdentity, StorageError},
};

mod event;

use event::{StateEvent, encode_event, replay};

/// Maximum number of authorized devices in one personal hive.
pub const MAX_HIVE_MEMBERS: usize = 256;

/// Replayed authoritative state and its append handle.
pub struct LocalState {
    identity: LocalIdentity,
    memberships: BTreeMap<NodeId, SignedMembership>,
    revocations: SignedRevocationList,
    generation: u64,
    sequence: u64,
    last_membership_serial: u64,
    event_count: usize,
    journal: Journal,
    lock: StateLock,
}

impl core::fmt::Debug for LocalState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LocalState")
            .field("identity", &self.identity)
            .field("members", &self.memberships.len())
            .field("revocation_serial", &self.revocations.list.serial)
            .field("generation", &self.generation)
            .field("sequence", &self.sequence)
            .field("last_membership_serial", &self.last_membership_serial)
            .field("event_count", &self.event_count)
            .field("journal", &"<protected>")
            .field("lock", &self.lock)
            .finish()
    }
}

impl LocalState {
    /// Returns the protected local identity.
    #[must_use]
    pub const fn identity(&self) -> &LocalIdentity {
        &self.identity
    }

    /// Returns the current recovery generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the latest durably reserved endpoint sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the number of verified committed state events.
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.event_count
    }

    /// Returns the number of root-authorized members.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.memberships.len()
    }

    /// Returns the local device's membership certificate.
    #[must_use]
    pub fn local_membership(&self) -> Option<&SignedMembership> {
        self.memberships.get(&self.identity.device.node_id())
    }

    /// Returns an authorized membership by stable node identifier.
    #[must_use]
    pub fn membership(&self, node_id: &NodeId) -> Option<&SignedMembership> {
        self.memberships.get(node_id)
    }

    /// Returns the latest verified root-signed revocation snapshot.
    #[must_use]
    pub const fn revocations(&self) -> &SignedRevocationList {
        &self.revocations
    }

    /// Persists the next endpoint sequence before returning it to a publisher.
    ///
    /// # Errors
    ///
    /// Fails without advancing in-memory state if encoding or durable append
    /// fails. After any append I/O error, the caller must stop and reopen state.
    pub fn reserve_next_sequence(&mut self) -> Result<u64, StateError> {
        let next = self.sequence.checked_add(1).ok_or(StateError::CounterExhausted)?;
        let event = StateEvent::Sequence {
            generation: self.generation,
            sequence: next,
        };
        self.journal.append(&encode_event(&event)?)?;
        self.sequence = next;
        self.event_count = self.event_count.saturating_add(1);
        Ok(next)
    }

    /// Persists a new sequence and signs this device's canonical endpoint record.
    ///
    /// The signed value is returned only after its sequence is synchronized.
    ///
    /// # Errors
    ///
    /// Rejects malformed candidates, time bounds, ungranted capabilities,
    /// missing local membership, counter exhaustion, and persistence failures.
    pub fn sign_endpoint_record(
        &mut self,
        transport_key_id: TransportKeyId,
        candidates: Vec<EndpointCandidate>,
        capabilities: Capabilities,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<SignedEndpointRecord, StateError> {
        let membership = self.local_membership().ok_or(StateError::IdentityMismatch)?;
        if expires_at > membership.certificate.expires_at {
            return Err(RecordError::OutlivesMembership.into());
        }
        if capabilities.contains(Capabilities::INTRODUCER)
            && !membership.certificate.roles.contains(MembershipRoles::INTRODUCER)
        {
            return Err(StateError::UnauthorizedCapability);
        }
        if capabilities.contains(Capabilities::CONTROL_RELAY)
            && !membership.certificate.roles.contains(MembershipRoles::CONTROL_RELAY)
        {
            return Err(StateError::UnauthorizedCapability);
        }
        let next = self.sequence.checked_add(1).ok_or(StateError::CounterExhausted)?;
        let mut record = EndpointRecord {
            protocol_version: ENDPOINT_RECORD_VERSION,
            hive_id: self.identity.hive_id,
            node_id: self.identity.device.node_id(),
            transport_key_id,
            generation: self.generation,
            sequence: next,
            issued_at,
            expires_at,
            candidates,
            capabilities,
        };
        record.canonicalize_candidates();
        record.validate_shape()?;
        let persisted = self.reserve_next_sequence()?;
        if persisted != next {
            return Err(StateError::InvalidSequence);
        }
        SignedEndpointRecord::sign(record, &self.identity.device).map_err(Into::into)
    }

    /// Root-authorizes a new device key and durably records the issuance.
    ///
    /// # Errors
    ///
    /// Rejects invalid time bounds, a duplicate node, a full hive, counter
    /// exhaustion, or any signing, encoding, or persistence failure.
    pub fn issue_membership(
        &mut self,
        device_key: &VerifyingKey,
        roles: MembershipRoles,
        admission_nonce: [u8; 32],
        issued_at: u64,
        expires_at: u64,
    ) -> Result<SignedMembership, StateError> {
        if self.memberships.len() >= MAX_HIVE_MEMBERS {
            return Err(StateError::HiveFull);
        }
        let node_id = NodeId::from_verifying_key(&device_key.to_bytes());
        if self.revocations.contains(&node_id) {
            return Err(StateError::RevokedMember);
        }
        if self.memberships.contains_key(&node_id) {
            return Err(StateError::DuplicateMember);
        }
        let serial = self
            .last_membership_serial
            .checked_add(1)
            .ok_or(StateError::CounterExhausted)?;
        let certificate = MembershipCertificate {
            version: MEMBERSHIP_VERSION,
            hive_id: self.identity.hive_id,
            node_id,
            device_verifying_key: device_key.to_bytes(),
            serial,
            issued_at,
            expires_at,
            roles,
            admission_nonce,
        };
        let root = self.identity.root.as_ref().ok_or(StateError::AdmissionUnavailable)?;
        let signed = SignedMembership::sign(certificate, root)?;
        let event = StateEvent::Membership(signed.clone());
        self.journal.append(&encode_event(&event)?)?;
        self.memberships.insert(node_id, signed.clone());
        self.last_membership_serial = serial;
        self.event_count = self.event_count.saturating_add(1);
        Ok(signed)
    }

    /// Verifies and root-authorizes an offline join request idempotently.
    ///
    /// # Errors
    ///
    /// Rejects an invalid proof of possession, conflicting request for an
    /// existing node, unavailable root authority, or persistence failure.
    pub fn authorize_join_request(
        &mut self,
        request: &JoinRequest,
        roles: MembershipRoles,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<SignedMembership, StateError> {
        let key = request.verify()?;
        let node_id = NodeId::from_verifying_key(&key.to_bytes());
        if let Some(existing) = self.memberships.get(&node_id) {
            if existing.certificate.device_verifying_key == request.device_verifying_key
                && existing.certificate.admission_nonce == request.nonce
            {
                return Ok(existing.clone());
            }
            return Err(StateError::JoinMismatch);
        }
        self.issue_membership(&key, roles, request.nonce, issued_at, expires_at)
    }

    /// Root-revokes one authorized device and persists the new snapshot.
    ///
    /// Repeating an already committed revocation is idempotent. Revocation is
    /// permanent for the same stable device key.
    ///
    /// # Errors
    ///
    /// Rejects the local authority device, an unknown member, unavailable root
    /// authority, counter exhaustion, or persistence and signing failures.
    pub fn revoke(&mut self, node_id: NodeId, issued_at: u64) -> Result<SignedRevocationList, StateError> {
        if node_id == self.identity.device.node_id() {
            return Err(StateError::CannotRevokeSelf);
        }
        if !self.memberships.contains_key(&node_id) {
            return Err(StateError::UnknownMember);
        }
        if self.revocations.contains(&node_id) {
            return Ok(self.revocations.clone());
        }
        if issued_at < self.revocations.list.issued_at {
            return Err(StateError::RevocationRollback);
        }
        let root = self.identity.root.as_ref().ok_or(StateError::AdmissionUnavailable)?;
        let serial = self
            .revocations
            .list
            .serial
            .checked_add(1)
            .ok_or(StateError::CounterExhausted)?;
        let mut revoked_nodes = self.revocations.list.revoked_nodes.clone();
        revoked_nodes.push(node_id);
        revoked_nodes.sort_unstable();
        let signed = SignedRevocationList::sign(
            RevocationList {
                version: REVOCATION_VERSION,
                hive_id: self.identity.hive_id,
                serial,
                issued_at,
                revoked_nodes,
            },
            root,
        )?;
        self.persist_revocations(signed.clone())?;
        Ok(signed)
    }

    /// Verifies and persists a newer root-signed revocation snapshot learned
    /// from an authenticated peer.
    ///
    /// # Errors
    ///
    /// Rejects invalid signatures, same-serial equivocation, a serial rollback,
    /// removal of an existing revocation, time rollback, or persistence failure.
    pub fn merge_revocations(&mut self, incoming: SignedRevocationList) -> Result<bool, StateError> {
        incoming.verify(&self.identity.root_verifying_key)?;
        match incoming.list.serial.cmp(&self.revocations.list.serial) {
            core::cmp::Ordering::Less => return Ok(false),
            core::cmp::Ordering::Equal => {
                if incoming == self.revocations {
                    return Ok(false);
                }
                return Err(StateError::RevocationEquivocation);
            }
            core::cmp::Ordering::Greater => {}
        }
        if incoming.list.issued_at < self.revocations.list.issued_at
            || self
                .revocations
                .list
                .revoked_nodes
                .iter()
                .any(|node_id| !incoming.contains(node_id))
        {
            return Err(StateError::RevocationRollback);
        }
        self.persist_revocations(incoming)?;
        Ok(true)
    }

    fn persist_revocations(&mut self, signed: SignedRevocationList) -> Result<(), StateError> {
        self.journal
            .append(&encode_event(&StateEvent::Revocation(signed.clone()))?)?;
        self.revocations = signed;
        self.event_count = self.event_count.saturating_add(1);
        Ok(())
    }
}

/// Creates protected keys and commits the founder membership as event one.
///
/// # Errors
///
/// Returns any secure-storage, time, membership, encoding, or journal failure.
pub fn initialize(path: impl AsRef<std::path::Path>) -> Result<LocalState, StateError> {
    let path = path.as_ref();
    let (initialized, lock) = match storage::initialize(path) {
        Ok(initialized) => {
            let lock = StateLock::acquire(path)?;
            (initialized, lock)
        }
        Err(StorageError::AlreadyInitialized) => {
            let lock = StateLock::acquire(path)?;
            let identity = storage::load_identity(path)?;
            let (journal, frames) = storage::open_journal(path)?;
            if identity.root.is_none() || !frames.is_empty() {
                return Err(StorageError::AlreadyInitialized.into());
            }
            (storage::InitializedState { identity, journal }, lock)
        }
        Err(error) => return Err(error.into()),
    };
    let now = unix_time()?;
    let certificate = MembershipCertificate {
        version: MEMBERSHIP_VERSION,
        hive_id: initialized.identity.hive_id,
        node_id: initialized.identity.device.node_id(),
        device_verifying_key: initialized.identity.device.verifying_key().to_bytes(),
        serial: 1,
        issued_at: now,
        expires_at: now.saturating_add(MAX_MEMBERSHIP_LIFETIME_SECONDS),
        roles: MembershipRoles::DEVICE,
        admission_nonce: [0; 32],
    };
    let root = initialized
        .identity
        .root
        .as_ref()
        .ok_or(StateError::AdmissionUnavailable)?;
    let founder = SignedMembership::sign(certificate, root)?;
    let revocations = SignedRevocationList::empty(root, now)?;
    let mut journal = initialized.journal;
    journal.append(&encode_event(&StateEvent::Genesis {
        membership: founder.clone(),
        revocations: revocations.clone(),
    })?)?;
    let mut memberships = BTreeMap::new();
    memberships.insert(founder.certificate.node_id, founder);
    Ok(LocalState {
        identity: initialized.identity,
        memberships,
        revocations,
        generation: 0,
        sequence: 0,
        last_membership_serial: 1,
        event_count: 1,
        journal,
        lock,
    })
}

/// Opens, cryptographically validates, and deterministically replays local state.
///
/// # Errors
///
/// Fails closed for missing genesis, malformed or non-canonical events,
/// identity mismatch, unauthorized membership, counter gaps, or storage errors.
pub fn open(path: impl AsRef<std::path::Path>) -> Result<LocalState, StateError> {
    let path = path.as_ref();
    let lock = StateLock::acquire(path)?;
    let identity = storage::load_identity(path)?;
    let (journal, frames) = storage::open_journal(path)?;
    replay(identity, journal, lock, &frames)
}

/// Creates or deterministically re-exports this computer's pending join request.
///
/// # Errors
///
/// Rejects an already initialized hive and any unsafe pending-key state.
pub fn create_join_request(path: impl AsRef<std::path::Path>) -> Result<JoinRequest, StateError> {
    let pending = match storage::create_pending_identity(path.as_ref()) {
        Ok(pending) => pending,
        Err(StorageError::PendingAlreadyExists) => storage::load_pending_identity(path)?,
        Err(error) => return Err(error.into()),
    };
    Ok(JoinRequest::create(&pending))
}

/// Installs a root-authorized bundle only on the computer that created its request.
///
/// The genesis event is synchronized before the pending secret becomes the
/// active identity. Repeating the same completed join is idempotent.
///
/// # Errors
///
/// Rejects mismatched requests, expired memberships, conflicting local state,
/// malformed journals, and storage or persistence failures.
pub fn install_join_bundle(path: impl AsRef<std::path::Path>, bundle: &JoinBundle) -> Result<LocalState, StateError> {
    let path = path.as_ref();
    match storage::load_identity(path) {
        Ok(_) => {
            let existing = open(path)?;
            let local = existing.local_membership().ok_or(StateError::IdentityMismatch)?;
            if existing.identity.root_verifying_key.to_bytes() == bundle.root_verifying_key
                && local == &bundle.membership
                && (existing.revocations.list.serial > bundle.revocations.list.serial
                    || existing.revocations == bundle.revocations)
            {
                return Ok(existing);
            }
            return Err(StateError::JoinMismatch);
        }
        Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let lock = StateLock::acquire(path)?;
    let pending = storage::load_pending_identity(path)?;
    let root_key = bundle.verify_for_pending(&pending)?;
    bundle.membership.certificate.validate_time(unix_time()?)?;
    let expected_event = StateEvent::Genesis {
        membership: bundle.membership.clone(),
        revocations: bundle.revocations.clone(),
    };
    let expected_bytes = encode_event(&expected_event)?;
    let (mut journal, frames) = storage::open_journal(path)?;
    match frames.as_slice() {
        [] => journal.append(&expected_bytes)?,
        [only] if only == &expected_bytes => {}
        _ => return Err(StateError::InvalidGenesis),
    }
    drop(journal);
    storage::install_joined_identity(path, pending, root_key)?;
    drop(lock);
    open(path)
}

/// A local state initialization, replay, or transition failure.
#[derive(Debug, Error)]
pub enum StateError {
    /// Protected storage failed validation.
    #[error("protected local state failed validation")]
    Storage(#[from] StorageError),
    /// Another process owns mutable state or the lock failed validation.
    #[error("exclusive local state ownership failed")]
    Lock(#[from] StateLockError),
    /// A journal append failed.
    #[error("authoritative state could not be persisted")]
    Journal(#[from] JournalError),
    /// A membership was invalid.
    #[error("root-authorized membership failed validation")]
    Membership(#[from] MembershipError),
    /// A revocation snapshot was invalid.
    #[error("root-authorized revocation failed validation")]
    Revocation(#[from] RevocationError),
    /// An offline join request or bundle was invalid.
    #[error("offline join artifact failed validation")]
    Invitation(#[from] InvitationError),
    /// Endpoint record construction or signing failed.
    #[error("local endpoint record failed validation")]
    Record(#[from] RecordError),
    /// State-event encoding failed.
    #[error("state event could not be encoded")]
    Encode(#[from] encode::Error<std::convert::Infallible>),
    /// State-event decoding failed.
    #[error("state event is malformed")]
    Decode(#[from] decode::Error),
    /// The journal has no founder event.
    #[error("authoritative journal is missing its founder event")]
    MissingGenesis,
    /// Genesis was not the first and only genesis event.
    #[error("authoritative journal has an invalid founder event")]
    InvalidGenesis,
    /// Journal authority does not match the protected local identity.
    #[error("journal authority does not match the protected local identity")]
    IdentityMismatch,
    /// A state event used valid values but non-canonical bytes.
    #[error("state event is not canonically encoded")]
    NonCanonical,
    /// A state event had a wrong field count, tag, or trailing bytes.
    #[error("state event has an invalid shape")]
    InvalidEvent,
    /// A sequence event skipped, repeated, rolled back, or changed generation.
    #[error("authoritative endpoint sequence is not strictly consecutive")]
    InvalidSequence,
    /// Membership serial order skipped, repeated, or rolled back.
    #[error("membership serial is not strictly consecutive")]
    InvalidMembershipSerial,
    /// A root attempted to publish different revocation content at one serial.
    #[error("root revocation equivocation detected")]
    RevocationEquivocation,
    /// A newer revocation snapshot removed a denial or rolled back issue time.
    #[error("root revocation snapshot attempted a rollback")]
    RevocationRollback,
    /// The member already exists.
    #[error("device is already a hive member")]
    DuplicateMember,
    /// A previously revoked stable device key cannot be admitted again.
    #[error("device identity has been permanently revoked")]
    RevokedMember,
    /// Revocation target is not represented in this authority's membership state.
    #[error("revocation target is not an authorized member")]
    UnknownMember,
    /// The online root-holder cannot revoke itself through the ordinary command.
    #[error("the local root-authority device cannot revoke itself")]
    CannotRevokeSelf,
    /// The fixed personal-hive member budget was reached.
    #[error("hive reached its 256-member limit")]
    HiveFull,
    /// A monotonic counter cannot advance further.
    #[error("authoritative monotonic counter is exhausted")]
    CounterExhausted,
    /// This member does not hold the hive root secret.
    #[error("this computer does not hold hive admission authority")]
    AdmissionUnavailable,
    /// Join authorization conflicts with existing local or member state.
    #[error("join authorization conflicts with existing state")]
    JoinMismatch,
    /// The record advertises a capability not granted to this member.
    #[error("local membership does not grant the requested endpoint capability")]
    UnauthorizedCapability,
    /// The operating-system clock could not produce a UNIX timestamp.
    #[error("system clock is before the UNIX epoch")]
    InvalidSystemTime,
}

fn unix_time() -> Result<u64, StateError> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| StateError::InvalidSystemTime)
}

#[cfg(test)]
mod tests;
