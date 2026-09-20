//! Presence-gated signing with durable predecessor locks and one-use nonces.

use std::collections::BTreeMap;

use frost_ed25519::{
    self as frost,
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use minicbor::Encoder;

use super::{Digest, Error, MAX_PARTICIPANTS, MAX_RECORDS, MAX_STEP_BYTES, hash, rng};
use super::{founding::GroupDescriptor, step::RootStep};
use crate::ids::HiveId;

mod file_store;
pub use file_store::FileSessionStore;
mod policy;
pub use policy::{ChainPolicy, Policy, Review, Role};

/// Deadline after which an unsigned commitment can be discarded.
pub const DEADLINE_SECONDS: u64 = 10 * 60;
/// Random identity for a single nonce lifecycle.
pub type SessionId = [u8; 32];

/// Durable protocol phase, independent of volatile nonce secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Step recorded before owner review.
    Proposed,
    /// Owner present; exact step and session locked.
    Committed,
    /// Public commitment durably recorded before release.
    NoncesIssued,
    /// Package identity recorded before computing any share.
    NoncesConsumed,
    /// Cached share durably recorded before release.
    Signed,
    /// Session abandoned; any permanent predecessor lock remains.
    Discarded,
}

/// One durable signing attempt. Contains no nonce secrets or signing key shares.
#[derive(Clone)]
pub struct Record {
    /// New random id for each attempt, including resumption.
    pub id: SessionId,
    /// Exact owner-reviewed operation.
    pub step: RootStep,
    /// Content digest committed to by the participant.
    pub step_digest: Digest,
    /// Chain revision and role validated before committing; immutable thereafter.
    pub review: Option<Review>,
    /// Current durable state-machine phase.
    pub phase: Phase,
    /// Local commitment time; deadlines never use the coordinator's clock.
    pub committed_at: u64,
    /// True before share computation, retained even after discard or restart.
    pub permanent: bool,
    /// Serialized public nonce commitment, never nonce secrets.
    pub commitment: Option<Vec<u8>>,
    /// Digest of the whole bound package, not just its message.
    pub package_digest: Option<Digest>,
    /// Cached signature share, released only after durable publication.
    pub cached_share: Option<Vec<u8>>,
}

/// Bounded atomic snapshot. Custom stores must honor the trait's CAS contract.
#[derive(Clone, Default)]
pub struct Snapshot {
    /// Compare-and-swap revision, incremented exactly once per durable write.
    pub revision: u64,
    /// Greatest caller-supplied local time, rejecting clock rollback.
    pub last_time: u64,
    /// At most 256 lifetime attempts; never prune permanent locks.
    pub records: Vec<Record>,
}

/// Store identity prevents loading another hive, group, generation or participant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Binding {
    /// Stable hive id.
    pub hive: HiveId,
    /// Complete current group descriptor.
    pub group: GroupDescriptor,
    /// Participant number within that group.
    pub participant: u16,
}

/// Durably serialized, exclusively owned signing state.
///
/// `replace` must compare the expected revision, atomically fsync the complete
/// next snapshot before success, and poison its handle on uncertain I/O. A
/// reopened store must return its durable outcome. No nonce secret is persisted.
/// Full-directory rollback is outside this prototype's storage guarantee.
pub trait SessionStore {
    /// Fixed hive/group/participant scope.
    fn binding(&self) -> &Binding;
    /// Current atomically published snapshot.
    fn snapshot(&self) -> &Snapshot;
    /// Compare-and-swap one complete snapshot.
    ///
    /// # Errors
    /// Refuses stale revisions, invalid snapshots, exhausted bounds or I/O failure.
    fn replace(&mut self, expected: u64, next: Snapshot) -> Result<(), Error>;
}

/// Coordinator package with explicit session, descriptor and generation binding.
#[derive(Clone)]
pub struct Package {
    /// Participants must all use this new session identity.
    pub id: SessionId,
    /// Current complete group descriptor identity.
    pub descriptor: Digest,
    /// Current share generation.
    pub generation: u64,
    /// Exact message and commitment set given to FROST.
    pub signing: frost::SigningPackage,
}

impl Package {
    /// Canonical wrapper identity covering FROST's exact pinned serialization.
    ///
    /// # Errors
    /// Refuses oversized message or commitment set before library serialization.
    pub fn digest(&self) -> Result<Digest, Error> {
        if self.signing.signing_commitments().len() > MAX_PARTICIPANTS
            || self.signing.message().len() > MAX_STEP_BYTES + super::step::DOMAIN.len()
        {
            return Err(Error::Bound);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(5)?
            .u8(1)?
            .bytes(&self.id)?
            .bytes(&self.descriptor)?
            .u64(self.generation)?;
        e.bytes(&self.signing.serialize()?)?;
        Ok(hash(&e.into_writer()))
    }
}

/// One participant's isolated signing machine and volatile nonce ownership.
pub struct Session<S: SessionStore> {
    store: S,
    key: frost::keys::KeyPackage,
    nonces: BTreeMap<SessionId, SigningNonces>,
    poisoned: bool,
}

impl<S: SessionStore> Session<S> {
    /// Opens a participant and burns incomplete attempts from a prior process.
    ///
    /// # Errors
    /// Refuses a share not in this exact generation/roster, bad state or I/O.
    pub fn open(mut store: S, key: frost::keys::KeyPackage) -> Result<Self, Error> {
        let binding = store.binding();
        let public = binding.group.public_package()?;
        if *key.identifier() != frost::Identifier::try_from(binding.participant)?
            || key.verifying_key() != public.verifying_key()
            || public.verifying_shares().get(key.identifier()) != Some(key.verifying_share())
            || *key.min_signers() != binding.group.k
        {
            return Err(Error::Authority);
        }
        let mut next = store.snapshot().clone();
        let mut changed = false;
        for record in &mut next.records {
            if !matches!(record.phase, Phase::Signed | Phase::Discarded) {
                record.phase = Phase::Discarded;
                changed = true;
            }
        }
        if changed {
            let expected = next.revision;
            next.revision = expected.checked_add(1).ok_or(Error::Bound)?;
            store.replace(expected, next)?;
        }
        Ok(Self {
            store,
            key,
            nonces: BTreeMap::new(),
            poisoned: false,
        })
    }

    /// Exposes only durable public state for inspection and crash fixtures.
    #[must_use]
    pub fn snapshot(&self) -> &Snapshot {
        self.store.snapshot()
    }

    /// Generates a new coordinator-selected session id using OS randomness.
    ///
    /// # Errors
    /// Refuses unavailable entropy.
    pub fn new_id() -> Result<SessionId, Error> {
        let mut id = [0; 32];
        getrandom::fill(&mut id).map_err(|_| Error::Random)?;
        Ok(id)
    }

    /// Durably records a proposal, requiring a fresh id even when resuming.
    ///
    /// # Errors
    /// Refuses wrong hive, historical session ids, bounds and clock rollback.
    pub fn propose(&mut self, id: SessionId, step: RootStep, now: u64) -> Result<(), Error> {
        if step.hive != self.store.binding().hive {
            return Err(Error::Authority);
        }
        let step_digest = step.digest()?;
        let mut next = self.next(now)?;
        if next.records.len() >= MAX_RECORDS {
            return Err(Error::Bound);
        }
        if next.records.iter().any(|record| record.id == id) {
            return Err(Error::Locked);
        }
        next.records.push(Record {
            id,
            step,
            step_digest,
            review: None,
            phase: Phase::Proposed,
            committed_at: 0,
            permanent: false,
            commitment: None,
            package_digest: None,
            cached_share: None,
        });
        self.persist(next)
    }

    /// Presence-gated durable commitment and nonce issuance, in that order.
    ///
    /// # Errors
    /// Refuses absence, conflicting predecessor locks, wrong state or I/O.
    pub fn commit(
        &mut self,
        id: SessionId,
        now: u64,
        policy: &impl Policy,
        presence: impl FnOnce(&RootStep) -> bool,
    ) -> Result<SigningCommitments, Error> {
        let record = self.record(id)?.clone();
        if record.phase != Phase::Proposed {
            return Err(Error::Locked);
        }
        let review = policy.review(self.store.binding(), &record.step)?;
        let mut next = self.next(now)?;
        for prior in &mut next.records {
            let same_role = prior.review.is_some_and(|r| r.role == review.role);
            let same_scope = if review.role == Role::Recovery {
                prior.step.recovery_gen == record.step.recovery_gen
            } else {
                prior.step.predecessor == record.step.predecessor
            };
            if prior.id == id || prior.phase == Phase::Proposed || !same_role || !same_scope {
                continue;
            }
            let expired = now >= prior.committed_at.checked_add(DEADLINE_SECONDS).ok_or(Error::Bound)?;
            if prior.step_digest != record.step_digest && (prior.permanent || !expired) {
                return Err(Error::Locked);
            }
            if expired && !prior.permanent && prior.phase != Phase::Discarded {
                prior.phase = Phase::Discarded;
                self.nonces.remove(&prior.id);
            }
        }
        if !presence(&record.step) {
            return Err(Error::Presence);
        }
        let selected = next.records.iter_mut().find(|r| r.id == id).ok_or(Error::Invalid)?;
        selected.phase = Phase::Committed;
        selected.review = Some(review);
        selected.committed_at = now;
        self.persist(next)?;
        let (nonces, commitment) = frost::round1::commit(self.key.signing_share(), &mut rng()?);
        let mut next = self.next(now)?;
        let selected = next.records.iter_mut().find(|r| r.id == id).ok_or(Error::Invalid)?;
        selected.phase = Phase::NoncesIssued;
        selected.commitment = Some(commitment.serialize()?);
        self.persist(next)?;
        self.nonces.insert(id, nonces);
        Ok(commitment)
    }

    /// Computes a share once, after durable consumption; exact retries use cache.
    ///
    /// # Errors
    /// Refuses message substitution, replay, expired nonces, changed commitments,
    /// mismatched generation or descriptor, and uncertain durable writes.
    pub fn sign(&mut self, package: &Package, now: u64) -> Result<SignatureShare, Error> {
        let mut next = self.next(now)?;
        let record = self.record(package.id)?.clone();
        self.validate_package(package, &record)?;
        let digest = package.digest()?;
        if let Some(previous) = record.package_digest {
            if previous != digest {
                return Err(Error::Proof);
            }
            return record
                .cached_share
                .as_ref()
                .ok_or(Error::Locked)
                .and_then(|bytes| Ok(SignatureShare::deserialize(bytes)?));
        }
        if record.phase != Phase::NoncesIssued {
            return Err(Error::Locked);
        }
        if now >= record.committed_at.checked_add(DEADLINE_SECONDS).ok_or(Error::Bound)? {
            self.discard(package.id, now)?;
            return Err(Error::Locked);
        }
        let selected = next
            .records
            .iter_mut()
            .find(|r| r.id == package.id)
            .ok_or(Error::Invalid)?;
        selected.phase = Phase::NoncesConsumed;
        selected.package_digest = Some(digest);
        selected.permanent = true;
        // No FROST share exists until this durable write has succeeded.
        self.persist(next)?;
        let nonces = self.nonces.remove(&package.id).ok_or(Error::Locked)?;
        let share = frost::round2::sign(&package.signing, &nonces, &self.key)?;
        drop(nonces);
        let mut next = self.next(now)?;
        let selected = next
            .records
            .iter_mut()
            .find(|r| r.id == package.id)
            .ok_or(Error::Invalid)?;
        selected.phase = Phase::Signed;
        selected.cached_share = Some(share.serialize());
        self.persist(next)?;
        Ok(share)
    }

    /// Abandons one attempt and drops its volatile nonces; permanent locks remain.
    ///
    /// # Errors
    /// Refuses unknown sessions, clock rollback and failed writes.
    pub fn discard(&mut self, id: SessionId, now: u64) -> Result<(), Error> {
        self.nonces.remove(&id);
        let mut next = self.next(now)?;
        next.records
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or(Error::Invalid)?
            .phase = Phase::Discarded;
        self.persist(next)
    }

    fn record(&self, id: SessionId) -> Result<&Record, Error> {
        if self.poisoned {
            return Err(Error::Store);
        }
        self.store
            .snapshot()
            .records
            .iter()
            .find(|r| r.id == id)
            .ok_or(Error::Invalid)
    }

    fn next(&self, now: u64) -> Result<Snapshot, Error> {
        if self.poisoned || now < self.store.snapshot().last_time {
            return Err(Error::Store);
        }
        let mut next = self.store.snapshot().clone();
        next.revision = next.revision.checked_add(1).ok_or(Error::Bound)?;
        next.last_time = now;
        Ok(next)
    }

    fn persist(&mut self, next: Snapshot) -> Result<(), Error> {
        self.poisoned = true;
        self.store.replace(self.store.snapshot().revision, next)?;
        self.poisoned = false;
        Ok(())
    }

    fn validate_package(&self, package: &Package, record: &Record) -> Result<(), Error> {
        let group = &self.store.binding().group;
        if package.generation != group.generation
            || package.descriptor != group.digest()?
            || package.signing.message() != &record.step.message()?
            || package.signing.signing_commitments().len() < usize::from(group.k)
            || package.signing.signing_commitments().len() > group.participants.len()
        {
            return Err(Error::Proof);
        }
        for identifier in package.signing.signing_commitments().keys() {
            if !group.public_package()?.verifying_shares().contains_key(identifier) {
                return Err(Error::Authority);
            }
        }
        let own = package
            .signing
            .signing_commitments()
            .get(self.key.identifier())
            .ok_or(Error::Proof)?;
        if Some(own.serialize()?) != record.commitment {
            return Err(Error::Proof);
        }
        Ok(())
    }
}
