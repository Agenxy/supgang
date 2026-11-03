//! Context-sensitive signature verification precedes chain mutation or fork evidence.

use std::collections::{BTreeMap, BTreeSet};

use super::{Digest, Error, MAX_RECORDS, Operation, Records, SignedStep};
use super::{
    grant::{AnyGrant, Grant, Revocation},
    role_grant::RoleGrant,
};
use crate::{
    ids::HiveId,
    threshold::{
        founding::{GroupDescriptor, RecoveryDescriptor, founding_digest},
        regroup::{Kind, Succession, empty_retained_digest},
    },
};

/// Administrative state of a verified chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// Ordinary operations can extend the current tip.
    Active,
    /// Authenticated conflicting content exists; ordinary operations are refused.
    Halted,
    /// Authenticated history exhausted; consumers must refuse administration.
    Exhausted,
}

/// Outcome of presenting a signed step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Advanced the tip, possibly draining held descendants.
    Accepted,
    /// Unknown predecessor; bounded untrusted memory only, no authority granted.
    Held,
    /// Byte-identical canonical content already accepted.
    Duplicate,
    /// Both authenticated branches retained and administration halted.
    Fork,
}

/// Reserved conflict evidence, independent of the ordinary history capacity.
#[derive(Clone)]
pub struct Conflict {
    /// Digest of the previously authenticated branch.
    pub first: Digest,
    /// Conflicting authenticated branch, retained even when history is full.
    pub second: SignedStep,
}

#[derive(Clone)]
struct Context {
    group: GroupDescriptor,
    epoch: u64,
    recovery_gen: u64,
    sequence: u64,
}

/// In-memory verifier model; callers must not mistake it for service persistence.
///
/// Retains at most 256 historical records, 256 held records and 256 recovery
/// proofs. Exhaustion fails closed. Held records never grant authority.
#[derive(Clone)]
pub struct Chain {
    hive: HiveId,
    founding: Digest,
    tip: Digest,
    current: Context,
    recovery: RecoveryDescriptor,
    contexts: BTreeMap<Digest, Context>,
    records: Records,
    pending: Records,
    children: BTreeMap<Digest, Digest>,
    active: Vec<Digest>,
    recovery_proofs: BTreeMap<u64, (SignedStep, RecoveryDescriptor)>,
    grants: BTreeMap<[u8; 16], AnyGrant>,
    used_grant_ids: BTreeSet<[u8; 16]>,
    grant_revocation_serial: u64,
    status: Status,
    recovery_fork: bool,
    conflict: Option<Conflict>,
}

impl Chain {
    /// Pins founding root and recovery descriptors before any root operation.
    ///
    /// # Errors
    /// Refuses malformed descriptors or noninitial recovery history.
    pub fn new(group: GroupDescriptor, recovery: RecoveryDescriptor) -> Result<Self, Error> {
        if recovery.sequence != 0
            || recovery.predecessor != [0; 32]
            || recovery.group.public_key == group.public_key
            || recovery.group.label != group.label
        {
            return Err(Error::Invalid);
        }
        let founding = founding_digest(&group, Some(&recovery))?;
        let hive = HiveId::from_root_verifying_key(&group.public_key);
        let current = Context {
            group,
            epoch: 0,
            recovery_gen: 0,
            sequence: 0,
        };
        Ok(Self {
            hive,
            founding,
            tip: founding,
            current: current.clone(),
            recovery,
            contexts: BTreeMap::from([(founding, current)]),
            records: BTreeMap::new(),
            pending: BTreeMap::new(),
            children: BTreeMap::new(),
            active: Vec::new(),
            recovery_proofs: BTreeMap::new(),
            grants: BTreeMap::new(),
            used_grant_ids: BTreeSet::new(),
            grant_revocation_serial: 0,
            status: Status::Active,
            recovery_fork: false,
            conflict: None,
        })
    }

    /// Stable identity derived once at founding.
    #[must_use]
    pub const fn hive(&self) -> HiveId {
        self.hive
    }
    /// Current content digest (founding digest before the first operation).
    #[must_use]
    pub const fn tip(&self) -> Digest {
        self.tip
    }
    /// Current recovery-first order, including a succession's advanced epoch.
    #[must_use]
    pub const fn order(&self) -> (u64, u64, u64) {
        (self.current.recovery_gen, self.current.epoch, self.current.sequence)
    }
    /// Current administrative state.
    #[must_use]
    pub const fn status(&self) -> Status {
        self.status
    }
    /// Current root group, never inferred from an input signature.
    #[must_use]
    pub const fn group(&self) -> &GroupDescriptor {
        &self.current.group
    }
    /// Recovery authority pinned independently of the ordinary tip.
    #[must_use]
    pub const fn recovery(&self) -> &RecoveryDescriptor {
        &self.recovery
    }
    /// Authenticated records, including both sides of detected forks.
    #[must_use]
    pub const fn evidence(&self) -> &Records {
        &self.records
    }
    /// Reserved authenticated conflict proof; never displaced by capacity checks.
    #[must_use]
    pub const fn conflict(&self) -> Option<&Conflict> {
        self.conflict.as_ref()
    }
    /// Records still standing on the selected branch after recovery truncation.
    #[must_use]
    pub fn active_digests(&self) -> &[Digest] {
        &self.active
    }
    /// Number of held, untrusted records.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Active typed grant in this in-memory model; not service authorization.
    #[must_use]
    pub fn grant(&self, id: &[u8; 16]) -> Option<&Grant> {
        match (self.status == Status::Active).then(|| self.grants.get(id)).flatten()? {
            AnyGrant::OwnerAction(grant) => Some(grant),
            AnyGrant::Role(_) => None,
        }
    }

    /// Active release or code-signing role in this in-memory model.
    #[must_use]
    pub fn role_grant(&self, id: &[u8; 16]) -> Option<&RoleGrant> {
        match (self.status == Status::Active).then(|| self.grants.get(id)).flatten()? {
            AnyGrant::OwnerAction(_) => None,
            AnyGrant::Role(grant) => Some(grant),
        }
    }

    /// Highest accepted grant-and-role revocation serial, never reset by recovery.
    #[must_use]
    pub const fn grant_revocation_serial(&self) -> u64 {
        self.grant_revocation_serial
    }

    /// Verifies authority and ordering; holds unknown predecessors, detects forks.
    ///
    /// # Errors
    /// Refuses invalid proofs, forbidden operations, stale generations, bounds or
    /// ordinary steps while halted. Recovery may clear an ordinary-root fork.
    pub fn accept(&mut self, signed: SignedStep) -> Result<Outcome, Error> {
        let digest = signed.step.digest()?;
        if signed.step.hive != self.hive {
            return Err(Error::Authority);
        }
        if self.recovery_fork {
            return Err(Error::Halted);
        }
        let succession = if signed.step.operation == Operation::Succession {
            Some(Succession::decode(&signed.step.payload)?)
        } else {
            None
        };
        let outcome = if let Some(transition) = succession.as_ref().filter(|s| s.kind == Kind::Recovery) {
            self.accept_recovery(signed, digest, transition)?
        } else {
            self.accept_ordinary(signed, digest, succession.as_ref())?
        };
        if outcome == Outcome::Accepted {
            self.drain_pending()?;
        }
        Ok(if self.status == Status::Halted {
            Outcome::Fork
        } else {
            outcome
        })
    }

    fn accept_ordinary(
        &mut self,
        signed: SignedStep,
        digest: Digest,
        transition: Option<&Succession>,
    ) -> Result<Outcome, Error> {
        if self.status != Status::Active {
            return Err(Error::Halted);
        }
        let step = &signed.step;
        if matches!(step.operation, Operation::SetRecoveryGroup | Operation::Reshare) {
            return Err(Error::Authority);
        }
        if step.recovery_gen != self.current.recovery_gen {
            return Err(Error::Authority);
        }
        let Some(context) = self.contexts.get(&step.predecessor).cloned() else {
            if self.pending.len() >= MAX_RECORDS {
                return Err(Error::Bound);
            }
            self.pending.insert(digest, signed);
            return Ok(Outcome::Held);
        };
        if context.recovery_gen != self.current.recovery_gen
            || step.epoch != context.epoch
            || step.sequence != context.sequence.checked_add(1).ok_or(Error::Bound)?
        {
            return Err(Error::Authority);
        }
        signed.verify(&context.group.public_key)?;
        let mut next = context.clone();
        next.sequence = step.sequence;
        if let Some(transition) = transition {
            if transition.kind != Kind::Planned
                || transition.previous_key != context.group.public_key
                || transition.recovery != self.recovery
                || transition.successor.public_key == context.group.public_key
                || transition.successor.public_key == transition.recovery.group.public_key
                || transition.successor.label != context.group.label
                || transition.successor.generation != context.group.generation.checked_add(1).ok_or(Error::Bound)?
            {
                return Err(Error::Authority);
            }
            transition.verify_possession(step, false)?;
            next.group = transition.successor.clone();
            next.epoch = context.epoch.checked_add(1).ok_or(Error::Bound)?;
        }
        if self.records.contains_key(&digest) {
            return Ok(Outcome::Duplicate);
        }
        if let Some(existing) = self
            .children
            .get(&step.predecessor)
            .copied()
            .filter(|existing| *existing != digest)
        {
            self.halt(existing, signed, digest);
            if self.records.contains_key(&digest) {
                self.contexts.insert(digest, next);
            }
            return Ok(Outcome::Fork);
        }
        if self.records.len() >= MAX_RECORDS {
            self.status = Status::Exhausted;
            return Err(Error::Bound);
        }
        if step.predecessor != self.tip {
            return Err(Error::Authority);
        }
        self.validate_grant_transition(step)?;
        self.children.insert(step.predecessor, digest);
        self.apply_grant_transition(step)?;
        self.records.insert(digest, signed);
        self.contexts.insert(digest, next.clone());
        self.current = next;
        self.tip = digest;
        self.active.push(digest);
        Ok(Outcome::Accepted)
    }

    fn accept_recovery(
        &mut self,
        signed: SignedStep,
        digest: Digest,
        transition: &Succession,
    ) -> Result<Outcome, Error> {
        let step = &signed.step;
        // Verify same-generation conflicts under the authority that authorized
        // that generation, even if the first transition rotated recovery keys.
        if let Some((previous, authority)) = self.recovery_proofs.get(&step.recovery_gen) {
            signed.verify(&authority.group.public_key)?;
            self.validate_recovery(step, transition, authority)?;
            if previous.step.digest()? == digest {
                return Ok(Outcome::Duplicate);
            }
            self.halt(previous.step.digest()?, signed, digest);
            self.recovery_fork = true;
            return Ok(Outcome::Fork);
        }
        if step.recovery_gen <= self.current.recovery_gen {
            return Err(Error::Authority);
        }
        signed.verify(&self.recovery.group.public_key)?;
        self.validate_recovery(step, transition, &self.recovery)?;
        if self.records.len() >= MAX_RECORDS || self.recovery_proofs.len() >= MAX_RECORDS {
            self.status = Status::Exhausted;
            return Err(Error::Bound);
        }
        let epoch = step.epoch.checked_add(1).ok_or(Error::Bound)?;
        let next = Context {
            group: transition.successor.clone(),
            epoch,
            recovery_gen: step.recovery_gen,
            sequence: step.sequence,
        };
        self.active = self.ancestry(step.predecessor);
        self.active.push(digest);
        // Recovery deliberately discards all owner-action grants. A successor
        // root must issue fresh IDs; retired identities and serials remain spent.
        self.grants.clear();
        self.pending.clear();
        self.children.clear();
        self.recovery_proofs
            .insert(step.recovery_gen, (signed.clone(), self.recovery.clone()));
        self.records.insert(digest, signed);
        self.contexts.insert(digest, next.clone());
        self.current = next;
        self.recovery = transition.recovery.clone();
        self.tip = digest;
        self.status = Status::Active;
        Ok(Outcome::Accepted)
    }

    fn halt(&mut self, first: Digest, signed: SignedStep, digest: Digest) {
        if self.records.len() < MAX_RECORDS {
            self.records.insert(digest, signed.clone());
        }
        self.conflict = Some(Conflict { first, second: signed });
        self.status = Status::Halted;
    }

    fn validate_grant_transition(&self, step: &super::RootStep) -> Result<(), Error> {
        match step.operation {
            Operation::Grant => {
                let grant = AnyGrant::decode(&step.payload)?;
                if self.used_grant_ids.len() >= MAX_RECORDS || self.used_grant_ids.contains(&grant.id()) {
                    return Err(Error::Authority);
                }
            }
            Operation::RevokeGrant => {
                let revoke = Revocation::decode(&step.payload)?;
                if self.grants.get(&revoke.id).map(AnyGrant::kind) != Some(revoke.kind)
                    || revoke.serial != self.grant_revocation_serial.checked_add(1).ok_or(Error::Bound)?
                {
                    return Err(Error::Authority);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn apply_grant_transition(&mut self, step: &super::RootStep) -> Result<(), Error> {
        match step.operation {
            Operation::Grant => {
                let grant = AnyGrant::decode(&step.payload)?;
                self.used_grant_ids.insert(grant.id());
                self.grants.insert(grant.id(), grant);
            }
            Operation::RevokeGrant => {
                let revoke = Revocation::decode(&step.payload)?;
                self.grants.remove(&revoke.id);
                self.grant_revocation_serial = revoke.serial;
            }
            _ => {}
        }
        Ok(())
    }

    fn ancestry(&self, mut predecessor: Digest) -> Vec<Digest> {
        let mut path = Vec::new();
        for _ in 0..MAX_RECORDS {
            if predecessor == self.founding {
                break;
            }
            let Some(record) = self.records.get(&predecessor) else {
                break;
            };
            path.push(predecessor);
            predecessor = record.step.predecessor;
        }
        path.reverse();
        path
    }

    fn validate_recovery(
        &self,
        step: &super::RootStep,
        transition: &Succession,
        authority: &RecoveryDescriptor,
    ) -> Result<(), Error> {
        if transition.retained != empty_retained_digest()
            || transition.successor.label != self.current.group.label
            || transition.successor.public_key == transition.previous_key
            || transition.successor.public_key == transition.recovery.group.public_key
            || transition.recovery.group.label != self.current.group.label
        {
            return Err(Error::Authority);
        }
        if let Some(context) = self.contexts.get(&step.predecessor)
            && (transition.previous_key != context.group.public_key
                || step.epoch != context.epoch
                || step.sequence != context.sequence.checked_add(1).ok_or(Error::Bound)?)
        {
            return Err(Error::Authority);
        }
        let changed = transition.recovery != *authority;
        if changed
            && (transition.recovery.sequence != authority.sequence.checked_add(1).ok_or(Error::Bound)?
                || transition.recovery.predecessor != authority.digest()?
                || transition.recovery.group.public_key == authority.group.public_key
                || transition.recovery.group.generation
                    != authority.group.generation.checked_add(1).ok_or(Error::Bound)?)
        {
            return Err(Error::Authority);
        }
        transition.verify_possession(step, changed)
    }

    fn drain_pending(&mut self) -> Result<(), Error> {
        // Each iteration removes at least one item. Invalid held input is
        // dropped without rolling back a legitimate newly accepted predecessor.
        for _ in 0..MAX_RECORDS {
            if self.status != Status::Active {
                break;
            }
            let Some(digest) = self
                .pending
                .iter()
                .find(|(_, s)| self.contexts.contains_key(&s.step.predecessor))
                .map(|(d, _)| *d)
            else {
                break;
            };
            let signed = self.pending.remove(&digest).ok_or(Error::Invalid)?;
            let transition = if signed.step.operation == Operation::Succession {
                match Succession::decode(&signed.step.payload) {
                    Ok(s) => Some(s),
                    Err(_) => continue,
                }
            } else {
                None
            };
            if matches!(
                self.accept_ordinary(signed, digest, transition.as_ref()),
                Err(Error::Bound)
            ) {
                return Err(Error::Bound);
            }
        }
        Ok(())
    }
}
