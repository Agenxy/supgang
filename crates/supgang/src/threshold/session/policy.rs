//! Chain-aware review before commitment, separate from physical presence.

use super::Binding;
use crate::threshold::{
    Digest, Error,
    regroup::{Kind, Succession, empty_retained_digest},
    step::{Chain, Operation, RootStep, Status},
};

/// What this group's signature means for the reviewed operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Authorize an ordinary operation or planned succession.
    Root,
    /// Authorize recovery, permanently locking its recovery generation.
    Recovery,
    /// Prove possession of the proposed successor root, granting no authority.
    SuccessorPossession,
    /// Prove possession of a replacement recovery group, granting no authority.
    RecoveryPossession,
}

/// Durable binding to the local chain revision and signing purpose reviewed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Review {
    /// Local tip digest at review, independent of the coordinator's assertion.
    pub tip: Digest,
    /// Authorization or possession; only recovery authorization locks a generation.
    pub role: Role,
}

/// Trusted local operation validator, called before commitment or nonce creation.
///
/// Implementations must review against an authenticated chain snapshot and enforce
/// signer roles and operation semantics. Presence is a separate decision. The
/// caller must serialize local chain changes with review and commitment.
pub trait Policy {
    /// Review this exact operation for the bound participant.
    ///
    /// # Errors
    /// Refuses stale ancestry, unauthorized roles, malformed payloads or bad keys.
    fn review(&self, binding: &Binding, step: &RootStep) -> Result<Review, Error>;
}

/// Default policy for the isolated chain model and its opaque application payloads.
///
/// Non-succession payloads are bounded nonempty bytes; application-specific schemas
/// remain a consumer obligation. Succession payloads are fully decoded and checked.
pub struct ChainPolicy<'a> {
    /// Authenticated local view; recovery may deliberately review a selected branch.
    pub chain: &'a Chain,
    /// Explicit purpose prevents possession signing from consuming authorization.
    pub role: Role,
}

impl Policy for ChainPolicy<'_> {
    fn review(&self, binding: &Binding, step: &RootStep) -> Result<Review, Error> {
        step.encode()?;
        let chain = self.chain;
        let (generation, epoch, sequence) = chain.order();
        if binding.hive != chain.hive()
            || step.hive != chain.hive()
            || step.predecessor != chain.tip()
            || step.sequence != sequence.checked_add(1).ok_or(Error::Bound)?
            || step.epoch != epoch
            || chain.group().public_key == chain.recovery().group.public_key
        {
            return Err(Error::Authority);
        }
        if step.operation == Operation::Succession {
            self.succession(binding, step)?;
        } else if self.role != Role::Root
            || chain.status() != Status::Active
            || binding.group != *chain.group()
            || step.recovery_gen != generation
            || step.payload.is_empty()
            || matches!(step.operation, Operation::Reshare | Operation::SetRecoveryGroup)
        {
            return Err(Error::Authority);
        }
        Ok(Review {
            tip: chain.tip(),
            role: self.role,
        })
    }
}

impl ChainPolicy<'_> {
    fn succession(&self, binding: &Binding, step: &RootStep) -> Result<(), Error> {
        let transition = Succession::decode(&step.payload)?;
        let chain = self.chain;
        let recovery = chain.recovery();
        let changed = transition.recovery != *recovery;
        if transition.previous_key != chain.group().public_key
            || transition.successor.public_key == chain.group().public_key
            || transition.successor.public_key == transition.recovery.group.public_key
            || transition.successor.label != chain.group().label
            || transition.recovery.group.label != chain.group().label
            || transition.successor.generation != chain.group().generation.checked_add(1).ok_or(Error::Bound)?
        {
            return Err(Error::Authority);
        }
        match transition.kind {
            Kind::Planned => {
                if chain.status() != Status::Active || changed || step.recovery_gen != chain.order().0 {
                    return Err(Error::Authority);
                }
            }
            Kind::Recovery => {
                if step.recovery_gen != chain.order().0.checked_add(1).ok_or(Error::Bound)?
                    || transition.retained != empty_retained_digest()
                    || (changed
                        && (transition.recovery.sequence != recovery.sequence.checked_add(1).ok_or(Error::Bound)?
                            || transition.recovery.predecessor != recovery.digest()?
                            || transition.recovery.group.public_key == recovery.group.public_key
                            || transition.recovery.group.generation
                                != recovery.group.generation.checked_add(1).ok_or(Error::Bound)?))
                {
                    return Err(Error::Authority);
                }
            }
        }
        let expected = match self.role {
            Role::Root if transition.kind == Kind::Planned => chain.group(),
            Role::Recovery if transition.kind == Kind::Recovery => &recovery.group,
            Role::SuccessorPossession => &transition.successor,
            Role::RecoveryPossession if changed && transition.kind == Kind::Recovery => &transition.recovery.group,
            _ => return Err(Error::Authority),
        };
        if binding.group != *expected {
            return Err(Error::Authority);
        }
        if matches!(self.role, Role::Root | Role::Recovery) {
            transition.verify_possession(step, changed)?;
        } else if transition.possession != [0; 64] || transition.recovery_possession != [0; 64] {
            return Err(Error::Proof);
        }
        Ok(())
    }
}
