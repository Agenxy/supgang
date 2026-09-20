//! New-root DKG and possession-bound planned/recovery succession payloads.

use minicbor::{Decoder, Encoder};

use super::founding::{GroupDescriptor, RecoveryDescriptor};
use super::step::{Operation, RootStep, SignedStep};
use super::{Digest, Error, array, canonical, fixed};

/// Runs a fresh DKG for a changed roster with the next share generation.
///
/// The old quorum must separately sign a planned `Succession` before a verifier
/// uses this output. This function grants no membership or control admission.
///
/// # Errors
/// Refuses parameter/loss-policy violations, bad packages, bounds or overflow.
pub fn fresh_dkg(
    current: &GroupDescriptor,
    parameters: super::founding::Parameters,
    devices: &[crate::device_key::DevicePublicKey],
    recovery: &RecoveryDescriptor,
    exchange: impl FnMut(u8, &mut super::founding::Channel),
) -> Result<super::founding::Group, Error> {
    super::founding::run(
        &current.label,
        parameters,
        current.generation.checked_add(1).ok_or(Error::Bound)?,
        devices,
        Some(recovery),
        exchange,
    )
}

/// Authority under which a root succession occurs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Current root signs, retains a frozen set and preserves recovery authority.
    Planned,
    /// Independent recovery group signs, advances recovery generation, retains nothing.
    Recovery,
}

/// Exact public transition payload, including successor possession.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Succession {
    /// Planned or recovery authorization.
    pub kind: Kind,
    /// Retired root key at the named predecessor.
    pub previous_key: [u8; 32],
    /// Fresh DKG output for the successor.
    pub successor: GroupDescriptor,
    /// Frozen retained-set digest; recovery requires the empty-set digest.
    pub retained: Digest,
    /// Recovery descriptor in force afterward.
    pub recovery: RecoveryDescriptor,
    /// Successor signature over the same step with possession slots zeroed.
    pub possession: [u8; 64],
    /// New recovery group's possession, required only on a descriptor change.
    pub recovery_possession: [u8; 64],
}

impl Succession {
    /// Canonical payload; descriptor digests are redundantly bound and checked.
    ///
    /// # Errors
    /// Refuses malformed descriptors.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut e = Encoder::new(Vec::new());
        e.array(10)?.u8(1)?.str(match self.kind {
            Kind::Planned => "planned",
            Kind::Recovery => "recovery",
        })?;
        e.bytes(&self.previous_key)?
            .bytes(&self.successor.encode()?)?
            .bytes(&self.successor.digest()?)?;
        e.bytes(&self.retained)?
            .bytes(&self.recovery.encode()?)?
            .bytes(&self.recovery.digest()?)?;
        e.bytes(&self.possession)?.bytes(&self.recovery_possession)?;
        Ok(e.into_writer())
    }

    /// Strict bounded payload decoding.
    ///
    /// # Errors
    /// Refuses unknown kinds, noncanonical bytes and inconsistent descriptor digests.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 12 * 1024 {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 10)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let kind = match d.str()? {
            "planned" => Kind::Planned,
            "recovery" => Kind::Recovery,
            _ => return Err(Error::Invalid),
        };
        let previous_key = fixed(&mut d)?;
        let successor = GroupDescriptor::decode(d.bytes()?)?;
        if fixed::<32>(&mut d)? != successor.digest()? {
            return Err(Error::Proof);
        }
        let retained = fixed(&mut d)?;
        let recovery = RecoveryDescriptor::decode(d.bytes()?)?;
        if fixed::<32>(&mut d)? != recovery.digest()? {
            return Err(Error::Proof);
        }
        let result = Self {
            kind,
            previous_key,
            successor,
            retained,
            recovery,
            possession: fixed(&mut d)?,
            recovery_possession: fixed(&mut d)?,
        };
        canonical(bytes, &result.encode()?)?;
        Ok(result)
    }

    /// Step that the new root and, when changed, new recovery group must sign.
    ///
    /// # Errors
    /// Refuses a non-succession operation or malformed descriptors.
    pub fn possession_step(&self, step: &RootStep) -> Result<RootStep, Error> {
        if step.operation != Operation::Succession {
            return Err(Error::Invalid);
        }
        let mut unsigned = self.clone();
        unsigned.possession = [0; 64];
        unsigned.recovery_possession = [0; 64];
        let mut proposal = step.clone();
        proposal.payload = unsigned.encode()?;
        Ok(proposal)
    }

    pub(super) fn verify_possession(&self, step: &RootStep, recovery_changed: bool) -> Result<(), Error> {
        let possession_step = self.possession_step(step)?;
        SignedStep {
            step: possession_step.clone(),
            signature: self.possession,
        }
        .verify(&self.successor.public_key)?;
        if recovery_changed {
            SignedStep {
                step: possession_step,
                signature: self.recovery_possession,
            }
            .verify(&self.recovery.group.public_key)?;
        } else if self.recovery_possession != [0; 64] {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Identity of the canonical empty retained set, required for every recovery.
#[must_use]
pub fn empty_retained_digest() -> Digest {
    super::hash(&[0x80])
}
