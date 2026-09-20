//! Canonical root steps and authenticated, bounded fork-detecting chains.

use std::collections::BTreeMap;

use minicbor::{Decoder, Encoder};

use super::{Digest, Error, MAX_RECORDS, MAX_STEP_BYTES, array, canonical, fixed, hash};
use crate::ids::{HiveId, NodeId};

mod chain;
pub use chain::{Chain, Conflict, Outcome, Status};

/// Domain prepended to canonical step bytes for ordinary Ed25519 signing.
pub const DOMAIN: &[u8] = b"supgang/root-step/v1\0";

/// Closed operation inventory; opaque payloads confer no application authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Issue membership.
    IssueMembership,
    /// Revoke membership.
    Revoke,
    /// Authorize an anchor.
    TrustAnchor,
    /// Allocate a name.
    AllocateName,
    /// Authorize a leaf.
    IssueLeaf,
    /// Reserved, refused until a separate reshare protocol exists.
    Reshare,
    /// Planned or recovery root rotation.
    Succession,
    /// Reserved as a standalone operation; changes occur inside recovery only.
    SetRecoveryGroup,
    /// Admit a pending roster to an isolated DKG, not application membership.
    AdmitRoster,
}

impl Operation {
    const fn text(self) -> &'static str {
        match self {
            Self::IssueMembership => "issue-membership",
            Self::Revoke => "revoke",
            Self::TrustAnchor => "trust-anchor",
            Self::AllocateName => "allocate-name",
            Self::IssueLeaf => "issue-leaf",
            Self::Reshare => "reshare",
            Self::Succession => "succession",
            Self::SetRecoveryGroup => "set-recovery-group",
            Self::AdmitRoster => "admit-roster",
        }
    }

    fn parse(text: &str) -> Result<Self, Error> {
        match text {
            "issue-membership" => Ok(Self::IssueMembership),
            "revoke" => Ok(Self::Revoke),
            "trust-anchor" => Ok(Self::TrustAnchor),
            "allocate-name" => Ok(Self::AllocateName),
            "issue-leaf" => Ok(Self::IssueLeaf),
            "reshare" => Ok(Self::Reshare),
            "succession" => Ok(Self::Succession),
            "set-recovery-group" => Ok(Self::SetRecoveryGroup),
            "admit-roster" => Ok(Self::AdmitRoster),
            _ => Err(Error::Invalid),
        }
    }
}

/// All fields of RootStep/v1; identity is its canonical content, not a signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootStep {
    /// Stable founding hive identity.
    pub hive: HiveId,
    /// Prior content digest or founding digest.
    pub predecessor: Digest,
    /// Predecessor sequence plus one; founding sequence is zero.
    pub sequence: u64,
    /// Authorizing root epoch; a succession's successor uses epoch plus one.
    pub epoch: u64,
    /// Recovery generation; only recovery may advance it.
    pub recovery_gen: u64,
    /// Closed operation tag.
    pub operation: Operation,
    /// Operation-specific bytes, at most 12 KiB.
    pub payload: Vec<u8>,
    /// Owner-reviewed UNIX proposal time.
    pub proposed_at: u64,
    /// Device proposing the operation.
    pub proposer: NodeId,
}

impl RootStep {
    /// Canonical definite array in ADR field order, preceded by version 1.
    ///
    /// # Errors
    /// Refuses zero sequence or a payload/record exceeding the byte ceiling.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.sequence == 0 || self.payload.len() > 12 * 1024 {
            return Err(Error::Bound);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(10)?
            .u8(1)?
            .bytes(self.hive.as_bytes())?
            .bytes(&self.predecessor)?;
        e.u64(self.sequence)?
            .u64(self.epoch)?
            .u64(self.recovery_gen)?
            .str(self.operation.text())?;
        e.bytes(&self.payload)?
            .u64(self.proposed_at)?
            .bytes(self.proposer.as_bytes())?;
        let bytes = e.into_writer();
        if bytes.len() > MAX_STEP_BYTES {
            return Err(Error::Bound);
        }
        Ok(bytes)
    }

    /// Bounded strict decoding with re-encoding equality, including trailing data.
    ///
    /// # Errors
    /// Refuses nonminimal integers, indefinite lengths, unknown tags and bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_STEP_BYTES {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 10)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let result = Self {
            hive: HiveId::from_bytes(fixed(&mut d)?),
            predecessor: fixed(&mut d)?,
            sequence: d.u64()?,
            epoch: d.u64()?,
            recovery_gen: d.u64()?,
            operation: Operation::parse(d.str()?)?,
            payload: d.bytes()?.to_vec(),
            proposed_at: d.u64()?,
            proposer: NodeId::from_bytes(fixed(&mut d)?),
        };
        canonical(bytes, &result.encode()?)?;
        Ok(result)
    }

    /// SHA-256 of canonical content, excluding signature and domain prefix.
    ///
    /// # Errors
    /// Refuses malformed or oversized steps.
    pub fn digest(&self) -> Result<Digest, Error> {
        Ok(hash(&self.encode()?))
    }

    /// Exact Ed25519 signing message: domain followed by the whole canonical step.
    ///
    /// # Errors
    /// Refuses malformed or oversized steps.
    pub fn message(&self) -> Result<Vec<u8>, Error> {
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(&self.encode()?);
        Ok(message)
    }

    /// Recovery generation outranks every ordinary epoch and sequence.
    #[must_use]
    pub const fn order(&self) -> (u64, u64, u64) {
        (self.recovery_gen, self.epoch, self.sequence)
    }
}

/// Root step with an ordinary Ed25519 aggregate signature.
#[derive(Clone, Debug)]
pub struct SignedStep {
    /// Canonical signed content.
    pub step: RootStep,
    /// Fixed 64-byte ordinary Ed25519 signature.
    pub signature: [u8; 64],
}

impl SignedStep {
    /// Strict Ed25519 verification used by the real verifier library.
    ///
    /// # Errors
    /// Refuses weak keys, invalid signatures and malformed records.
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<(), Error> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(|_| Error::Proof)?;
        if key.is_weak() {
            return Err(Error::Proof);
        }
        key.verify_strict(
            &self.step.message()?,
            &ed25519_dalek::Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Error::Proof)
    }
}

type Records = BTreeMap<Digest, SignedStep>;
