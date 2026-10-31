//! Draft root-signed renewal policy and monotonic ledger state.
//!
//! These types are an offline wire and state model. They do not provide a
//! current-head issuer, rollback-resistant storage, or a physical
//! recertification ceremony. No runtime may construct `AvailabilityPermit`.

use minicbor::{Decoder, Encoder};
use sha2::{Digest as _, Sha256};

use crate::{
    ids::HiveId,
    threshold::{Digest, Error, array, canonical, fixed, owner_action::AvailabilityPermit},
};

/// Owner-approved first operating maximum (28 Oct 2026): seven days.
pub const OWNER_MAX_AGE: u64 = 7 * 24 * 60 * 60;
/// Owner-approved first epoch: no unattended status renewals.
pub const OWNER_POLICY_CAP: u64 = 0;
/// Owner-approved first epoch: four fresh-presence status renewals.
pub const OWNER_PRESENCE_CAP: u64 = 4;
/// Owner-approved first epoch: four total status renewals.
pub const OWNER_TOTAL_CAP: u64 = 4;
/// Domain for the ordinary current-root signature on exact policy content.
pub const POLICY_DOMAIN: &[u8] = b"supgang/status-policy/v1\0";
const TERMS_DOMAIN: &[u8] = b"supgang/status-policy-terms/v1\0";

/// Root-authorized renewal terms, bound to the root head at policy issuance.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Policy {
    /// Founding hive identity.
    pub hive: HiveId,
    /// Current authenticated root head at issuance.
    pub root_head: Digest,
    /// Random identifier, never reused across physical recertification epochs.
    pub budget_id: [u8; 16],
    /// Monotonic physical recertification epoch, starting at one.
    pub epoch: u64,
    /// Maximum lease lifetime and age at execution.
    pub maximum_age: u64,
    /// Maximum renewals without owner presence.
    pub policy_cap: u64,
    /// Maximum renewals with fresh owner presence.
    pub presence_cap: u64,
    /// Independent maximum across both modes.
    pub total_cap: u64,
}

impl Policy {
    /// Encode the draft canonical policy content.
    ///
    /// # Errors
    /// Refuses zero budget/epoch, excessive age or renewal caps.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.budget_id == [0; 16]
            || self.epoch == 0
            || self.maximum_age == 0
            || self.maximum_age > OWNER_MAX_AGE
            || self.policy_cap > OWNER_POLICY_CAP
            || self.presence_cap > OWNER_PRESENCE_CAP
            || self.total_cap > OWNER_TOTAL_CAP
            || self.total_cap > self.policy_cap + self.presence_cap
        {
            return Err(Error::Bound);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(9)?
            .u8(1)?
            .bytes(self.hive.as_bytes())?
            .bytes(&self.root_head)?
            .bytes(&self.budget_id)?
            .u64(self.epoch)?
            .u64(self.maximum_age)?
            .u64(self.policy_cap)?
            .u64(self.presence_cap)?
            .u64(self.total_cap)?;
        Ok(e.into_writer())
    }

    /// Decode exact bounded canonical policy content.
    ///
    /// # Errors
    /// Refuses unsupported, oversized, trailing or noncanonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 256 {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 9)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let value = Self {
            hive: HiveId::from_bytes(fixed(&mut d)?),
            root_head: fixed(&mut d)?,
            budget_id: fixed(&mut d)?,
            epoch: d.u64()?,
            maximum_age: d.u64()?,
            policy_cap: d.u64()?,
            presence_cap: d.u64()?,
            total_cap: d.u64()?,
        };
        canonical(bytes, &value.encode()?)?;
        Ok(value)
    }

    /// Identity of policy terms independent of a root-head refresh.
    ///
    /// # Errors
    /// Refuses invalid policy bounds.
    pub fn terms_digest(&self) -> Result<Digest, Error> {
        self.encode()?;
        let mut e = Encoder::new(Vec::new());
        e.array(7)?
            .bytes(self.hive.as_bytes())?
            .bytes(&self.budget_id)?
            .u64(self.epoch)?
            .u64(self.maximum_age)?
            .u64(self.policy_cap)?
            .u64(self.presence_cap)?
            .u64(self.total_cap)?;
        let mut hash = Sha256::new();
        hash.update(TERMS_DOMAIN);
        hash.update(e.into_writer());
        Ok(hash.finalize().into())
    }

    /// Domain-separated identity of the exact policy, including its root head.
    ///
    /// # Errors
    /// Refuses invalid policy bounds.
    pub fn content_digest(&self) -> Result<Digest, Error> {
        let mut hash = Sha256::new();
        hash.update(POLICY_DOMAIN);
        hash.update(self.encode()?);
        Ok(hash.finalize().into())
    }
}

/// Policy content with an ordinary current-root Ed25519 signature.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SignedPolicy {
    /// Exact root-authorized terms.
    pub policy: Policy,
    /// Signature over domain and canonical policy content.
    pub signature: [u8; 64],
}

impl SignedPolicy {
    /// Encode `[1, canonical_policy, signature]`.
    ///
    /// # Errors
    /// Refuses invalid policy content.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut e = Encoder::new(Vec::new());
        e.array(3)?
            .u8(1)?
            .bytes(&self.policy.encode()?)?
            .bytes(&self.signature)?;
        Ok(e.into_writer())
    }

    /// Decode a bounded canonical policy envelope.
    ///
    /// # Errors
    /// Refuses unsupported, trailing, noncanonical or oversized bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 384 {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 3)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let value = Self {
            policy: Policy::decode(d.bytes()?)?,
            signature: fixed(&mut d)?,
        };
        canonical(bytes, &value.encode()?)?;
        Ok(value)
    }

    /// Verify against the locally pinned current root and chain head.
    ///
    /// # Errors
    /// Refuses another hive/head, weak key or invalid root signature.
    pub fn verify(&self, root_key: &[u8; 32], hive: HiveId, head: Digest) -> Result<(), Error> {
        if self.policy.hive != hive || self.policy.root_head != head {
            return Err(Error::Authority);
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(root_key).map_err(|_| Error::Proof)?;
        if key.is_weak() {
            return Err(Error::Proof);
        }
        let mut message = POLICY_DOMAIN.to_vec();
        message.extend_from_slice(&self.policy.encode()?);
        key.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&self.signature))
            .map_err(|_| Error::Proof)
    }
}

/// How one status was issued within an epoch.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Mode {
    /// First lease after physical recertification; no renewal count consumed.
    Initial,
    /// Renewal without a fresh owner-presence assertion.
    Policy,
    /// Renewal approved by a fresh carried-device presence assertion.
    Presence,
}

impl Mode {
    /// Canonical wire label.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Policy => "policy",
            Self::Presence => "presence",
        }
    }

    /// Parse an exact wire label.
    ///
    /// # Errors
    /// Refuses any unknown mode.
    pub fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "initial" => Ok(Self::Initial),
            "policy" => Ok(Self::Policy),
            "presence" => Ok(Self::Presence),
            _ => Err(Error::Invalid),
        }
    }
}

/// Cumulative renewal counts within one budget and epoch.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct Counts {
    /// Unattended policy renewals.
    pub policy: u64,
    /// Fresh-presence renewals.
    pub presence: u64,
    /// Independent total, equal to the sum of the two mode counts.
    pub total: u64,
}

impl Counts {
    /// Check sum and three independent ceilings.
    ///
    /// # Errors
    /// Refuses impossible or over-budget counts.
    pub fn check(self, policy: &Policy) -> Result<(), Error> {
        if self.policy > policy.policy_cap
            || self.presence > policy.presence_cap
            || self.total > policy.total_cap
            || self.policy.checked_add(self.presence) != Some(self.total)
        {
            return Err(Error::Authority);
        }
        Ok(())
    }
}

/// Canonical state to be held by a protected, atomic issuer or target store.
///
/// This is a codec and monotonic model, not the durable store itself. A caller
/// must atomically persist the advanced state before releasing a signed lease
/// or performing a privileged effect. The runtime permit is uninhabited.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Ledger {
    /// Policy terms bound to this state, independent of head refreshes.
    terms: Digest,
    /// Random budget identity.
    budget_id: [u8; 16],
    /// Physical recertification epoch.
    epoch: u64,
    /// Highest observed cumulative counts.
    counts: Counts,
    /// Highest trusted issuance second.
    issued_at: u64,
    /// Exact signed-status digest at the highest counts, or zero before first issue.
    status_digest: Digest,
}

impl Ledger {
    /// Last authenticated status digest, or zero before initial issue.
    #[must_use]
    pub const fn status_digest(&self) -> Digest {
        self.status_digest
    }

    /// Cumulative counts accepted by this ledger.
    #[must_use]
    pub const fn counts(&self) -> Counts {
        self.counts
    }

    /// Runtime enrollment is unavailable until the native physical ceremony
    /// and protected atomic store are implemented.
    ///
    /// # Errors
    /// Always unreachable to safe runtime callers today.
    pub fn new(policy: &Policy, _permit: &AvailabilityPermit) -> Result<Self, Error> {
        Self::draft_new(policy)
    }

    /// Seed protected state for a policy after native physical enrollment.
    ///
    /// # Errors
    /// Refuses invalid policy terms.
    pub(crate) fn draft_new(policy: &Policy) -> Result<Self, Error> {
        Ok(Self {
            terms: policy.terms_digest()?,
            budget_id: policy.budget_id,
            epoch: policy.epoch,
            counts: Counts::default(),
            issued_at: 0,
            status_digest: [0; 32],
        })
    }

    /// Encode the exact protected-state record.
    ///
    /// # Errors
    /// Refuses an impossible empty or inconsistent state.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.terms == [0; 32]
            || self.budget_id == [0; 16]
            || self.epoch == 0
            || self.counts.policy.checked_add(self.counts.presence) != Some(self.counts.total)
            || self.counts.total > OWNER_TOTAL_CAP
            || ((self.status_digest == [0; 32]) != (self.issued_at == 0 && self.counts == Counts::default()))
        {
            return Err(Error::Invalid);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(9)?
            .u8(1)?
            .bytes(&self.terms)?
            .bytes(&self.budget_id)?
            .u64(self.epoch)?
            .u64(self.counts.policy)?
            .u64(self.counts.presence)?
            .u64(self.counts.total)?
            .u64(self.issued_at)?
            .bytes(&self.status_digest)?;
        Ok(e.into_writer())
    }

    /// Decode exact bounded canonical protected-state bytes.
    ///
    /// # Errors
    /// Refuses unsupported, oversized, trailing or noncanonical state.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 256 {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 9)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let value = Self {
            terms: fixed(&mut d)?,
            budget_id: fixed(&mut d)?,
            epoch: d.u64()?,
            counts: Counts {
                policy: d.u64()?,
                presence: d.u64()?,
                total: d.u64()?,
            },
            issued_at: d.u64()?,
            status_digest: fixed(&mut d)?,
        };
        canonical(bytes, &value.encode()?)?;
        Ok(value)
    }

    fn check_common(&self, policy: &Policy, counts: Counts, issued_at: u64, digest: Digest) -> Result<(), Error> {
        if self.terms != policy.terms_digest()?
            || self.budget_id != policy.budget_id
            || self.epoch != policy.epoch
            || issued_at < self.issued_at
            || digest == [0; 32]
        {
            return Err(Error::Authority);
        }
        counts.check(policy)
    }

    /// Model one issuer renewal, requiring exactly one count in its mode.
    /// The actual issuer must sign against current-head evidence and persist
    /// the returned record atomically before releasing the lease.
    ///
    /// # Errors
    /// Refuses count skips, replay, changed terms or exhausted caps.
    pub(crate) fn draft_issue(
        &self,
        policy: &Policy,
        mode: Mode,
        counts: Counts,
        issued_at: u64,
        digest: Digest,
    ) -> Result<Self, Error> {
        self.check_common(policy, counts, issued_at, digest)?;
        let next = match mode {
            Mode::Initial if self.status_digest == [0; 32] && counts == Counts::default() => true,
            Mode::Policy => {
                counts.policy == self.counts.policy.checked_add(1).ok_or(Error::Bound)?
                    && counts.presence == self.counts.presence
                    && counts.total == self.counts.total.checked_add(1).ok_or(Error::Bound)?
            }
            Mode::Presence => {
                counts.policy == self.counts.policy
                    && counts.presence == self.counts.presence.checked_add(1).ok_or(Error::Bound)?
                    && counts.total == self.counts.total.checked_add(1).ok_or(Error::Bound)?
            }
            Mode::Initial => false,
        };
        if !next || (mode != Mode::Initial && self.status_digest == [0; 32]) {
            return Err(Error::Authority);
        }
        Ok(Self {
            counts,
            issued_at,
            status_digest: digest,
            ..*self
        })
    }

    /// Model a target that may miss intermediate leases but must not roll back.
    /// A repeated count must have the identical signed-status digest.
    ///
    /// # Errors
    /// Refuses rollback, same-count equivocation, changed policy or over-budget lease.
    pub(crate) fn draft_observe(
        &self,
        policy: &Policy,
        mode: Mode,
        counts: Counts,
        issued_at: u64,
        digest: Digest,
    ) -> Result<Self, Error> {
        self.check_common(policy, counts, issued_at, digest)?;
        if counts.policy < self.counts.policy
            || counts.presence < self.counts.presence
            || counts.total < self.counts.total
        {
            return Err(Error::Authority);
        }
        if counts == self.counts {
            if self.status_digest != [0; 32] && self.status_digest != digest {
                return Err(Error::Halted);
            }
            if self.status_digest != [0; 32] && self.issued_at != issued_at {
                return Err(Error::Halted);
            }
            if self.status_digest == [0; 32] && mode != Mode::Initial {
                return Err(Error::Authority);
            }
        } else if mode == Mode::Initial
            || self.status_digest == [0; 32]
            || (mode == Mode::Policy && counts.policy == self.counts.policy)
            || (mode == Mode::Presence && counts.presence == self.counts.presence)
        {
            return Err(Error::Authority);
        }
        Ok(Self {
            counts,
            issued_at,
            status_digest: digest,
            ..*self
        })
    }

    /// Runtime issuer transition is unavailable until custody and atomic
    /// storage are implemented and physically accepted.
    ///
    /// # Errors
    /// Always unreachable to safe runtime callers today.
    pub fn issue(
        &self,
        policy: &Policy,
        mode: Mode,
        counts: Counts,
        issued_at: u64,
        digest: Digest,
        _permit: &AvailabilityPermit,
    ) -> Result<Self, Error> {
        self.draft_issue(policy, mode, counts, issued_at, digest)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer as _;

    use super::*;

    fn policy() -> Policy {
        let key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        Policy {
            hive: HiveId::from_root_verifying_key(&key.verifying_key().to_bytes()),
            root_head: [4; 32],
            budget_id: [5; 16],
            epoch: 1,
            maximum_age: OWNER_MAX_AGE,
            policy_cap: OWNER_POLICY_CAP,
            presence_cap: OWNER_PRESENCE_CAP,
            total_cap: OWNER_TOTAL_CAP,
        }
    }

    #[test]
    fn policy_is_canonical_signed_and_exactly_scoped() -> Result<(), Error> {
        let key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let policy = policy();
        assert!(Policy::decode(&policy.encode()?)? == policy);
        let mut message = POLICY_DOMAIN.to_vec();
        message.extend_from_slice(&policy.encode()?);
        let signed = SignedPolicy {
            policy,
            signature: key.sign(&message).to_bytes(),
        };
        assert!(SignedPolicy::decode(&signed.encode()?)? == signed);
        signed.verify(&key.verifying_key().to_bytes(), policy.hive, policy.root_head)?;
        assert!(
            signed
                .verify(&key.verifying_key().to_bytes(), policy.hive, [8; 32])
                .is_err()
        );
        let mut forged = signed;
        forged.policy.presence_cap = 5;
        assert!(
            forged
                .verify(&key.verifying_key().to_bytes(), policy.hive, policy.root_head)
                .is_err()
        );
        let mut invalid = policy;
        invalid.budget_id = [0; 16];
        assert!(invalid.encode().is_err());
        invalid = policy;
        invalid.maximum_age = OWNER_MAX_AGE + 1;
        assert!(invalid.encode().is_err());
        invalid = policy;
        invalid.policy_cap = 1;
        assert!(invalid.encode().is_err());
        invalid = policy;
        invalid.presence_cap = OWNER_PRESENCE_CAP + 1;
        assert!(invalid.encode().is_err());
        invalid = policy;
        invalid.total_cap = OWNER_TOTAL_CAP + 1;
        assert!(invalid.encode().is_err());
        Ok(())
    }

    #[test]
    fn issuer_ledger_enforces_all_three_caps_and_exact_mode_steps() -> Result<(), Error> {
        let policy = policy();
        let ledger = Ledger::draft_new(&policy)?;
        assert!(Ledger::decode(&ledger.encode()?)? == ledger);
        let initial = ledger.draft_issue(&policy, Mode::Initial, Counts::default(), 100, [1; 32])?;
        assert!(
            initial
                .draft_issue(&policy, Mode::Initial, Counts::default(), 101, [2; 32])
                .is_err()
        );
        assert!(
            initial
                .draft_issue(
                    &policy,
                    Mode::Policy,
                    Counts {
                        policy: 1,
                        presence: 0,
                        total: 1
                    },
                    101,
                    [2; 32]
                )
                .is_err()
        );
        assert!(
            initial
                .draft_issue(
                    &policy,
                    Mode::Presence,
                    Counts {
                        policy: 0,
                        presence: 2,
                        total: 2
                    },
                    101,
                    [2; 32]
                )
                .is_err()
        );
        let mut state = initial;
        for count in 1..=OWNER_PRESENCE_CAP {
            state = state.draft_issue(
                &policy,
                Mode::Presence,
                Counts {
                    policy: 0,
                    presence: count,
                    total: count,
                },
                100 + count,
                [u8::try_from(count).map_err(|_| Error::Bound)? + 1; 32],
            )?;
        }
        assert!(
            state
                .draft_issue(
                    &policy,
                    Mode::Presence,
                    Counts {
                        policy: 0,
                        presence: 5,
                        total: 5
                    },
                    110,
                    [9; 32]
                )
                .is_err()
        );
        assert!(
            state
                .draft_issue(&policy, Mode::Presence, state.counts(), 99, [9; 32])
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn target_ledger_rejects_rollback_equivocation_and_changed_terms() -> Result<(), Error> {
        let policy = policy();
        let fresh = Ledger::draft_new(&policy)?;
        let initial = fresh.draft_observe(&policy, Mode::Initial, Counts::default(), 100, [1; 32])?;
        let one = Counts {
            policy: 0,
            presence: 1,
            total: 1,
        };
        let observed = initial.draft_observe(&policy, Mode::Presence, one, 101, [2; 32])?;
        assert!(observed.draft_observe(&policy, Mode::Presence, one, 101, [2; 32])? == observed);
        assert!(matches!(
            observed.draft_observe(&policy, Mode::Presence, one, 101, [3; 32]),
            Err(Error::Halted)
        ));
        assert!(
            observed
                .draft_observe(&policy, Mode::Initial, Counts::default(), 100, [1; 32])
                .is_err()
        );
        assert!(
            observed
                .draft_observe(&policy, Mode::Presence, one, 100, [2; 32])
                .is_err()
        );
        let mut changed = policy;
        changed.total_cap = 3;
        assert!(
            observed
                .draft_observe(&changed, Mode::Presence, one, 101, [2; 32])
                .is_err()
        );
        let mut bytes = observed.encode()?;
        bytes.push(0);
        assert!(Ledger::decode(&bytes).is_err());
        Ok(())
    }
}
