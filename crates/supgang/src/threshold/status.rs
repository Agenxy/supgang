//! Shared, short-lived root status for owner actions and future release roles.
//!
//! No live issuer exists yet. A valid signature bounds staleness; it cannot by
//! itself prove that an isolated issuer knew about a newer root operation.
//! The owner approved initial renewal limits; issuer current-head evidence and
//! physically proven atomic storage are still absent. This codec cannot enable privileged actions.

use minicbor::{Decoder, Encoder};

use crate::{
    ids::{HiveId, NodeId},
    threshold::{
        Digest, Error, array, canonical, count, fixed,
        status_renewal::{Counts, Ledger, Mode, SignedPolicy},
    },
};

/// Fixed protocol ceiling; a consumer or owner policy can require less.
pub const MAX_STATUS_AGE: u64 = 7 * 24 * 60 * 60;
/// Maximum active grant and member entries in one authenticated snapshot.
pub const MAX_ACTIVE_ENTRIES: usize = 256;
const MAX_STATUS_BYTES: usize = 16 * 1024;
const MAX_SIGNED_STATUS_BYTES: usize = MAX_STATUS_BYTES + 128;
/// Domain for an ordinary root signature over canonical status bytes.
pub const DOMAIN: &[u8] = b"supgang/root-status/v1\0";

/// Protected local constraints against which a signed status is checked.
#[derive(Clone, Copy)]
pub struct Scope<'a> {
    /// Pinned founding hive.
    pub hive: HiveId,
    /// Current authenticated root-chain head.
    pub head: Digest,
    /// Persisted member-revocation high-water mark.
    pub member_floor: u64,
    /// Persisted grant-and-role-revocation high-water mark.
    pub grant_floor: u64,
    /// Trusted target clock.
    pub now: u64,
    /// Owner-approved age further narrowed by consumer policy.
    pub maximum_age: u64,
    /// Root-signed renewal terms for this exact status head.
    pub policy: &'a SignedPolicy,
    /// Target's protected monotonic high-water state.
    pub ledger: &'a Ledger,
}

/// Root-authorized status at one exact chain head.
#[derive(Clone, Eq, PartialEq)]
pub struct Status {
    /// Stable founding hive.
    pub hive: HiveId,
    /// Root-chain head known to the issuer.
    pub root_head: Digest,
    /// Member revocation snapshot serial.
    pub member_serial: u64,
    /// Shared grant-and-role revocation serial.
    pub grant_serial: u64,
    /// Sorted active grant and role IDs at this exact root head.
    pub active_grants: Vec<[u8; 16]>,
    /// Sorted active member device IDs at this exact root head.
    pub active_members: Vec<NodeId>,
    /// UNIX issuance second.
    pub issued_at: u64,
    /// Last UNIX second at which this status can be used.
    pub expires_at: u64,
    /// Domain-separated identity of the exact root-signed renewal policy.
    pub policy_digest: Digest,
    /// Random renewal-budget identity.
    pub budget_id: [u8; 16],
    /// Physical recertification epoch.
    pub epoch: u64,
    /// How this lease consumed its renewal budget.
    pub mode: Mode,
    /// Cumulative counts under the policy's three independent caps.
    pub counts: Counts,
}

impl Status {
    /// Encode canonical status content.
    ///
    /// # Errors
    /// Refuses zero-length or excessive validity windows.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.issued_at >= self.expires_at || self.expires_at - self.issued_at > MAX_STATUS_AGE {
            return Err(Error::Bound);
        }
        self.check_active_sets()?;
        let mut e = Encoder::new(Vec::new());
        e.array(16)?
            .u8(1)?
            .bytes(self.hive.as_bytes())?
            .bytes(&self.root_head)?
            .u64(self.member_serial)?
            .u64(self.grant_serial)?
            .array(u64::try_from(self.active_grants.len()).map_err(|_| Error::Bound)?)?;
        for id in &self.active_grants {
            e.bytes(id)?;
        }
        e.array(u64::try_from(self.active_members.len()).map_err(|_| Error::Bound)?)?;
        for member in &self.active_members {
            e.bytes(member.as_bytes())?;
        }
        e.u64(self.issued_at)?
            .u64(self.expires_at)?
            .bytes(&self.policy_digest)?
            .bytes(&self.budget_id)?
            .u64(self.epoch)?
            .str(self.mode.text())?
            .u64(self.counts.policy)?
            .u64(self.counts.presence)?
            .u64(self.counts.total)?;
        let bytes = e.into_writer();
        if bytes.len() > MAX_STATUS_BYTES {
            return Err(Error::Bound);
        }
        Ok(bytes)
    }

    /// Decode canonical status content with a fixed byte ceiling.
    ///
    /// # Errors
    /// Refuses unsupported versions, trailing bytes and nonminimal fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_STATUS_BYTES {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 16)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let hive = HiveId::from_bytes(fixed(&mut d)?);
        let root_head = fixed(&mut d)?;
        let member_serial = d.u64()?;
        let grant_serial = d.u64()?;
        let grant_count = count(&mut d, MAX_ACTIVE_ENTRIES)?;
        let mut active_grants = Vec::with_capacity(grant_count);
        for _ in 0..grant_count {
            active_grants.push(fixed(&mut d)?);
        }
        let member_count = count(&mut d, MAX_ACTIVE_ENTRIES)?;
        let mut active_members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            active_members.push(NodeId::from_bytes(fixed(&mut d)?));
        }
        let status = Self {
            hive,
            root_head,
            member_serial,
            grant_serial,
            active_grants,
            active_members,
            issued_at: d.u64()?,
            expires_at: d.u64()?,
            policy_digest: fixed(&mut d)?,
            budget_id: fixed(&mut d)?,
            epoch: d.u64()?,
            mode: Mode::parse(d.str()?)?,
            counts: Counts {
                policy: d.u64()?,
                presence: d.u64()?,
                total: d.u64()?,
            },
        };
        canonical(bytes, &status.encode()?)?;
        Ok(status)
    }

    /// Check freshness, root head, and local monotonic serial high-water marks.
    ///
    /// # Errors
    /// Refuses stale/future status, an unknown head, rollback, or a weaker policy.
    pub fn check(&self, scope: &Scope<'_>) -> Result<(), Error> {
        self.check_active_sets()?;
        let policy = &scope.policy.policy;
        if scope.maximum_age == 0 || scope.maximum_age > policy.maximum_age {
            return Err(Error::Bound);
        }
        if self.hive != scope.hive || self.hive != policy.hive {
            return Err(Error::Authority);
        }
        if self.root_head != scope.head || scope.head != policy.root_head {
            return Err(Error::Authority);
        }
        if self.policy_digest != policy.content_digest()?
            || self.budget_id != policy.budget_id
            || self.epoch != policy.epoch
        {
            return Err(Error::Authority);
        }
        self.counts.check(policy)?;
        if (self.mode == Mode::Initial && self.counts != Counts::default())
            || (self.mode == Mode::Policy && self.counts.policy == 0)
            || (self.mode == Mode::Presence && self.counts.presence == 0)
        {
            return Err(Error::Authority);
        }
        if self.member_serial < scope.member_floor || self.grant_serial < scope.grant_floor {
            return Err(Error::Authority);
        }
        if self.issued_at >= self.expires_at {
            return Err(Error::Authority);
        }
        if scope.now < self.issued_at || scope.now > self.expires_at {
            return Err(Error::Authority);
        }
        if scope.now - self.issued_at > scope.maximum_age || self.expires_at - self.issued_at > scope.maximum_age {
            return Err(Error::Authority);
        }
        Ok(())
    }

    /// Require a role or owner grant and every named signer device to remain active.
    ///
    /// # Errors
    /// Refuses a missing grant or signer device in this authenticated snapshot.
    pub fn check_active_grant(&self, grant_id: &[u8; 16], signer_nodes: &[NodeId]) -> Result<(), Error> {
        self.check_active_sets()?;
        if signer_nodes.is_empty()
            || signer_nodes.len() > 3
            || self.active_grants.binary_search(grant_id).is_err()
            || signer_nodes
                .iter()
                .any(|node| self.active_members.binary_search(node).is_err())
        {
            return Err(Error::Authority);
        }
        Ok(())
    }

    fn check_active_sets(&self) -> Result<(), Error> {
        if self.active_grants.len() > MAX_ACTIVE_ENTRIES
            || self.active_members.len() > MAX_ACTIVE_ENTRIES
            || !self.active_grants.windows(2).all(|pair| pair.first() < pair.get(1))
            || !self.active_members.windows(2).all(|pair| pair.first() < pair.get(1))
        {
            return Err(Error::Bound);
        }
        Ok(())
    }
}

/// Canonical status content plus an ordinary Ed25519 root signature.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedStatus {
    /// Signed content.
    pub status: Status,
    /// Strict Ed25519 signature, never an unsigned label.
    pub signature: [u8; 64],
}

impl SignedStatus {
    /// Encode a bounded canonical signed-status envelope.
    ///
    /// # Errors
    /// Refuses malformed status or a record outside its fixed size ceiling.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut e = Encoder::new(Vec::new());
        e.array(3)?
            .u8(1)?
            .bytes(&self.status.encode()?)?
            .bytes(&self.signature)?;
        let bytes = e.into_writer();
        if bytes.len() > MAX_SIGNED_STATUS_BYTES {
            return Err(Error::Bound);
        }
        Ok(bytes)
    }

    /// Decode a canonical signed status without trusting its signature yet.
    ///
    /// # Errors
    /// Refuses unsupported versions, trailing bytes, nonminimal fields or bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SIGNED_STATUS_BYTES {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 3)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let result = Self {
            status: Status::decode(d.bytes()?)?,
            signature: fixed(&mut d)?,
        };
        canonical(bytes, &result.encode()?)?;
        Ok(result)
    }

    /// Verify against the pinned current root key and local status constraints.
    ///
    /// # Errors
    /// Refuses weak keys, invalid signatures, stale status, or rollback.
    pub fn verify(&self, root_key: &[u8; 32], scope: &Scope<'_>) -> Result<Ledger, Error> {
        scope.policy.verify(root_key, scope.hive, scope.head)?;
        self.status.check(scope)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(root_key).map_err(|_| Error::Proof)?;
        if key.is_weak() {
            return Err(Error::Proof);
        }
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(&self.status.encode()?);
        key.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&self.signature))
            .map_err(|_| Error::Proof)?;
        let digest = crate::threshold::hash(&self.encode()?);
        scope.ledger.draft_observe(
            &scope.policy.policy,
            self.status.mode,
            self.status.counts,
            self.status.issued_at,
            digest,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Counts, MAX_ACTIVE_ENTRIES, Mode, NodeId, Status};
    use crate::{ids::HiveId, threshold::Error};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn sample() -> Status {
        Status {
            hive: HiveId::from_bytes([1; 32]),
            root_head: [2; 32],
            member_serial: 0,
            grant_serial: 0,
            active_grants: vec![[3; 16]],
            active_members: vec![NodeId::from_bytes([4; 32])],
            issued_at: 100,
            expires_at: 200,
            policy_digest: [5; 32],
            budget_id: [6; 16],
            epoch: 1,
            mode: Mode::Initial,
            counts: Counts::default(),
        }
    }

    #[test]
    fn active_sets_are_exact_sorted_bounded_and_canonical() -> TestResult {
        let status = sample();
        assert!(Status::decode(&status.encode()?)? == status);
        status.check_active_grant(&[3; 16], &[NodeId::from_bytes([4; 32])])?;
        assert!(
            status
                .check_active_grant(&[7; 16], &[NodeId::from_bytes([4; 32])])
                .is_err()
        );
        assert!(
            status
                .check_active_grant(&[3; 16], &[NodeId::from_bytes([8; 32])])
                .is_err()
        );
        assert!(status.check_active_grant(&[3; 16], &[]).is_err());

        let mut invalid = status.clone();
        invalid.active_grants = vec![[3; 16], [3; 16]];
        assert!(matches!(invalid.encode(), Err(Error::Bound)));
        invalid.active_grants = vec![[4; 16], [3; 16]];
        assert!(invalid.encode().is_err());
        invalid = status.clone();
        invalid.active_members = vec![NodeId::from_bytes([5; 32]), NodeId::from_bytes([4; 32])];
        assert!(invalid.encode().is_err());

        let mut maximal = status;
        maximal.active_grants = (0_u8..=u8::MAX).map(|value| [value; 16]).collect();
        maximal.active_members = (0_u8..=u8::MAX).map(|value| NodeId::from_bytes([value; 32])).collect();
        assert_eq!(maximal.active_grants.len(), MAX_ACTIVE_ENTRIES);
        assert!(Status::decode(&maximal.encode()?)? == maximal);
        maximal.active_grants.push([u8::MAX; 16]);
        assert!(maximal.encode().is_err());
        Ok(())
    }
}
