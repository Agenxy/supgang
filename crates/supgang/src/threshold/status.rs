//! Shared, short-lived root status for owner actions and future release roles.
//!
//! No live issuer exists yet. A valid signature bounds staleness; it cannot by
//! itself prove that an isolated issuer knew about a newer root operation.
//! The owner-approved renewal budget and monotonic issuer ledger are not yet
//! represented, so this codec alone cannot enable privileged actions.

use minicbor::{Decoder, Encoder};

use crate::{
    ids::HiveId,
    threshold::{Digest, Error, array, canonical, fixed},
};

/// Fixed protocol ceiling; a consumer or owner policy can require less.
pub const MAX_STATUS_AGE: u64 = 7 * 24 * 60 * 60;
/// Domain for an ordinary root signature over canonical status bytes.
pub const DOMAIN: &[u8] = b"supgang/root-status/v1\0";

/// Protected local constraints against which a signed status is checked.
#[derive(Clone, Copy)]
pub struct Scope {
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
}

/// Root-authorized status at one exact chain head.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Status {
    /// Stable founding hive.
    pub hive: HiveId,
    /// Root-chain head known to the issuer.
    pub root_head: Digest,
    /// Member revocation snapshot serial.
    pub member_serial: u64,
    /// Shared grant-and-role revocation serial.
    pub grant_serial: u64,
    /// UNIX issuance second.
    pub issued_at: u64,
    /// Last UNIX second at which this status can be used.
    pub expires_at: u64,
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
        let mut e = Encoder::new(Vec::new());
        e.array(7)?
            .u8(1)?
            .bytes(self.hive.as_bytes())?
            .bytes(&self.root_head)?
            .u64(self.member_serial)?
            .u64(self.grant_serial)?
            .u64(self.issued_at)?
            .u64(self.expires_at)?;
        Ok(e.into_writer())
    }

    /// Decode canonical status content with a fixed byte ceiling.
    ///
    /// # Errors
    /// Refuses unsupported versions, trailing bytes and nonminimal fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 256 {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 7)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let status = Self {
            hive: HiveId::from_bytes(fixed(&mut d)?),
            root_head: fixed(&mut d)?,
            member_serial: d.u64()?,
            grant_serial: d.u64()?,
            issued_at: d.u64()?,
            expires_at: d.u64()?,
        };
        canonical(bytes, &status.encode()?)?;
        Ok(status)
    }

    /// Check freshness, root head, and local monotonic serial high-water marks.
    ///
    /// # Errors
    /// Refuses stale/future status, an unknown head, rollback, or a weaker policy.
    pub fn check(&self, scope: &Scope) -> Result<(), Error> {
        if scope.maximum_age == 0 || scope.maximum_age > MAX_STATUS_AGE {
            return Err(Error::Bound);
        }
        if self.hive != scope.hive {
            return Err(Error::Authority);
        }
        if self.root_head != scope.head {
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
}

/// Canonical status content plus an ordinary Ed25519 root signature.
#[derive(Clone, Copy, Eq, PartialEq)]
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
        if bytes.len() > 384 {
            return Err(Error::Bound);
        }
        Ok(bytes)
    }

    /// Decode a canonical signed status without trusting its signature yet.
    ///
    /// # Errors
    /// Refuses unsupported versions, trailing bytes, nonminimal fields or bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 384 {
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
    pub fn verify(&self, root_key: &[u8; 32], scope: &Scope) -> Result<(), Error> {
        self.status.check(scope)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(root_key).map_err(|_| Error::Proof)?;
        if key.is_weak() {
            return Err(Error::Proof);
        }
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(&self.status.encode()?);
        key.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&self.signature))
            .map_err(|_| Error::Proof)
    }
}
