//! Signed, single-writer endpoint records.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    candidate::{EndpointCandidate, MAX_CANDIDATES},
    identity::{DeviceIdentity, verify_domain},
    ids::{HiveId, NodeId, TransportKeyId},
    membership::{MembershipError, MembershipRoles, SignedMembership},
    wire,
};

/// Domain separator for endpoint-record signatures.
pub const ENDPOINT_RECORD_SIGNATURE_DOMAIN: &[u8] = b"supgang/endpoint-record/v1\0";
/// Current endpoint-record protocol version.
pub const ENDPOINT_RECORD_VERSION: u16 = 1;
/// Maximum lifetime of one endpoint record, in seconds.
pub const MAX_RECORD_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;
/// Maximum tolerated future clock skew, in seconds.
pub const MAX_FUTURE_SKEW_SECONDS: u64 = 5 * 60;

/// Capabilities an endpoint record may advertise.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Capabilities(u64);

impl Capabilities {
    /// No optional capabilities.
    pub const NONE: Self = Self(0);
    /// The node may introduce authenticated hive members.
    pub const INTRODUCER: Self = Self(1 << 0);
    /// The node may relay bounded Supgang control frames.
    pub const CONTROL_RELAY: Self = Self(1 << 1);
    const KNOWN_BITS: u64 = Self::INTRODUCER.0 | Self::CONTROL_RELAY.0;

    /// Constructs a capability bitset after rejecting unknown critical bits.
    ///
    /// # Errors
    ///
    /// Returns an error when this protocol version does not define one or more bits.
    pub const fn from_bits(bits: u64) -> Result<Self, RecordError> {
        if bits & !Self::KNOWN_BITS == 0 {
            Ok(Self(bits))
        } else {
            Err(RecordError::UnknownCapability)
        }
    }

    /// Returns the encoded bitset.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns whether all bits in `other` are present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for Capabilities {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// The authoritative, unsigned contents of one node's current endpoint record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndpointRecord {
    /// Exact protocol version and downgrade boundary.
    pub protocol_version: u16,
    /// Hive in which the record is valid.
    pub hive_id: HiveId,
    /// Stable author identity.
    pub node_id: NodeId,
    /// Current short-lived transport certificate or public-key identifier.
    pub transport_key_id: TransportKeyId,
    /// Explicit recovery generation.
    pub generation: u64,
    /// Transactionally increasing sequence within the generation.
    pub sequence: u64,
    /// UNIX timestamp at which the record was issued.
    pub issued_at: u64,
    /// UNIX timestamp after which the record is stale.
    pub expires_at: u64,
    /// Bounded, sorted endpoint candidates.
    pub candidates: Vec<EndpointCandidate>,
    /// Optional node roles relevant to discovery and control-frame forwarding.
    pub capabilities: Capabilities,
}

impl EndpointRecord {
    /// Validates shape, bounds, ordering, and time-independent semantics.
    ///
    /// # Errors
    ///
    /// Returns the first violated record invariant.
    pub fn validate_shape(&self) -> Result<(), RecordError> {
        if self.protocol_version != ENDPOINT_RECORD_VERSION {
            return Err(RecordError::UnsupportedVersion);
        }
        if self.sequence == 0 {
            return Err(RecordError::ZeroSequence);
        }
        if self.expires_at <= self.issued_at {
            return Err(RecordError::InvalidLifetime);
        }
        if self.expires_at.saturating_sub(self.issued_at) > MAX_RECORD_LIFETIME_SECONDS {
            return Err(RecordError::LifetimeTooLong);
        }
        if self.candidates.len() > MAX_CANDIDATES {
            return Err(RecordError::TooManyCandidates);
        }
        if !strictly_sorted(&self.candidates) {
            return Err(RecordError::CandidatesNotCanonical);
        }
        Capabilities::from_bits(self.capabilities.bits())?;
        Ok(())
    }

    /// Validates freshness against a trusted local wall clock.
    ///
    /// # Errors
    ///
    /// Rejects expired records and issue times too far in the future.
    pub const fn validate_time(&self, now: u64) -> Result<(), RecordError> {
        if self.expires_at < now {
            return Err(RecordError::Expired);
        }
        if self.issued_at > now.saturating_add(MAX_FUTURE_SKEW_SECONDS) {
            return Err(RecordError::IssuedInFuture);
        }
        Ok(())
    }

    /// Sorts and deduplicates candidate endpoints before signing.
    pub fn canonicalize_candidates(&mut self) {
        self.candidates.sort_unstable();
        self.candidates.dedup();
    }
}

/// An endpoint record and its author's Ed25519 signature.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedEndpointRecord {
    /// Canonical record content.
    pub record: EndpointRecord,
    /// Domain-separated Ed25519 signature over canonical record bytes.
    pub signature: Vec<u8>,
}

impl SignedEndpointRecord {
    /// Canonicalizes, validates, and signs an endpoint record.
    ///
    /// # Errors
    ///
    /// Rejects a record whose node does not match the signer or whose invariants fail.
    pub fn sign(mut record: EndpointRecord, identity: &DeviceIdentity) -> Result<Self, RecordError> {
        record.canonicalize_candidates();
        record.validate_shape()?;
        if record.node_id != identity.node_id() {
            return Err(RecordError::SignerMismatch);
        }
        let payload = wire::encode_endpoint_record(&record).map_err(|_| RecordError::Encoding)?;
        let signature = identity
            .sign_domain(ENDPOINT_RECORD_SIGNATURE_DOMAIN, &payload)
            .to_vec();
        Ok(Self { record, signature })
    }

    /// Verifies canonical shape, signer identity, and signature.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical, mismatched, and incorrectly signed records.
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), RecordError> {
        self.record.validate_shape()?;
        if self.record.node_id != NodeId::from_verifying_key(&key.to_bytes()) {
            return Err(RecordError::SignerMismatch);
        }
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| RecordError::InvalidSignature)?;
        let payload = wire::encode_endpoint_record(&self.record).map_err(|_| RecordError::Encoding)?;
        if !verify_domain(key, ENDPOINT_RECORD_SIGNATURE_DOMAIN, &payload, &signature) {
            return Err(RecordError::InvalidSignature);
        }
        Ok(())
    }

    /// Verifies record signature, freshness, hive membership, and capability authorization.
    ///
    /// # Errors
    ///
    /// Rejects invalid membership, cross-hive or cross-node binding, expired
    /// content, signature failure, and capabilities not granted by the root.
    pub fn verify_authorized(
        &self,
        membership: &SignedMembership,
        root_key: &VerifyingKey,
        now: u64,
    ) -> Result<(), RecordError> {
        membership.verify(root_key)?;
        membership.certificate.validate_time(now)?;
        self.record.validate_time(now)?;
        if self.record.hive_id != membership.certificate.hive_id
            || self.record.node_id != membership.certificate.node_id
        {
            return Err(RecordError::MembershipMismatch);
        }
        if self.record.expires_at > membership.certificate.expires_at {
            return Err(RecordError::OutlivesMembership);
        }
        let device_key = VerifyingKey::from_bytes(&membership.certificate.device_verifying_key)
            .map_err(|_| RecordError::MembershipMismatch)?;
        self.verify(&device_key)?;
        if self.record.capabilities.contains(Capabilities::INTRODUCER)
            && !membership.certificate.roles.contains(MembershipRoles::INTRODUCER)
        {
            return Err(RecordError::UnauthorizedCapability);
        }
        if self.record.capabilities.contains(Capabilities::CONTROL_RELAY)
            && !membership.certificate.roles.contains(MembershipRoles::CONTROL_RELAY)
        {
            return Err(RecordError::UnauthorizedCapability);
        }
        Ok(())
    }
}

/// A reason an endpoint record was rejected.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RecordError {
    /// The protocol version is not supported.
    #[error("endpoint record protocol version is not supported")]
    UnsupportedVersion,
    /// Sequence zero is reserved and never published.
    #[error("endpoint record sequence must be greater than zero")]
    ZeroSequence,
    /// Expiry did not follow issuance.
    #[error("endpoint record expiry must be later than issuance")]
    InvalidLifetime,
    /// The record's lifetime exceeds the protocol maximum.
    #[error("endpoint record lifetime exceeds seven days")]
    LifetimeTooLong,
    /// The record contained too many candidate endpoints.
    #[error("endpoint record contains too many candidates")]
    TooManyCandidates,
    /// Candidates were not strictly sorted or contained duplicates.
    #[error("endpoint record candidates are not in canonical order")]
    CandidatesNotCanonical,
    /// An undefined capability bit was set.
    #[error("endpoint record contains an unknown critical capability")]
    UnknownCapability,
    /// The record has expired.
    #[error("endpoint record has expired")]
    Expired,
    /// The issue time is beyond the allowed clock skew.
    #[error("endpoint record issue time is too far in the future")]
    IssuedInFuture,
    /// The declared node identifier does not match the verification key.
    #[error("endpoint record signer does not match its node identifier")]
    SignerMismatch,
    /// The signature had the wrong length or failed verification.
    #[error("endpoint record signature is invalid")]
    InvalidSignature,
    /// Canonical encoding failed.
    #[error("endpoint record could not be encoded canonically")]
    Encoding,
    /// Root membership authorization failed.
    #[error("endpoint record membership is invalid")]
    Membership,
    /// Record hive or node does not match the supplied membership.
    #[error("endpoint record does not match its membership")]
    MembershipMismatch,
    /// Endpoint authority cannot extend beyond its membership certificate.
    #[error("endpoint record expires after its membership authorization")]
    OutlivesMembership,
    /// The record advertises a role not granted by membership.
    #[error("endpoint record advertises an unauthorized capability")]
    UnauthorizedCapability,
}

impl From<MembershipError> for RecordError {
    fn from(_: MembershipError) -> Self {
        Self::Membership
    }
}

fn strictly_sorted<T: Ord>(items: &[T]) -> bool {
    items
        .windows(2)
        .all(|pair| matches!(pair, [first, second] if first < second))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{Capabilities, ENDPOINT_RECORD_VERSION, EndpointRecord, RecordError, SignedEndpointRecord};
    use crate::{
        candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
        identity::DeviceIdentity,
        ids::{HiveId, TransportKeyId},
    };

    fn record(identity: &DeviceIdentity) -> Result<EndpointRecord, Box<dyn std::error::Error>> {
        Ok(EndpointRecord {
            protocol_version: ENDPOINT_RECORD_VERSION,
            hive_id: HiveId::from_bytes([1; 32]),
            node_id: identity.node_id(),
            transport_key_id: TransportKeyId::from_public_material(b"transport"),
            generation: 0,
            sequence: 1,
            issued_at: 1_000,
            expires_at: 2_000,
            candidates: vec![EndpointCandidate::new(
                CandidateKind::Direct,
                CandidateTransport::QuicV1,
                SocketAddr::from(([8, 8, 8, 8], 443)),
            )?],
            capabilities: Capabilities::INTRODUCER | Capabilities::CONTROL_RELAY,
        })
    }

    #[test]
    fn sign_and_verify_record() -> Result<(), Box<dyn std::error::Error>> {
        let identity = DeviceIdentity::generate()?;
        let signed = SignedEndpointRecord::sign(record(&identity)?, &identity)?;
        signed.verify(&identity.verifying_key())?;
        Ok(())
    }

    #[test]
    fn signature_rejects_mutation() -> Result<(), Box<dyn std::error::Error>> {
        let identity = DeviceIdentity::generate()?;
        let mut signed = SignedEndpointRecord::sign(record(&identity)?, &identity)?;
        signed.record.sequence = 2;
        assert_eq!(
            signed.verify(&identity.verifying_key()),
            Err(RecordError::InvalidSignature)
        );
        Ok(())
    }
}
