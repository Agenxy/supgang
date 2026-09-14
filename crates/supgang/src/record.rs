//! Signed, single-writer endpoint records.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    candidate::{EndpointCandidate, MAX_CANDIDATES},
    identity::{DeviceIdentity, verify_domain},
    ids::{HiveId, NodeId, TransportKeyId},
    membership::{MembershipError, MembershipRoles, SignedMembership},
    profile::PeerName,
    wire,
};

const ENDPOINT_RECORD_SIGNATURE_DOMAIN_V1: &[u8] = b"supgang/endpoint-record/v1\0";
const ENDPOINT_RECORD_SIGNATURE_DOMAIN_V2: &[u8] = b"supgang/endpoint-record/v2\0";
const ENDPOINT_RECORD_SIGNATURE_DOMAIN_V3: &[u8] = b"supgang/endpoint-record/v3\0";
/// First endpoint-record protocol version, retained for verified migration.
pub const ENDPOINT_RECORD_VERSION_V1: u16 = 1;
/// Second endpoint-record protocol version: a device-signed display name.
pub const ENDPOINT_RECORD_VERSION_V2: u16 = 2;
/// Current endpoint-record protocol version: bounded service advertisements.
pub const ENDPOINT_RECORD_VERSION: u16 = 3;
/// Maximum service advertisements one record may carry.
pub const MAX_SERVICE_ADVERTS: usize = 4;
/// Maximum bytes in a service name.
pub const MAX_SERVICE_NAME_BYTES: usize = 16;

/// The name of a locally offered service, as its own software calls it.
///
/// One to sixteen lowercase ASCII letters, digits and hyphens, not starting
/// with a hyphen: a stable key a consumer matches, never text a person is
/// asked to read as an identity.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceName(String);

impl TryFrom<String> for ServiceName {
    type Error = RecordError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ServiceName> for String {
    fn from(name: ServiceName) -> Self {
        name.0
    }
}

impl ServiceName {
    /// Validates a service name.
    ///
    /// # Errors
    ///
    /// Rejects an empty, overlong, or non-portable name.
    pub fn new(value: impl Into<String>) -> Result<Self, RecordError> {
        let value = value.into();
        let bytes = value.as_bytes();
        let portable = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-';
        if bytes.is_empty()
            || bytes.len() > MAX_SERVICE_NAME_BYTES
            || bytes.first() == Some(&b'-')
            || !bytes.iter().all(portable)
        {
            return Err(RecordError::InvalidServiceName);
        }
        Ok(Self(value))
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One service the signing computer offers: its name, the port it listens
/// on at this computer's addresses, and a pin of the TLS key it presents.
///
/// A claim by the device that signed the record, never an observation, and
/// it confers no authorization: a consumer that dials the port and finds the
/// pinned key has exactly the assurance Supgang gives about the computer's
/// own transport. No address is carried; the record's candidates are the
/// addresses, so an advertisement can never point at a third party.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ServiceAdvert {
    /// The service's own name, unique within a record.
    pub name: ServiceName,
    /// The port the service listens on, at the record's candidates.
    pub port: u16,
    /// SHA-256 of the service's TLS public key, as the service states it.
    #[serde(with = "hex_pin")]
    pub key_pin: [u8; 32],
}

impl ServiceAdvert {
    /// Validates one advertisement on its own: the name portable, the port
    /// nonzero. The name is enforced by its type; the port is not, so every
    /// path that admits an advertisement (signing, a stored profile, the
    /// wire) asks this rather than trusting the constructor was used.
    ///
    /// # Errors
    ///
    /// Rejects port zero.
    pub const fn validate(&self) -> Result<(), RecordError> {
        if self.port == 0 {
            return Err(RecordError::InvalidServicePort);
        }
        Ok(())
    }

    /// Builds an advertisement from the operator's words: a name, a port,
    /// and the pin as 64 hexadecimal digits.
    ///
    /// # Errors
    ///
    /// Rejects an invalid name, port zero, or a pin that is not 32 bytes of hex.
    pub fn new(name: impl Into<String>, port: u16, key_pin_hex: &str) -> Result<Self, RecordError> {
        let name = ServiceName::new(name)?;
        if port == 0 {
            return Err(RecordError::InvalidServicePort);
        }
        let key_pin = parse_key_pin(key_pin_hex)?;
        Ok(Self { name, port, key_pin })
    }

    /// Returns the pin as lowercase hexadecimal.
    #[must_use]
    pub fn key_pin_hex(&self) -> String {
        hex::encode(self.key_pin)
    }
}

fn parse_key_pin(text: &str) -> Result<[u8; 32], RecordError> {
    let bytes = hex::decode(text).map_err(|_| RecordError::InvalidKeyPin)?;
    bytes.try_into().map_err(|_| RecordError::InvalidKeyPin)
}

/// Serde helpers that write a key pin as hexadecimal text, the form an
/// operator can compare with what their service prints.
mod hex_pin {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(pin: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        hex::encode(pin).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        super::parse_key_pin(&text).map_err(serde::de::Error::custom)
    }
}
/// Validates a list of advertisements as a record would carry them: each
/// valid on its own, at most `MAX_SERVICE_ADVERTS`, strictly sorted by
/// unique name.
///
/// # Errors
///
/// Returns the first violated invariant.
pub fn validate_services(services: &[ServiceAdvert]) -> Result<(), RecordError> {
    if services.len() > MAX_SERVICE_ADVERTS {
        return Err(RecordError::TooManyServices);
    }
    if !services
        .windows(2)
        .all(|pair| matches!(pair, [first, second] if first.name < second.name))
    {
        return Err(RecordError::ServicesNotCanonical);
    }
    services.iter().try_for_each(ServiceAdvert::validate)
}

/// What a record claims about its computer beyond identity and time: where
/// it is, which roles it holds, and what it runs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EndpointClaims {
    /// Addresses the computer can be reached at.
    pub candidates: Vec<EndpointCandidate>,
    /// Roles the computer offers the hive.
    pub capabilities: Capabilities,
    /// Services the computer runs at those addresses.
    pub services: Vec<ServiceAdvert>,
}

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
    /// Human label signed by the device; never an authorization identifier.
    pub display_name: Option<PeerName>,
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
    /// Bounded, sorted service advertisements; empty before v3.
    pub services: Vec<ServiceAdvert>,
}

impl EndpointRecord {
    /// Validates shape, bounds, ordering, and time-independent semantics.
    ///
    /// # Errors
    ///
    /// Returns the first violated record invariant.
    pub fn validate_shape(&self) -> Result<(), RecordError> {
        if !matches!(
            self.protocol_version,
            ENDPOINT_RECORD_VERSION_V1 | ENDPOINT_RECORD_VERSION_V2 | ENDPOINT_RECORD_VERSION
        ) {
            return Err(RecordError::UnsupportedVersion);
        }
        if (self.protocol_version == ENDPOINT_RECORD_VERSION_V1) != self.display_name.is_none() {
            return Err(RecordError::InvalidDisplayName);
        }
        if self.protocol_version < ENDPOINT_RECORD_VERSION && !self.services.is_empty() {
            return Err(RecordError::ServicesNotSupported);
        }
        validate_services(&self.services)?;
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

    /// Sorts and deduplicates candidate endpoints and service advertisements
    /// before signing. Two advertisements with one name and different content
    /// are left for `validate_shape` to refuse: a record must not silently
    /// drop one of two claims.
    pub fn canonicalize_candidates(&mut self) {
        self.candidates.sort_unstable();
        self.candidates.dedup();
        self.services.sort_unstable();
        self.services.dedup();
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
            .sign_domain(signature_domain(record.protocol_version)?, &payload)
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
        if !verify_domain(
            key,
            signature_domain(self.record.protocol_version)?,
            &payload,
            &signature,
        ) {
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
    /// A service name is empty, overlong, or not lowercase ASCII.
    #[error(
        "service name must be 1 through 16 lowercase ASCII letters, digits, or hyphens, not starting with a hyphen"
    )]
    InvalidServiceName,
    /// A service port was zero.
    #[error("service port must be 1 through 65535")]
    InvalidServicePort,
    /// A key pin was not 32 bytes of hexadecimal.
    #[error("service key pin must be 64 hexadecimal digits: the SHA-256 of the service's TLS public key")]
    InvalidKeyPin,
    /// Service advertisements appeared in a record version that has none.
    #[error("endpoint record version does not carry service advertisements")]
    ServicesNotSupported,
    /// More service advertisements than the protocol allows.
    #[error("endpoint record has too many service advertisements")]
    TooManyServices,
    /// Service advertisements are not strictly sorted by unique name.
    #[error("endpoint record service advertisements are not canonical")]
    ServicesNotCanonical,
    /// The display-name field does not match the record version.
    #[error("endpoint record display name is invalid for this protocol version")]
    InvalidDisplayName,
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

const fn signature_domain(protocol_version: u16) -> Result<&'static [u8], RecordError> {
    match protocol_version {
        ENDPOINT_RECORD_VERSION_V1 => Ok(ENDPOINT_RECORD_SIGNATURE_DOMAIN_V1),
        ENDPOINT_RECORD_VERSION_V2 => Ok(ENDPOINT_RECORD_SIGNATURE_DOMAIN_V2),
        ENDPOINT_RECORD_VERSION => Ok(ENDPOINT_RECORD_SIGNATURE_DOMAIN_V3),
        _ => Err(RecordError::UnsupportedVersion),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{
        Capabilities, ENDPOINT_RECORD_VERSION, EndpointRecord, RecordError, ServiceAdvert, ServiceName,
        SignedEndpointRecord,
    };
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
            display_name: Some(crate::profile::PeerName::new("Test Computer")?),
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
            services: Vec::new(),
        })
    }

    #[test]
    fn sign_and_verify_record() -> Result<(), Box<dyn std::error::Error>> {
        let identity = DeviceIdentity::generate()?;
        let signed = SignedEndpointRecord::sign(record(&identity)?, &identity)?;
        signed.verify(&identity.verifying_key())?;
        Ok(())
    }

    // The rules an advertisement is held to, on every path it can arrive by:
    // a name the type refuses even through serde, port zero refused by
    // validation, two claims under one name refused rather than one dropped,
    // and a version-2 record refusing to carry any.
    #[test]
    fn service_advertisements_are_validated_on_every_path() -> Result<(), Box<dyn std::error::Error>> {
        assert!(
            serde_json::from_str::<ServiceName>("\"Dibs\"").is_err(),
            "an invalid name deserialized"
        );
        assert!(serde_json::from_str::<ServiceName>("\"dibs\"").is_ok());
        assert!(matches!(
            ServiceAdvert::new("dibs", 0, &"ab".repeat(32)),
            Err(RecordError::InvalidServicePort)
        ));
        assert!(matches!(
            ServiceAdvert::new("dibs", 1, "ab"),
            Err(RecordError::InvalidKeyPin)
        ));
        let identity = DeviceIdentity::generate()?;
        let mut record = record(&identity)?;
        record.services = vec![ServiceAdvert::new("dibs", 4_777, &"ab".repeat(32))?];
        if let Some(first) = record.services.first_mut() {
            first.port = 0;
        }
        assert_eq!(record.validate_shape(), Err(RecordError::InvalidServicePort));
        record.services = vec![
            ServiceAdvert::new("dibs", 4_777, &"ab".repeat(32))?,
            ServiceAdvert::new("dibs", 4_790, &"ab".repeat(32))?,
        ];
        assert_eq!(
            SignedEndpointRecord::sign(record.clone(), &identity).map(|_| ()),
            Err(RecordError::ServicesNotCanonical),
            "two claims under one name must not become one"
        );
        record.services = vec![ServiceAdvert::new("dibs", 4_777, &"ab".repeat(32))?];
        record.protocol_version = super::ENDPOINT_RECORD_VERSION_V2;
        assert_eq!(record.validate_shape(), Err(RecordError::ServicesNotSupported));
        record.protocol_version = ENDPOINT_RECORD_VERSION;
        SignedEndpointRecord::sign(record, &identity)?.verify(&identity.verifying_key())?;
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
