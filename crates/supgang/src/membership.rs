//! Root-authorized, bounded hive membership certificates.

use ed25519_dalek::VerifyingKey;
use minicbor::{Decoder, Encoder, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    identity::{RootIdentity, verify_domain},
    ids::{HiveId, NodeId},
};

/// Current membership certificate version.
pub const MEMBERSHIP_VERSION: u16 = 1;
/// Maximum encoded signed membership envelope.
pub const MAX_SIGNED_MEMBERSHIP_BYTES: usize = 1_024;
/// Maximum membership validity window, in seconds.
pub const MAX_MEMBERSHIP_LIFETIME_SECONDS: u64 = 10 * 366 * 24 * 60 * 60;

const MEMBERSHIP_DOMAIN: &[u8] = b"supgang/membership/v1\0";
const CERTIFICATE_FIELDS: u64 = 9;
const SIGNED_ENVELOPE_VERSION: u16 = 1;

/// Roles granted to one hive member.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MembershipRoles(u64);

impl MembershipRoles {
    /// Ordinary device participation.
    pub const DEVICE: Self = Self(1 << 0);
    /// Ability to help authenticated members exchange candidates.
    pub const INTRODUCER: Self = Self(1 << 1);
    /// Ability to forward bounded control frames.
    pub const CONTROL_RELAY: Self = Self(1 << 2);
    const KNOWN_BITS: u64 = Self::DEVICE.0 | Self::INTRODUCER.0 | Self::CONTROL_RELAY.0;

    /// Constructs a role set while rejecting unknown critical bits.
    ///
    /// # Errors
    ///
    /// Returns an error for a bit undefined by this protocol version.
    pub const fn from_bits(bits: u64) -> Result<Self, MembershipError> {
        if bits & !Self::KNOWN_BITS == 0 {
            Ok(Self(bits))
        } else {
            Err(MembershipError::UnknownRole)
        }
    }

    /// Returns the wire bitset.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns whether every requested role is granted.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for MembershipRoles {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Root-signed authorization for one stable device identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MembershipCertificate {
    /// Exact certificate version.
    pub version: u16,
    /// Self-certifying hive identifier.
    pub hive_id: HiveId,
    /// Stable device identifier derived from `device_verifying_key`.
    pub node_id: NodeId,
    /// Ed25519 device verification key.
    pub device_verifying_key: [u8; 32],
    /// Root-controlled monotonic issuance serial.
    pub serial: u64,
    /// UNIX issue timestamp.
    pub issued_at: u64,
    /// UNIX expiry timestamp.
    pub expires_at: u64,
    /// Capabilities granted to the device.
    pub roles: MembershipRoles,
    /// Nonce binding this authorization to one signed offline join request.
    pub admission_nonce: [u8; 32],
}

impl MembershipCertificate {
    /// Validates certificate structure independently from the root signature.
    ///
    /// # Errors
    ///
    /// Rejects unsupported versions, identity mismatches, invalid validity
    /// ranges, empty roles, unknown roles, and serial zero.
    pub fn validate_shape(&self) -> Result<(), MembershipError> {
        if self.version != MEMBERSHIP_VERSION {
            return Err(MembershipError::UnsupportedVersion);
        }
        if self.serial == 0 {
            return Err(MembershipError::ZeroSerial);
        }
        if self.node_id.as_bytes().as_slice()
            != NodeId::from_verifying_key(&self.device_verifying_key)
                .as_bytes()
                .as_slice()
        {
            return Err(MembershipError::NodeKeyMismatch);
        }
        if self.expires_at <= self.issued_at {
            return Err(MembershipError::InvalidLifetime);
        }
        if self.expires_at.saturating_sub(self.issued_at) > MAX_MEMBERSHIP_LIFETIME_SECONDS {
            return Err(MembershipError::LifetimeTooLong);
        }
        if self.roles.bits() == 0 || !self.roles.contains(MembershipRoles::DEVICE) {
            return Err(MembershipError::MissingDeviceRole);
        }
        MembershipRoles::from_bits(self.roles.bits())?;
        Ok(())
    }

    /// Validates expiry against a trusted local wall clock.
    ///
    /// # Errors
    ///
    /// Rejects an expired membership.
    pub const fn validate_time(&self, now: u64) -> Result<(), MembershipError> {
        if self.expires_at < now {
            Err(MembershipError::Expired)
        } else {
            Ok(())
        }
    }
}

/// A membership certificate and its hive-root signature.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedMembership {
    /// Authorized membership content.
    pub certificate: MembershipCertificate,
    /// Domain-separated Ed25519 signature.
    pub signature: Vec<u8>,
}

impl SignedMembership {
    /// Signs a certificate with the matching hive root.
    ///
    /// # Errors
    ///
    /// Rejects malformed content or a certificate for another hive.
    pub fn sign(certificate: MembershipCertificate, root: &RootIdentity) -> Result<Self, MembershipError> {
        certificate.validate_shape()?;
        if certificate.hive_id != root.hive_id() {
            return Err(MembershipError::HiveRootMismatch);
        }
        let payload = encode_certificate(&certificate)?;
        let signature = root.sign_domain(MEMBERSHIP_DOMAIN, &payload).to_vec();
        Ok(Self { certificate, signature })
    }

    /// Verifies content, self-certifying hive identity, and root signature.
    ///
    /// # Errors
    ///
    /// Rejects malformed, cross-hive, or incorrectly signed memberships.
    pub fn verify(&self, root_key: &VerifyingKey) -> Result<(), MembershipError> {
        self.certificate.validate_shape()?;
        if self.certificate.hive_id != HiveId::from_root_verifying_key(&root_key.to_bytes()) {
            return Err(MembershipError::HiveRootMismatch);
        }
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| MembershipError::InvalidSignature)?;
        let payload = encode_certificate(&self.certificate)?;
        if !verify_domain(root_key, MEMBERSHIP_DOMAIN, &payload, &signature) {
            return Err(MembershipError::InvalidSignature);
        }
        Ok(())
    }
}

/// Encodes a signed membership in the canonical bounded wire profile.
///
/// # Errors
///
/// Rejects an invalid signature size or an oversized encoding.
pub fn encode_signed_membership(signed: &SignedMembership) -> Result<Vec<u8>, MembershipError> {
    if signed.signature.len() != 64 {
        return Err(MembershipError::InvalidSignature);
    }
    let payload = encode_certificate(&signed.certificate)?;
    let mut output = Vec::with_capacity(payload.len().saturating_add(80));
    let mut encoder = Encoder::new(&mut output);
    encoder.array(3)?;
    encoder.u16(SIGNED_ENVELOPE_VERSION)?;
    encoder.bytes(&payload)?;
    encoder.bytes(&signed.signature)?;
    if output.len() > MAX_SIGNED_MEMBERSHIP_BYTES {
        return Err(MembershipError::Oversized);
    }
    Ok(output)
}

/// Decodes a signed membership and requires canonical input bytes.
///
/// # Errors
///
/// Rejects malformed, trailing, non-canonical, or oversized input.
pub fn decode_signed_membership(input: &[u8]) -> Result<SignedMembership, MembershipError> {
    if input.len() > MAX_SIGNED_MEMBERSHIP_BYTES {
        return Err(MembershipError::Oversized);
    }
    let mut decoder = Decoder::new(input);
    require_array(&mut decoder, 3)?;
    if decoder.u16()? != SIGNED_ENVELOPE_VERSION {
        return Err(MembershipError::UnsupportedVersion);
    }
    let payload = decoder.bytes()?;
    let signature = decoder.bytes()?;
    if signature.len() != 64 || decoder.position() != input.len() {
        return Err(MembershipError::Malformed);
    }
    let signed = SignedMembership {
        certificate: decode_certificate(payload)?,
        signature: signature.to_vec(),
    };
    if encode_signed_membership(&signed)?.as_slice() != input {
        return Err(MembershipError::NonCanonical);
    }
    Ok(signed)
}

/// A membership construction or validation failure.
#[derive(Debug, Error)]
pub enum MembershipError {
    /// The version is not supported.
    #[error("membership version is not supported")]
    UnsupportedVersion,
    /// The serial is reserved.
    #[error("membership serial must be greater than zero")]
    ZeroSerial,
    /// The device key does not derive the declared node identity.
    #[error("membership node identifier does not match its device key")]
    NodeKeyMismatch,
    /// Expiry does not follow issuance.
    #[error("membership expiry must follow issuance")]
    InvalidLifetime,
    /// The validity window exceeds the protocol maximum.
    #[error("membership lifetime exceeds ten years")]
    LifetimeTooLong,
    /// The certificate does not grant ordinary device participation.
    #[error("membership must grant the device role")]
    MissingDeviceRole,
    /// An undefined role bit is present.
    #[error("membership contains an unknown critical role")]
    UnknownRole,
    /// The membership is expired.
    #[error("membership is expired")]
    Expired,
    /// The certificate does not belong to the supplied root.
    #[error("membership hive does not match its root key")]
    HiveRootMismatch,
    /// The root signature is invalid.
    #[error("membership signature is invalid")]
    InvalidSignature,
    /// The input exceeds its fixed budget.
    #[error("membership message exceeds its size limit")]
    Oversized,
    /// CBOR encoding failed.
    #[error("membership could not be encoded")]
    Encode(#[from] encode::Error<std::convert::Infallible>),
    /// CBOR decoding failed.
    #[error("membership message is malformed")]
    Decode(#[from] decode::Error),
    /// The top-level shape, field count, signature, or trailing data is invalid.
    #[error("membership message has an invalid shape")]
    Malformed,
    /// A valid value used a non-canonical representation.
    #[error("membership message is not canonically encoded")]
    NonCanonical,
}

fn encode_certificate(certificate: &MembershipCertificate) -> Result<Vec<u8>, MembershipError> {
    let mut output = Vec::with_capacity(192);
    let mut encoder = Encoder::new(&mut output);
    encoder.array(CERTIFICATE_FIELDS)?;
    encoder.u16(certificate.version)?;
    encoder.bytes(certificate.hive_id.as_bytes())?;
    encoder.bytes(certificate.node_id.as_bytes())?;
    encoder.bytes(&certificate.device_verifying_key)?;
    encoder.u64(certificate.serial)?;
    encoder.u64(certificate.issued_at)?;
    encoder.u64(certificate.expires_at)?;
    encoder.u64(certificate.roles.bits())?;
    encoder.bytes(&certificate.admission_nonce)?;
    Ok(output)
}

fn decode_certificate(input: &[u8]) -> Result<MembershipCertificate, MembershipError> {
    let mut decoder = Decoder::new(input);
    require_array(&mut decoder, CERTIFICATE_FIELDS)?;
    let version = decoder.u16()?;
    let hive_id = HiveId::from_bytes(read_fixed(&mut decoder)?);
    let node_id = NodeId::from_bytes(read_fixed(&mut decoder)?);
    let device_verifying_key = read_fixed(&mut decoder)?;
    let serial = decoder.u64()?;
    let issued_at = decoder.u64()?;
    let expires_at = decoder.u64()?;
    let roles = MembershipRoles::from_bits(decoder.u64()?)?;
    let admission_nonce = read_fixed(&mut decoder)?;
    if decoder.position() != input.len() {
        return Err(MembershipError::Malformed);
    }
    let certificate = MembershipCertificate {
        version,
        hive_id,
        node_id,
        device_verifying_key,
        serial,
        issued_at,
        expires_at,
        roles,
        admission_nonce,
    };
    certificate.validate_shape()?;
    if encode_certificate(&certificate)?.as_slice() != input {
        return Err(MembershipError::NonCanonical);
    }
    Ok(certificate)
}

fn require_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), MembershipError> {
    if decoder.array()? == Some(expected) {
        Ok(())
    } else {
        Err(MembershipError::Malformed)
    }
}

fn read_fixed(decoder: &mut Decoder<'_>) -> Result<[u8; 32], MembershipError> {
    decoder.bytes()?.try_into().map_err(|_| MembershipError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::{
        MEMBERSHIP_VERSION, MembershipCertificate, MembershipError, MembershipRoles, SignedMembership,
        decode_signed_membership, encode_signed_membership,
    };
    use crate::identity::{DeviceIdentity, RootIdentity};

    fn membership(root: &RootIdentity, device: &DeviceIdentity) -> MembershipCertificate {
        MembershipCertificate {
            version: MEMBERSHIP_VERSION,
            hive_id: root.hive_id(),
            node_id: device.node_id(),
            device_verifying_key: device.verifying_key().to_bytes(),
            serial: 1,
            issued_at: 100,
            expires_at: 200,
            roles: MembershipRoles::DEVICE,
            admission_nonce: [0; 32],
        }
    }

    #[test]
    fn signed_membership_round_trips_and_verifies() -> Result<(), Box<dyn std::error::Error>> {
        let root = RootIdentity::generate()?;
        let device = DeviceIdentity::generate()?;
        let signed = SignedMembership::sign(membership(&root, &device), &root)?;
        let bytes = encode_signed_membership(&signed)?;
        let decoded = decode_signed_membership(&bytes)?;
        decoded.verify(&root.verifying_key())?;
        Ok(())
    }

    #[test]
    fn cross_hive_replay_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let root = RootIdentity::generate()?;
        let other_root = RootIdentity::generate()?;
        let device = DeviceIdentity::generate()?;
        let signed = SignedMembership::sign(membership(&root, &device), &root)?;
        assert!(matches!(
            signed.verify(&other_root.verifying_key()),
            Err(MembershipError::HiveRootMismatch)
        ));
        Ok(())
    }
}
