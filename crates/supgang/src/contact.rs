//! Canonical, bounded member contact artifacts shared by files and peers.

use ed25519_dalek::VerifyingKey;
use minicbor::{Decoder, Encoder, decode, encode};
use thiserror::Error;

use crate::{
    membership::{
        MAX_SIGNED_MEMBERSHIP_BYTES, MembershipError, SignedMembership, decode_signed_membership,
        encode_signed_membership,
    },
    record::{RecordError, SignedEndpointRecord},
    wire::{MAX_SIGNED_ENDPOINT_RECORD_BYTES, WireError, decode_signed_endpoint_record, encode_signed_endpoint_record},
};

/// Maximum accepted canonical contact artifact size.
pub const MAX_CONTACT_BYTES: usize = MAX_SIGNED_MEMBERSHIP_BYTES + MAX_SIGNED_ENDPOINT_RECORD_BYTES + 128;

const CONTACT_VERSION: u16 = 1;
const CONTACT_FIELDS: u64 = 3;

/// A root-authorized member and its signed, short-lived endpoint claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerContact {
    /// Root-signed authorization for the device identity.
    pub membership: SignedMembership,
    /// Device-signed current endpoint register value.
    pub endpoint: SignedEndpointRecord,
}

impl PeerContact {
    /// Verifies authority, identity binding, signatures, roles, and freshness.
    ///
    /// # Errors
    ///
    /// Rejects cross-hive, expired, malformed, unauthorized, or invalidly
    /// signed contact information.
    pub fn verify(&self, root_key: &VerifyingKey, now: u64) -> Result<(), ContactError> {
        self.endpoint
            .verify_authorized(&self.membership, root_key, now)
            .map_err(Into::into)
    }

    /// Verifies durable historical content at the time it claimed issuance.
    ///
    /// This is used only while replaying an authenticated cache. Call
    /// [`Self::verify`] again with current time before dialing or sharing it.
    ///
    /// # Errors
    ///
    /// Rejects invalid authority, binding, signatures, roles, and shape.
    pub fn verify_historical(&self, root_key: &VerifyingKey) -> Result<(), ContactError> {
        self.verify(root_key, self.endpoint.record.issued_at)
    }
}

/// A contact encoding or authorization failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContactError {
    /// Contact bytes exceed the fixed protocol budget.
    #[error("peer contact exceeds the protocol size limit")]
    Oversized,
    /// The top-level fixed array had the wrong shape or version.
    #[error("peer contact has an invalid shape or version")]
    InvalidShape,
    /// CBOR encoding failed.
    #[error("peer contact could not be encoded")]
    Encode,
    /// CBOR decoding failed.
    #[error("peer contact is malformed")]
    Decode,
    /// Membership encoding or verification failed.
    #[error("peer contact membership is invalid")]
    Membership,
    /// Endpoint encoding or authorization failed.
    #[error("peer contact endpoint is invalid")]
    Record,
    /// Contact bytes used a non-canonical representation or trailing data.
    #[error("peer contact is not canonically encoded")]
    NonCanonical,
}

impl From<MembershipError> for ContactError {
    fn from(_: MembershipError) -> Self {
        Self::Membership
    }
}

impl From<RecordError> for ContactError {
    fn from(_: RecordError) -> Self {
        Self::Record
    }
}

impl From<WireError> for ContactError {
    fn from(_: WireError) -> Self {
        Self::Record
    }
}

impl From<encode::Error<core::convert::Infallible>> for ContactError {
    fn from(_: encode::Error<core::convert::Infallible>) -> Self {
        Self::Encode
    }
}

impl From<decode::Error> for ContactError {
    fn from(_: decode::Error) -> Self {
        Self::Decode
    }
}

/// Encodes a contact using Supgang's deterministic CBOR profile.
///
/// # Errors
///
/// Returns an error if a nested object is invalid or the result is oversized.
pub fn encode_contact(contact: &PeerContact) -> Result<Vec<u8>, ContactError> {
    let membership = encode_signed_membership(&contact.membership)?;
    let endpoint = encode_signed_endpoint_record(&contact.endpoint)?;
    let mut output = Vec::with_capacity(membership.len().saturating_add(endpoint.len()).saturating_add(32));
    let mut encoder = Encoder::new(&mut output);
    encoder.array(CONTACT_FIELDS)?;
    encoder.u16(CONTACT_VERSION)?;
    encoder.bytes(&membership)?;
    encoder.bytes(&endpoint)?;
    if output.len() > MAX_CONTACT_BYTES {
        return Err(ContactError::Oversized);
    }
    Ok(output)
}

/// Decodes a canonical, bounded contact artifact.
///
/// Cryptographic authorization is intentionally separate in
/// [`PeerContact::verify`] so callers must supply their local root key and time.
///
/// # Errors
///
/// Rejects oversized, malformed, non-canonical, and trailing bytes.
pub fn decode_contact(input: &[u8]) -> Result<PeerContact, ContactError> {
    if input.len() > MAX_CONTACT_BYTES {
        return Err(ContactError::Oversized);
    }
    let mut decoder = Decoder::new(input);
    if decoder.array()? != Some(CONTACT_FIELDS) || decoder.u16()? != CONTACT_VERSION {
        return Err(ContactError::InvalidShape);
    }
    let membership_bytes = decoder.bytes()?;
    if membership_bytes.len() > MAX_SIGNED_MEMBERSHIP_BYTES {
        return Err(ContactError::Oversized);
    }
    let endpoint_bytes = decoder.bytes()?;
    if endpoint_bytes.len() > MAX_SIGNED_ENDPOINT_RECORD_BYTES {
        return Err(ContactError::Oversized);
    }
    if decoder.position() != input.len() {
        return Err(ContactError::NonCanonical);
    }
    let contact = PeerContact {
        membership: decode_signed_membership(membership_bytes)?,
        endpoint: decode_signed_endpoint_record(endpoint_bytes)?,
    };
    if encode_contact(&contact)?.as_slice() != input {
        return Err(ContactError::NonCanonical);
    }
    Ok(contact)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{PeerContact, decode_contact, encode_contact};
    use crate::{
        candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
        identity::{DeviceIdentity, RootIdentity},
        membership::{MEMBERSHIP_VERSION, MembershipCertificate, MembershipRoles, SignedMembership},
        record::{Capabilities, ENDPOINT_RECORD_VERSION, EndpointRecord, SignedEndpointRecord},
    };

    #[test]
    fn canonical_contact_round_trips_and_verifies() -> Result<(), Box<dyn std::error::Error>> {
        let root = RootIdentity::generate()?;
        let device = DeviceIdentity::generate()?;
        let membership = SignedMembership::sign(
            MembershipCertificate {
                version: MEMBERSHIP_VERSION,
                hive_id: root.hive_id(),
                node_id: device.node_id(),
                device_verifying_key: device.verifying_key().to_bytes(),
                serial: 1,
                issued_at: 10,
                expires_at: 1_000,
                roles: MembershipRoles::DEVICE,
                admission_nonce: [1; 32],
            },
            &root,
        )?;
        let endpoint = SignedEndpointRecord::sign(
            EndpointRecord {
                protocol_version: ENDPOINT_RECORD_VERSION,
                hive_id: root.hive_id(),
                node_id: device.node_id(),
                transport_key_id: crate::ids::TransportKeyId::from_public_material(b"transport"),
                generation: 0,
                sequence: 1,
                issued_at: 20,
                expires_at: 100,
                candidates: vec![EndpointCandidate::new(
                    CandidateKind::Local,
                    CandidateTransport::QuicV1,
                    SocketAddr::from(([127, 0, 0, 1], 4_433)),
                )?],
                capabilities: Capabilities::NONE,
            },
            &device,
        )?;
        let contact = PeerContact { membership, endpoint };
        let decoded = decode_contact(&encode_contact(&contact)?)?;
        assert_eq!(decoded, contact);
        decoded.verify(&root.verifying_key(), 50)?;
        Ok(())
    }
}
