//! Offline, recipient-bound join requests and root-authorized responses.

use ed25519_dalek::VerifyingKey;
use minicbor::{Decoder, Encoder, decode, encode};
use thiserror::Error;

use crate::{
    identity::verify_domain,
    membership::{MembershipError, SignedMembership, decode_signed_membership, encode_signed_membership},
    revocation::{RevocationError, SignedRevocationList, decode_signed_revocations, encode_signed_revocations},
    storage::PendingIdentity,
};

/// Maximum encoded join-request size.
pub const MAX_JOIN_REQUEST_BYTES: usize = 512;
/// Maximum encoded root-authorized join bundle size.
pub const MAX_JOIN_BUNDLE_BYTES: usize = 12 * 1024;

const JOIN_VERSION: u16 = 2;
const REQUEST_DOMAIN: &[u8] = b"supgang/join-request/v2\0";
const REQUEST_FIELDS: u64 = 4;
const BUNDLE_FIELDS: u64 = 4;

/// A device-generated, proof-of-possession request for hive admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinRequest {
    /// Device verification key generated on the joining computer.
    pub device_verifying_key: [u8; 32],
    /// High-entropy admission nonce generated on the joining computer.
    pub nonce: [u8; 32],
    /// Device signature over the versioned request content.
    pub signature: [u8; 64],
}

impl JoinRequest {
    /// Creates a request proving possession of the protected pending key.
    #[must_use]
    pub fn create(pending: &PendingIdentity) -> Self {
        let device_verifying_key = pending.device.verifying_key().to_bytes();
        let payload = request_payload(&device_verifying_key, &pending.request_nonce);
        let signature = pending.device.sign_domain(REQUEST_DOMAIN, &payload);
        Self {
            device_verifying_key,
            nonce: pending.request_nonce,
            signature,
        }
    }

    /// Verifies the canonical proof of possession.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Ed25519 key or signature.
    pub fn verify(&self) -> Result<VerifyingKey, InvitationError> {
        let key =
            VerifyingKey::from_bytes(&self.device_verifying_key).map_err(|_| InvitationError::InvalidDeviceKey)?;
        let payload = request_payload(&self.device_verifying_key, &self.nonce);
        if verify_domain(&key, REQUEST_DOMAIN, &payload, &self.signature) {
            Ok(key)
        } else {
            Err(InvitationError::InvalidRequestSignature)
        }
    }
}

/// A root key and membership authorization returned to the joining computer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinBundle {
    /// Hive root verification key establishing the self-certifying hive ID.
    pub root_verifying_key: [u8; 32],
    /// Root-signed authorization bound to the original request nonce and key.
    pub membership: SignedMembership,
    /// Current root-signed revocation snapshot.
    pub revocations: SignedRevocationList,
}

impl JoinBundle {
    /// Creates a transport bundle from an already-persisted membership.
    #[must_use]
    pub fn new(
        root_verifying_key: &VerifyingKey,
        membership: SignedMembership,
        revocations: SignedRevocationList,
    ) -> Self {
        Self {
            root_verifying_key: root_verifying_key.to_bytes(),
            membership,
            revocations,
        }
    }

    /// Verifies root authorization and binding to protected pending state.
    ///
    /// # Errors
    ///
    /// Rejects invalid root keys, signatures, hives, device keys, or nonces.
    pub fn verify_for_pending(&self, pending: &PendingIdentity) -> Result<VerifyingKey, InvitationError> {
        let root_key =
            VerifyingKey::from_bytes(&self.root_verifying_key).map_err(|_| InvitationError::InvalidRootKey)?;
        self.membership.verify(&root_key)?;
        self.revocations.verify(&root_key)?;
        if self.membership.certificate.device_verifying_key != pending.device.verifying_key().to_bytes()
            || self.membership.certificate.admission_nonce != pending.request_nonce
            || self.revocations.contains(&self.membership.certificate.node_id)
        {
            return Err(InvitationError::RequestBindingMismatch);
        }
        Ok(root_key)
    }
}

/// Encodes a join request in the canonical bounded wire profile.
///
/// # Errors
///
/// Returns an encoding or fixed-budget failure.
pub fn encode_join_request(request: &JoinRequest) -> Result<Vec<u8>, InvitationError> {
    let mut output = Vec::with_capacity(144);
    let mut encoder = Encoder::new(&mut output);
    encoder.array(REQUEST_FIELDS)?;
    encoder.u16(JOIN_VERSION)?;
    encoder.bytes(&request.device_verifying_key)?;
    encoder.bytes(&request.nonce)?;
    encoder.bytes(&request.signature)?;
    if output.len() > MAX_JOIN_REQUEST_BYTES {
        return Err(InvitationError::Oversized);
    }
    Ok(output)
}

/// Decodes, canonicalizes, and verifies a join request.
///
/// # Errors
///
/// Rejects malformed, trailing, non-canonical, oversized, or unsigned input.
pub fn decode_join_request(input: &[u8]) -> Result<JoinRequest, InvitationError> {
    if input.len() > MAX_JOIN_REQUEST_BYTES {
        return Err(InvitationError::Oversized);
    }
    let mut decoder = Decoder::new(input);
    require_array(&mut decoder, REQUEST_FIELDS)?;
    if decoder.u16()? != JOIN_VERSION {
        return Err(InvitationError::UnsupportedVersion);
    }
    let request = JoinRequest {
        device_verifying_key: read_fixed(&mut decoder)?,
        nonce: read_fixed(&mut decoder)?,
        signature: read_signature(&mut decoder)?,
    };
    ensure_finished(&decoder, input)?;
    if encode_join_request(&request)?.as_slice() != input {
        return Err(InvitationError::NonCanonical);
    }
    request.verify()?;
    Ok(request)
}

/// Encodes a root-authorized join bundle.
///
/// # Errors
///
/// Returns an encoding, membership, or fixed-budget failure.
pub fn encode_join_bundle(bundle: &JoinBundle) -> Result<Vec<u8>, InvitationError> {
    let membership = encode_signed_membership(&bundle.membership)?;
    let revocations = encode_signed_revocations(&bundle.revocations)?;
    let mut output = Vec::with_capacity(membership.len().saturating_add(revocations.len()).saturating_add(48));
    let mut encoder = Encoder::new(&mut output);
    encoder.array(BUNDLE_FIELDS)?;
    encoder.u16(JOIN_VERSION)?;
    encoder.bytes(&bundle.root_verifying_key)?;
    encoder.bytes(&membership)?;
    encoder.bytes(&revocations)?;
    if output.len() > MAX_JOIN_BUNDLE_BYTES {
        return Err(InvitationError::Oversized);
    }
    Ok(output)
}

/// Decodes a canonical root-authorized join bundle.
///
/// # Errors
///
/// Rejects malformed, trailing, non-canonical, or oversized input. Binding to
/// local pending state is verified separately by `JoinBundle::verify_for_pending`.
pub fn decode_join_bundle(input: &[u8]) -> Result<JoinBundle, InvitationError> {
    if input.len() > MAX_JOIN_BUNDLE_BYTES {
        return Err(InvitationError::Oversized);
    }
    let mut decoder = Decoder::new(input);
    require_array(&mut decoder, BUNDLE_FIELDS)?;
    if decoder.u16()? != JOIN_VERSION {
        return Err(InvitationError::UnsupportedVersion);
    }
    let bundle = JoinBundle {
        root_verifying_key: read_fixed(&mut decoder)?,
        membership: decode_signed_membership(decoder.bytes()?)?,
        revocations: decode_signed_revocations(decoder.bytes()?)?,
    };
    ensure_finished(&decoder, input)?;
    if encode_join_bundle(&bundle)?.as_slice() != input {
        return Err(InvitationError::NonCanonical);
    }
    Ok(bundle)
}

/// A join artifact construction or verification failure.
#[derive(Debug, Error)]
pub enum InvitationError {
    /// The join protocol version is unsupported.
    #[error("join artifact version is not supported")]
    UnsupportedVersion,
    /// The message exceeds its fixed budget.
    #[error("join artifact exceeds its size limit")]
    Oversized,
    /// The device verification key is invalid.
    #[error("join request contains an invalid device key")]
    InvalidDeviceKey,
    /// The request signature does not prove device-key possession.
    #[error("join request signature is invalid")]
    InvalidRequestSignature,
    /// The root verification key is invalid.
    #[error("join bundle contains an invalid hive root key")]
    InvalidRootKey,
    /// The response is not for this computer's pending key and nonce.
    #[error("join bundle does not match this computer's pending request")]
    RequestBindingMismatch,
    /// Root membership authorization failed.
    #[error("join membership authorization is invalid")]
    Membership(#[from] MembershipError),
    /// Root revocation authorization failed.
    #[error("join revocation snapshot is invalid")]
    Revocation(#[from] RevocationError),
    /// CBOR encoding failed.
    #[error("join artifact could not be encoded")]
    Encode(#[from] encode::Error<std::convert::Infallible>),
    /// CBOR decoding failed.
    #[error("join artifact is malformed")]
    Decode(#[from] decode::Error),
    /// The top-level shape, fixed field length, or trailing data is invalid.
    #[error("join artifact has an invalid shape")]
    InvalidShape,
    /// A valid value used non-canonical bytes.
    #[error("join artifact is not canonically encoded")]
    NonCanonical,
}

fn request_payload(device_key: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(66);
    payload.extend_from_slice(&JOIN_VERSION.to_be_bytes());
    payload.extend_from_slice(device_key);
    payload.extend_from_slice(nonce);
    payload
}

fn require_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), InvitationError> {
    if decoder.array()? == Some(expected) {
        Ok(())
    } else {
        Err(InvitationError::InvalidShape)
    }
}

fn read_fixed(decoder: &mut Decoder<'_>) -> Result<[u8; 32], InvitationError> {
    decoder.bytes()?.try_into().map_err(|_| InvitationError::InvalidShape)
}

fn read_signature(decoder: &mut Decoder<'_>) -> Result<[u8; 64], InvitationError> {
    decoder.bytes()?.try_into().map_err(|_| InvitationError::InvalidShape)
}

fn ensure_finished(decoder: &Decoder<'_>, input: &[u8]) -> Result<(), InvitationError> {
    if decoder.position() == input.len() {
        Ok(())
    } else {
        Err(InvitationError::InvalidShape)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InvitationError, JoinBundle, JoinRequest, decode_join_bundle, decode_join_request, encode_join_bundle,
        encode_join_request,
    };
    use crate::{
        identity::{DeviceIdentity, RootIdentity},
        membership::{MEMBERSHIP_VERSION, MembershipCertificate, MembershipRoles, SignedMembership},
        revocation::SignedRevocationList,
        storage::PendingIdentity,
    };

    #[test]
    fn artifacts_round_trip_and_bind_to_recipient() -> Result<(), Box<dyn std::error::Error>> {
        let root = RootIdentity::generate()?;
        let pending = PendingIdentity {
            device: DeviceIdentity::generate()?,
            request_nonce: [9; 32],
        };
        let request = decode_join_request(&encode_join_request(&JoinRequest::create(&pending))?)?;
        let membership = SignedMembership::sign(
            MembershipCertificate {
                version: MEMBERSHIP_VERSION,
                hive_id: root.hive_id(),
                node_id: pending.device.node_id(),
                device_verifying_key: request.device_verifying_key,
                serial: 2,
                issued_at: 100,
                expires_at: 200,
                roles: MembershipRoles::DEVICE,
                admission_nonce: request.nonce,
            },
            &root,
        )?;
        let bundle = decode_join_bundle(&encode_join_bundle(&JoinBundle::new(
            &root.verifying_key(),
            membership,
            SignedRevocationList::empty(&root, 100)?,
        ))?)?;
        bundle.verify_for_pending(&pending)?;

        let other = PendingIdentity {
            device: DeviceIdentity::generate()?,
            request_nonce: [9; 32],
        };
        assert!(matches!(
            bundle.verify_for_pending(&other),
            Err(InvitationError::RequestBindingMismatch)
        ));
        Ok(())
    }
}
