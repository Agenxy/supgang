//! Offline, recipient-bound join requests and root-authorized responses.

use ed25519_dalek::VerifyingKey;
use minicbor::{Decoder, Encoder, decode, encode};
use thiserror::Error;

use crate::{
    identity::{RootIdentity, verify_domain},
    membership::{MembershipError, SignedMembership, decode_signed_membership, encode_signed_membership},
    revocation::{RevocationError, SignedRevocationList, decode_signed_revocations, encode_signed_revocations},
    storage::PendingIdentity,
};

/// Maximum encoded join-request size.
pub const MAX_JOIN_REQUEST_BYTES: usize = 512;
/// Maximum encoded root-authorized join bundle size.
pub const MAX_JOIN_BUNDLE_BYTES: usize = 12 * 1024;

const REQUEST_VERSION: u16 = 2;
const BUNDLE_VERSION: u16 = 3;
const REQUEST_DOMAIN: &[u8] = b"supgang/join-request/v2\0";
const BUNDLE_DOMAIN: &[u8] = b"supgang/join-bundle/v3\0";
const REQUEST_FIELDS: u64 = 4;
const BUNDLE_FIELDS: u64 = 7;
const MAX_BUNDLE_LIFETIME_SECONDS: u64 = 60 * 60;

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
    /// UNIX time at which the root assembled this exact response.
    pub issued_at: u64,
    /// Short deadline after which this offline response is no longer accepted.
    pub expires_at: u64,
    /// Root signature binding the recipient and exact revocation snapshot.
    pub signature: Vec<u8>,
}

impl JoinBundle {
    /// Root-signs one short-lived response from already-persisted authority.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent authorization timestamps or encoding failure.
    pub fn new(
        root: &RootIdentity,
        membership: SignedMembership,
        revocations: SignedRevocationList,
        issued_at: u64,
    ) -> Result<Self, InvitationError> {
        let root_verifying_key = root.verifying_key().to_bytes();
        membership.verify(&root.verifying_key())?;
        revocations.verify(&root.verifying_key())?;
        if membership.certificate.issued_at > issued_at || revocations.list.issued_at > issued_at {
            return Err(InvitationError::InvalidBundleLifetime);
        }
        let expires_at = issued_at.saturating_add(MAX_BUNDLE_LIFETIME_SECONDS);
        let payload = bundle_payload(&root_verifying_key, &membership, &revocations, issued_at, expires_at)?;
        Ok(Self {
            root_verifying_key,
            membership,
            revocations,
            issued_at,
            expires_at,
            signature: root.sign_domain(BUNDLE_DOMAIN, &payload).to_vec(),
        })
    }

    /// Verifies root authorization and binding to protected pending state.
    ///
    /// # Errors
    ///
    /// Rejects invalid root keys, signatures, hives, device keys, or nonces.
    pub fn verify_for_pending(&self, pending: &PendingIdentity, now: u64) -> Result<VerifyingKey, InvitationError> {
        let root_key =
            VerifyingKey::from_bytes(&self.root_verifying_key).map_err(|_| InvitationError::InvalidRootKey)?;
        self.membership.verify(&root_key)?;
        self.revocations.verify(&root_key)?;
        if self.expires_at <= self.issued_at
            || self.expires_at.saturating_sub(self.issued_at) > MAX_BUNDLE_LIFETIME_SECONDS
            || self.membership.certificate.issued_at > self.issued_at
            || self.revocations.list.issued_at > self.issued_at
        {
            return Err(InvitationError::InvalidBundleLifetime);
        }
        if self.expires_at < now {
            return Err(InvitationError::ExpiredBundle);
        }
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| InvitationError::InvalidBundleSignature)?;
        let payload = bundle_payload(
            &self.root_verifying_key,
            &self.membership,
            &self.revocations,
            self.issued_at,
            self.expires_at,
        )?;
        if !verify_domain(&root_key, BUNDLE_DOMAIN, &payload, &signature) {
            return Err(InvitationError::InvalidBundleSignature);
        }
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
    encoder.u16(REQUEST_VERSION)?;
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
    if decoder.u16()? != REQUEST_VERSION {
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
    encoder.u16(BUNDLE_VERSION)?;
    encoder.bytes(&bundle.root_verifying_key)?;
    encoder.bytes(&membership)?;
    encoder.bytes(&revocations)?;
    encoder.u64(bundle.issued_at)?;
    encoder.u64(bundle.expires_at)?;
    encoder.bytes(&bundle.signature)?;
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
    if decoder.u16()? != BUNDLE_VERSION {
        return Err(InvitationError::UnsupportedVersion);
    }
    let bundle = JoinBundle {
        root_verifying_key: read_fixed(&mut decoder)?,
        membership: decode_signed_membership(decoder.bytes()?)?,
        revocations: decode_signed_revocations(decoder.bytes()?)?,
        issued_at: decoder.u64()?,
        expires_at: decoder.u64()?,
        signature: decoder.bytes()?.to_vec(),
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
    /// The root did not sign this exact membership and revocation combination.
    #[error("join bundle response signature is invalid")]
    InvalidBundleSignature,
    /// The join response validity window is malformed.
    #[error("join bundle validity window is invalid")]
    InvalidBundleLifetime,
    /// The short-lived join response is no longer current.
    #[error("join bundle has expired; create a fresh response")]
    ExpiredBundle,
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
    payload.extend_from_slice(&REQUEST_VERSION.to_be_bytes());
    payload.extend_from_slice(device_key);
    payload.extend_from_slice(nonce);
    payload
}

fn bundle_payload(
    root_key: &[u8; 32],
    membership: &SignedMembership,
    revocations: &SignedRevocationList,
    issued_at: u64,
    expires_at: u64,
) -> Result<Vec<u8>, InvitationError> {
    let membership = encode_signed_membership(membership)?;
    let revocations = encode_signed_revocations(revocations)?;
    let mut output = Vec::with_capacity(membership.len().saturating_add(revocations.len()).saturating_add(90));
    let mut encoder = Encoder::new(&mut output);
    encoder.array(6)?;
    encoder.u16(BUNDLE_VERSION)?;
    encoder.bytes(root_key)?;
    encoder.bytes(&membership)?;
    encoder.bytes(&revocations)?;
    encoder.u64(issued_at)?;
    encoder.u64(expires_at)?;
    Ok(output)
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
            &root,
            membership,
            SignedRevocationList::empty(&root, 100)?,
            100,
        )?)?)?;
        bundle.verify_for_pending(&pending, 100)?;

        let other = PendingIdentity {
            device: DeviceIdentity::generate()?,
            request_nonce: [9; 32],
        };
        assert!(matches!(
            bundle.verify_for_pending(&other, 100),
            Err(InvitationError::RequestBindingMismatch)
        ));

        let mut substituted = bundle.clone();
        substituted.revocations = crate::revocation::SignedRevocationList::sign(
            crate::revocation::RevocationList {
                version: crate::revocation::REVOCATION_VERSION,
                hive_id: root.hive_id(),
                serial: 1,
                issued_at: 100,
                revoked_nodes: vec![other.device.node_id()],
            },
            &root,
        )?;
        assert!(matches!(
            substituted.verify_for_pending(&pending, 100),
            Err(InvitationError::InvalidBundleSignature)
        ));
        assert!(matches!(
            bundle.verify_for_pending(&pending, bundle.expires_at.saturating_add(1)),
            Err(InvitationError::ExpiredBundle)
        ));
        Ok(())
    }
}
