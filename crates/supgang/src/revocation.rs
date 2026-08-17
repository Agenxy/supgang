//! Root-signed, monotonic device revocation snapshots.

use ed25519_dalek::VerifyingKey;
use minicbor::{Decoder, Encoder, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    identity::{RootIdentity, verify_domain},
    ids::{HiveId, NodeId},
};

/// Current root-signed revocation-list version.
pub const REVOCATION_VERSION: u16 = 1;
/// Maximum revoked devices in one personal hive.
pub const MAX_REVOKED_NODES: usize = 256;
/// Maximum canonical signed revocation snapshot size.
pub const MAX_SIGNED_REVOCATION_BYTES: usize = 9 * 1024;

const REVOCATION_DOMAIN: &[u8] = b"supgang/revocation/v1\0";
const LIST_FIELDS: u64 = 5;
const SIGNED_VERSION: u16 = 1;

/// Monotonic root-authorized set of device identities denied hive access.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationList {
    /// Exact schema version.
    pub version: u16,
    /// Self-certifying hive identifier.
    pub hive_id: HiveId,
    /// Root-controlled monotonic snapshot serial, starting at zero.
    pub serial: u64,
    /// UNIX time at which this snapshot was issued.
    pub issued_at: u64,
    /// Sorted, duplicate-free revoked device identities.
    pub revoked_nodes: Vec<NodeId>,
}

impl RevocationList {
    /// Validates bounds, sorting, version, and serial semantics.
    ///
    /// # Errors
    ///
    /// Rejects unsupported versions, oversized or unordered sets, and a serial
    /// inconsistent with whether the set is empty.
    pub fn validate_shape(&self) -> Result<(), RevocationError> {
        if self.version != REVOCATION_VERSION {
            return Err(RevocationError::UnsupportedVersion);
        }
        if self.revoked_nodes.len() > MAX_REVOKED_NODES {
            return Err(RevocationError::Oversized);
        }
        if (self.serial == 0) != self.revoked_nodes.is_empty() {
            return Err(RevocationError::InvalidSerial);
        }
        if !self.revoked_nodes.is_sorted_by(|left, right| left < right) {
            return Err(RevocationError::Unordered);
        }
        Ok(())
    }

    /// Reports whether one stable device identity is revoked.
    #[must_use]
    pub fn contains(&self, node_id: &NodeId) -> bool {
        self.revoked_nodes.binary_search(node_id).is_ok()
    }
}

/// Revocation snapshot plus its hive-root signature.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedRevocationList {
    /// Authorized revocation content.
    pub list: RevocationList,
    /// Domain-separated Ed25519 root signature.
    pub signature: Vec<u8>,
}

impl SignedRevocationList {
    /// Signs a canonical revocation snapshot with the matching hive root.
    ///
    /// # Errors
    ///
    /// Rejects malformed content or another hive's identifier.
    pub fn sign(list: RevocationList, root: &RootIdentity) -> Result<Self, RevocationError> {
        list.validate_shape()?;
        if list.hive_id != root.hive_id() {
            return Err(RevocationError::HiveRootMismatch);
        }
        let payload = encode_list(&list)?;
        Ok(Self {
            list,
            signature: root.sign_domain(REVOCATION_DOMAIN, &payload).to_vec(),
        })
    }

    /// Creates the signed serial-zero snapshot for a new hive.
    ///
    /// # Errors
    ///
    /// Returns signing or canonical-encoding failures.
    pub fn empty(root: &RootIdentity, issued_at: u64) -> Result<Self, RevocationError> {
        Self::sign(
            RevocationList {
                version: REVOCATION_VERSION,
                hive_id: root.hive_id(),
                serial: 0,
                issued_at,
                revoked_nodes: Vec::new(),
            },
            root,
        )
    }

    /// Verifies shape, hive binding, and the root signature.
    ///
    /// # Errors
    ///
    /// Rejects malformed, cross-hive, or incorrectly signed snapshots.
    pub fn verify(&self, root_key: &VerifyingKey) -> Result<(), RevocationError> {
        self.list.validate_shape()?;
        if self.list.hive_id != HiveId::from_root_verifying_key(&root_key.to_bytes()) {
            return Err(RevocationError::HiveRootMismatch);
        }
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| RevocationError::InvalidSignature)?;
        let payload = encode_list(&self.list)?;
        if verify_domain(root_key, REVOCATION_DOMAIN, &payload, &signature) {
            Ok(())
        } else {
            Err(RevocationError::InvalidSignature)
        }
    }

    /// Reports whether one stable device identity is revoked.
    #[must_use]
    pub fn contains(&self, node_id: &NodeId) -> bool {
        self.list.contains(node_id)
    }
}

/// Encodes a canonical signed revocation snapshot.
///
/// # Errors
///
/// Rejects invalid signatures, malformed content, and oversized output.
pub fn encode_signed_revocations(value: &SignedRevocationList) -> Result<Vec<u8>, RevocationError> {
    value.list.validate_shape()?;
    if value.signature.len() != 64 {
        return Err(RevocationError::InvalidSignature);
    }
    let payload = encode_list(&value.list)?;
    let mut output = Vec::with_capacity(payload.len().saturating_add(80));
    let mut encoder = Encoder::new(&mut output);
    encoder.array(3)?;
    encoder.u16(SIGNED_VERSION)?;
    encoder.bytes(&payload)?;
    encoder.bytes(&value.signature)?;
    if output.len() > MAX_SIGNED_REVOCATION_BYTES {
        return Err(RevocationError::Oversized);
    }
    Ok(output)
}

/// Decodes a canonical signed revocation snapshot.
///
/// # Errors
///
/// Rejects malformed, trailing, non-canonical, or oversized input.
pub fn decode_signed_revocations(input: &[u8]) -> Result<SignedRevocationList, RevocationError> {
    if input.is_empty() || input.len() > MAX_SIGNED_REVOCATION_BYTES {
        return Err(RevocationError::Oversized);
    }
    let mut decoder = Decoder::new(input);
    require_array(&mut decoder, 3)?;
    if decoder.u16()? != SIGNED_VERSION {
        return Err(RevocationError::UnsupportedVersion);
    }
    let payload = decoder.bytes()?;
    let signature = decoder.bytes()?;
    if signature.len() != 64 || decoder.position() != input.len() {
        return Err(RevocationError::Malformed);
    }
    let value = SignedRevocationList {
        list: decode_list(payload)?,
        signature: signature.to_vec(),
    };
    if encode_signed_revocations(&value)?.as_slice() != input {
        return Err(RevocationError::NonCanonical);
    }
    Ok(value)
}

/// Revocation construction, canonicalization, or verification failure.
#[derive(Debug, Error)]
pub enum RevocationError {
    /// Exact schema version is unsupported.
    #[error("revocation version is not supported")]
    UnsupportedVersion,
    /// Serial zero and empty-set semantics are inconsistent.
    #[error("revocation serial is inconsistent with its set")]
    InvalidSerial,
    /// Revoked identities are not strictly sorted and unique.
    #[error("revoked identities must be sorted and unique")]
    Unordered,
    /// The snapshot exceeds fixed node or byte limits.
    #[error("revocation snapshot exceeds its fixed limit")]
    Oversized,
    /// The snapshot does not belong to the supplied hive root.
    #[error("revocation hive does not match its root key")]
    HiveRootMismatch,
    /// Root signature is absent or invalid.
    #[error("revocation root signature is invalid")]
    InvalidSignature,
    /// Canonical encoding failed.
    #[error("revocation snapshot could not be encoded")]
    Encode(#[from] encode::Error<core::convert::Infallible>),
    /// CBOR decoding failed.
    #[error("revocation snapshot is malformed")]
    Decode(#[from] decode::Error),
    /// Field count, fixed size, or trailing data is invalid.
    #[error("revocation snapshot has an invalid shape")]
    Malformed,
    /// A semantically valid value used non-canonical bytes.
    #[error("revocation snapshot is not canonically encoded")]
    NonCanonical,
}

fn encode_list(list: &RevocationList) -> Result<Vec<u8>, RevocationError> {
    list.validate_shape()?;
    let mut output = Vec::with_capacity(64 + list.revoked_nodes.len().saturating_mul(34));
    let mut encoder = Encoder::new(&mut output);
    encoder.array(LIST_FIELDS)?;
    encoder.u16(list.version)?;
    encoder.bytes(list.hive_id.as_bytes())?;
    encoder.u64(list.serial)?;
    encoder.u64(list.issued_at)?;
    encoder.array(u64::try_from(list.revoked_nodes.len()).map_err(|_| RevocationError::Oversized)?)?;
    for node_id in &list.revoked_nodes {
        encoder.bytes(node_id.as_bytes())?;
    }
    Ok(output)
}

fn decode_list(input: &[u8]) -> Result<RevocationList, RevocationError> {
    let mut decoder = Decoder::new(input);
    require_array(&mut decoder, LIST_FIELDS)?;
    let version = decoder.u16()?;
    let hive_id = HiveId::from_bytes(read_fixed(&mut decoder)?);
    let serial = decoder.u64()?;
    let issued_at = decoder.u64()?;
    let count = decoder.array()?.ok_or(RevocationError::Malformed)?;
    let count = usize::try_from(count).map_err(|_| RevocationError::Oversized)?;
    if count > MAX_REVOKED_NODES {
        return Err(RevocationError::Oversized);
    }
    let mut revoked_nodes = Vec::with_capacity(count);
    for _ in 0..count {
        revoked_nodes.push(NodeId::from_bytes(read_fixed(&mut decoder)?));
    }
    if decoder.position() != input.len() {
        return Err(RevocationError::Malformed);
    }
    let list = RevocationList {
        version,
        hive_id,
        serial,
        issued_at,
        revoked_nodes,
    };
    list.validate_shape()?;
    if encode_list(&list)?.as_slice() != input {
        return Err(RevocationError::NonCanonical);
    }
    Ok(list)
}

fn require_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), RevocationError> {
    if decoder.array()? == Some(expected) {
        Ok(())
    } else {
        Err(RevocationError::Malformed)
    }
}

fn read_fixed(decoder: &mut Decoder<'_>) -> Result<[u8; 32], RevocationError> {
    decoder.bytes()?.try_into().map_err(|_| RevocationError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::{
        REVOCATION_VERSION, RevocationError, RevocationList, SignedRevocationList, decode_signed_revocations,
        encode_signed_revocations,
    };
    use crate::{identity::RootIdentity, ids::NodeId};

    #[test]
    fn signed_snapshot_round_trips_and_detects_mutation() -> Result<(), Box<dyn std::error::Error>> {
        let root = RootIdentity::generate()?;
        let node = NodeId::from_bytes([7_u8; 32]);
        let signed = SignedRevocationList::sign(
            RevocationList {
                version: REVOCATION_VERSION,
                hive_id: root.hive_id(),
                serial: 1,
                issued_at: 50,
                revoked_nodes: vec![node],
            },
            &root,
        )?;
        let decoded = decode_signed_revocations(&encode_signed_revocations(&signed)?)?;
        decoded.verify(&root.verifying_key())?;
        assert!(decoded.contains(&node));

        let mut changed = decoded;
        changed.list.issued_at = 51;
        assert!(matches!(
            changed.verify(&root.verifying_key()),
            Err(RevocationError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn empty_snapshot_is_serial_zero_only() -> Result<(), Box<dyn std::error::Error>> {
        let root = RootIdentity::generate()?;
        let empty = SignedRevocationList::empty(&root, 10)?;
        empty.verify(&root.verifying_key())?;
        assert_eq!(empty.list.serial, 0);
        assert!(empty.list.revoked_nodes.is_empty());
        Ok(())
    }
}
