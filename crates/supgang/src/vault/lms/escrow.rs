//! Offline, age-encrypted NC0 product-root escrow record.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{LmsPublic, identity};
use crate::vault::{VaultError, lms_rfc, validate_name};

const SCHEMA: &str = "supgang.nc0-lms-escrow/v1";
const KNOWN_ANSWER_DOMAIN: &[u8] = b"supgang/nc0-lms-known-answer/v1\0";
const RECORD_FIELDS: u64 = 11;

/// Public result of an offline product-root ceremony.
pub struct EscrowPublic {
    /// RFC 8554 root identity.
    pub identity: LmsPublic,
    /// The known-answer signature's SHA-256, for the owner photo and record.
    pub signature_sha256: String,
    /// First unused q after the known answer consumed q=0.
    pub next_q: u32,
}

/// A live, zeroizing escrow record; keep it in memory only until age encryption.
pub struct EscrowKey {
    record: Zeroizing<Vec<u8>>,
    public: EscrowPublic,
}

impl EscrowKey {
    /// The secret record to encrypt into each independent age file.
    #[must_use]
    pub fn record(&self) -> &[u8] {
        &self.record
    }

    /// Public identity and known-answer receipt.
    #[must_use]
    pub const fn public(&self) -> &EscrowPublic {
        &self.public
    }
}

fn answer_digest(name: &str, public: &[u8; lms_rfc::PUBLIC_LEN]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(KNOWN_ANSWER_DOMAIN);
    hash.update(name.as_bytes());
    hash.update(public);
    hash.finalize().into()
}

fn encode(
    name: &str,
    seed: &[u8; 32],
    id: &[u8; 16],
    public: &[u8; lms_rfc::PUBLIC_LEN],
    signature: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(9_400));
    let mut writer = minicbor::Encoder::new(&mut *bytes);
    writer.array(RECORD_FIELDS).map_err(|_| VaultError::Corrupt)?;
    writer.str(SCHEMA).map_err(|_| VaultError::Corrupt)?;
    writer.u32(lms_rfc::LMS_TYPE).map_err(|_| VaultError::Corrupt)?;
    writer.u32(lms_rfc::OTS_TYPE).map_err(|_| VaultError::Corrupt)?;
    writer.bytes(id).map_err(|_| VaultError::Corrupt)?;
    writer.bytes(seed).map_err(|_| VaultError::Corrupt)?;
    writer.bytes(public).map_err(|_| VaultError::Corrupt)?;
    writer.str(name).map_err(|_| VaultError::Corrupt)?;
    writer.u32(1).map_err(|_| VaultError::Corrupt)?;
    writer.u32(0).map_err(|_| VaultError::Corrupt)?;
    writer.str("known-answer").map_err(|_| VaultError::Corrupt)?;
    writer.bytes(signature).map_err(|_| VaultError::Corrupt)?;
    Ok(bytes)
}

/// Build a fresh H20/W1 root, burn q=0 on a domain-separated known answer, and
/// return only an in-memory record for independent age encryption.
///
/// # Errors
/// Refuses malformed names, entropy failure, treehash failure, or signature failure.
pub fn generate_escrow(name: &str, progress: impl FnMut(u32, u32)) -> Result<EscrowKey, VaultError> {
    validate_name(name)?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    let mut id = Zeroizing::new([0_u8; 16]);
    let mut randomizer = Zeroizing::new([0_u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(std::io::Error::other)?;
    getrandom::fill(id.as_mut()).map_err(std::io::Error::other)?;
    getrandom::fill(randomizer.as_mut()).map_err(std::io::Error::other)?;
    let (root, path) = lms_rfc::tree(&seed, &id, lms_rfc::HEIGHT, lms_rfc::WIDTH, Some(0), progress)?;
    let public = identity(lms_rfc::public_key(&id, &root));
    let digest = answer_digest(name, &public.public_key);
    let signature = Zeroizing::new(lms_rfc::sign_with_path(&seed, &id, 0, &digest, &randomizer, &path)?);
    if !lms_rfc::verify_fixed(&public.public_key, &digest, &signature) {
        return Err(VaultError::Corrupt);
    }
    let receipt = EscrowPublic {
        identity: public,
        signature_sha256: hex::encode(Sha256::digest(signature.as_slice())),
        next_q: 1,
    };
    let record = encode(name, &seed, &id, &receipt.identity.public_key, &signature)?;
    Ok(EscrowKey {
        record,
        public: receipt,
    })
}

/// Validate a decrypted escrow record against the ceremony's expected public
/// receipt, including a fresh streaming treehash of all 1,048,576 leaves.
///
/// # Errors
/// Rejects malformed records, changed names, roots, q states, signatures, and
/// records whose seed and I no longer produce the public root.
pub fn verify_escrow(
    plaintext: &[u8],
    name: &str,
    expected: &EscrowPublic,
    progress: impl FnMut(u32, u32),
) -> Result<(), VaultError> {
    let mut reader = minicbor::Decoder::new(plaintext);
    if reader.array().map_err(|_| VaultError::Corrupt)? != Some(RECORD_FIELDS)
        || reader.str().map_err(|_| VaultError::Corrupt)? != SCHEMA
        || reader.u32().map_err(|_| VaultError::Corrupt)? != lms_rfc::LMS_TYPE
        || reader.u32().map_err(|_| VaultError::Corrupt)? != lms_rfc::OTS_TYPE
    {
        return Err(VaultError::Corrupt);
    }
    let id: Zeroizing<[u8; 16]> = Zeroizing::new(
        reader
            .bytes()
            .map_err(|_| VaultError::Corrupt)?
            .try_into()
            .map_err(|_| VaultError::Corrupt)?,
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        reader
            .bytes()
            .map_err(|_| VaultError::Corrupt)?
            .try_into()
            .map_err(|_| VaultError::Corrupt)?,
    );
    let public: [u8; lms_rfc::PUBLIC_LEN] = reader
        .bytes()
        .map_err(|_| VaultError::Corrupt)?
        .try_into()
        .map_err(|_| VaultError::Corrupt)?;
    if reader.str().map_err(|_| VaultError::Corrupt)? != name
        || reader.u32().map_err(|_| VaultError::Corrupt)? != 1
        || reader.u32().map_err(|_| VaultError::Corrupt)? != 0
        || reader.str().map_err(|_| VaultError::Corrupt)? != "known-answer"
    {
        return Err(VaultError::Corrupt);
    }
    let signature = reader.bytes().map_err(|_| VaultError::Corrupt)?;
    if reader.position() != plaintext.len()
        || public != expected.identity.public_key
        || expected.next_q != 1
        || hex::encode(Sha256::digest(signature)) != expected.signature_sha256
        || !lms_rfc::verify_fixed(&public, &answer_digest(name, &public), signature)
    {
        return Err(VaultError::Corrupt);
    }
    let (root, _) = lms_rfc::tree(&seed, &id, lms_rfc::HEIGHT, lms_rfc::WIDTH, None, progress)?;
    if lms_rfc::public_key(&id, &root) != public {
        return Err(VaultError::Corrupt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{EscrowPublic, encode, verify_escrow};
    use crate::vault::lms::LmsPublic;

    #[test]
    fn injected_public_mismatch_fails_before_treehash() -> Result<(), Box<dyn std::error::Error>> {
        let seed = [3_u8; 32];
        let id = [4_u8; 16];
        let public = [5_u8; 56];
        let record = encode("test-root", &seed, &id, &public, &[0_u8; 9_164])?;
        let mut expected_public = public;
        expected_public[0] ^= 1;
        let expected = EscrowPublic {
            identity: LmsPublic {
                public_key: expected_public,
                fingerprint: String::new(),
            },
            signature_sha256: String::new(),
            next_q: 1,
        };
        assert!(verify_escrow(&record, "test-root", &expected, |_, _| {}).is_err());
        Ok(())
    }
}
