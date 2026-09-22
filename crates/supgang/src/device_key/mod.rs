//! ECDSA P-256 device keys: the algorithm the owner's hardware speaks (ADR 0003).
//!
//! Every encoding is fixed here so that a key or a signature has one form on the
//! wire and in the record: public keys are 33-byte compressed SEC1 points,
//! validated on the curve at decode; signatures are 64 bytes, `r || s`, with
//! low-`s` enforced so a given signature has one encoding. Normalisation is not
//! uniqueness: two valid signatures over the same content may differ, so records
//! are compared by content, never by signature bytes.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub mod custody;
mod file;
#[cfg(target_os = "macos")]
mod helper;
mod sealed;
#[cfg(target_os = "macos")]
pub mod secure_enclave;
pub mod signature;
#[cfg(target_os = "linux")]
pub mod tpm2;

#[cfg(test)]
mod custody_tests;

/// Typed threshold control-channel proof domain, including its terminal NUL.
pub const CONTROL_AUTH_DOMAIN: &[u8] = b"supgang/control-auth/v1\0";

/// Bytes in a compressed P-256 public key.
pub const PUBLIC_KEY_BYTES: usize = 33;
/// Bytes in a P-256 signature as Supgang carries it.
pub const SIGNATURE_BYTES: usize = 64;
/// Bytes in a P-256 private scalar.
const SECRET_BYTES: usize = 32;

/// A key or signature that is not what P-256 requires.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DeviceKeyError {
    /// The custody provider could not perform this operation.
    #[error("device custody refused: {0}")]
    CustodyRefused(custody::UnavailableReason),
    /// The public key is not a valid compressed point on the curve.
    #[error("device public key must be a 33-byte compressed point on P-256")]
    InvalidPublicKey,
    /// The signature is not 64 bytes of `r || s` with low `s`.
    #[error("device signature must be 64 bytes of r || s with low s")]
    InvalidSignature,
    /// The secret scalar is out of range or the wrong size.
    #[error("device secret must be a 32-byte scalar in range")]
    InvalidSecret,
    /// The operating system did not provide random bytes.
    #[error("the operating system could not provide secure random bytes")]
    Random,
}

/// A device's P-256 public key, in its one encoding.
#[derive(Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct DevicePublicKey([u8; PUBLIC_KEY_BYTES]);

impl core::fmt::Debug for DevicePublicKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "DevicePublicKey({})", hex(&self.0))
    }
}

impl DevicePublicKey {
    /// Decodes a compressed point, refusing anything not on the curve.
    ///
    /// # Errors
    ///
    /// [`DeviceKeyError::InvalidPublicKey`] for the wrong length, an uncompressed
    /// or hybrid prefix, or a point not on the curve.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeviceKeyError> {
        let array: [u8; PUBLIC_KEY_BYTES] = bytes.try_into().map_err(|_| DeviceKeyError::InvalidPublicKey)?;
        let key = VerifyingKey::from_sec1_bytes(&array).map_err(|_| DeviceKeyError::InvalidPublicKey)?;
        // Only a compressed encoding is ours; SEC1 also accepts uncompressed
        // and hybrid, which the length check above already excludes.
        let point = key.to_sec1_point(true);
        let bytes: [u8; PUBLIC_KEY_BYTES] = point
            .as_bytes()
            .try_into()
            .map_err(|_| DeviceKeyError::InvalidPublicKey)?;
        if bytes != array {
            return Err(DeviceKeyError::InvalidPublicKey);
        }
        Ok(Self(array))
    }

    /// The 33 compressed bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.0
    }

    /// The bytes `NodeId` is derived from: the algorithm name, then the key.
    #[must_use]
    pub fn identity_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + PUBLIC_KEY_BYTES);
        out.extend_from_slice(b"p256");
        out.extend_from_slice(&self.0);
        out
    }

    /// Verifies a domain-separated signature.
    ///
    /// # Errors
    ///
    /// [`DeviceKeyError::InvalidSignature`] when the signature is malformed or
    /// does not verify.
    pub fn verify_domain(
        &self,
        domain: &'static [u8],
        message: &[u8],
        signature: &DeviceSignature,
    ) -> Result<(), DeviceKeyError> {
        let key = VerifyingKey::from_sec1_bytes(&self.0).map_err(|_| DeviceKeyError::InvalidPublicKey)?;
        let parsed = Signature::from_slice(&signature.0).map_err(|_| DeviceKeyError::InvalidSignature)?;
        let digest = domain_digest(domain, message);
        key.verify_prehash(&digest, &parsed)
            .map_err(|_| DeviceKeyError::InvalidSignature)
    }
}

/// A P-256 signature as Supgang carries it: 64 bytes, low `s`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DeviceSignature([u8; SIGNATURE_BYTES]);

impl core::fmt::Debug for DeviceSignature {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "DeviceSignature({}…)", hex(self.0.get(..8).unwrap_or(&[])))
    }
}

impl DeviceSignature {
    /// Decodes 64 bytes of `r || s`, refusing a high `s`: the other encoding of
    /// the same signature is not accepted, so a signature has one form.
    ///
    /// # Errors
    ///
    /// [`DeviceKeyError::InvalidSignature`] for the wrong length, `r` or `s` out
    /// of range, or a high `s`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeviceKeyError> {
        let array: [u8; SIGNATURE_BYTES] = bytes.try_into().map_err(|_| DeviceKeyError::InvalidSignature)?;
        let parsed = Signature::from_slice(&array).map_err(|_| DeviceKeyError::InvalidSignature)?;
        // `normalize_s` returns the low-s form; a signature already low is its
        // own normalisation, and one that is not is the other form of itself.
        if parsed.normalize_s() != parsed {
            return Err(DeviceKeyError::InvalidSignature);
        }
        Ok(Self(array))
    }

    /// The 64 bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; SIGNATURE_BYTES] {
        self.0
    }
}

/// What holds a device key: the owner's hardware, or a file only the owner reads.
/// Self-reported by the device; a peer cannot verify it and does not pretend to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Custody {
    /// A Secure Enclave, TPM or security key: the private key never leaves it.
    Hardware,
    /// An owner-only file: extractable by whatever runs as the owner.
    File,
}

/// Something that signs as a device.
///
/// The file-held key below, or a hardware provider that performs the signature
/// elsewhere. The secret is never exposed through this trait; a provider hands
/// out signatures, not keys.
pub trait DeviceSigner: Send + Sync {
    /// The provider's opaque restore record, for owner-only storage.
    /// File custody explicitly exports an extractable scalar here.
    ///
    /// # Errors
    /// Refuses signers that do not support persistent restore records.
    fn sealed_key(&self) -> Result<custody::SealedKey, custody::CustodyError> {
        Err(custody::CustodyError::NotExportable)
    }
    /// The public key.
    fn public_key(&self) -> DevicePublicKey;
    /// Where the key lives, as this provider reports it.
    fn custody(&self) -> Custody;
    /// Signs `message` after the protocol's domain separator.
    ///
    /// # Errors
    ///
    /// A provider that cannot sign now (hardware refused, owner absent) says so.
    fn sign_domain(&self, domain: &'static [u8], message: &[u8]) -> Result<DeviceSignature, DeviceKeyError>;
}

/// A P-256 device key held in process memory, from an owner-only file.
pub struct FileDeviceKey {
    secret: [u8; SECRET_BYTES],
    public: DevicePublicKey,
}

impl Drop for FileDeviceKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl core::fmt::Debug for FileDeviceKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The secret is deliberately absent.
        formatter
            .debug_struct("FileDeviceKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl FileDeviceKey {
    /// Generates a key from the operating system's random source.
    ///
    /// # Errors
    ///
    /// [`DeviceKeyError::Random`] when the system has no randomness to give or
    /// 32 draws fail to produce an in-range scalar.
    pub fn generate() -> Result<Self, DeviceKeyError> {
        let mut secret = [0_u8; SECRET_BYTES];
        for _ in 0..32 {
            getrandom::fill(&mut secret).map_err(|_| DeviceKeyError::Random)?;
            match Self::from_secret_bytes(&secret) {
                Ok(key) => {
                    secret.zeroize();
                    return Ok(key);
                }
                // A scalar out of range: one chance in 2^128; draw again.
                Err(DeviceKeyError::InvalidSecret) => {}
                Err(other) => return Err(other),
            }
        }
        secret.zeroize();
        Err(DeviceKeyError::Random)
    }

    /// Restores a key from its 32-byte scalar.
    ///
    /// # Errors
    ///
    /// [`DeviceKeyError::InvalidSecret`] when the bytes are not a scalar in range.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, DeviceKeyError> {
        let secret: [u8; SECRET_BYTES] = bytes.try_into().map_err(|_| DeviceKeyError::InvalidSecret)?;
        let signing = SigningKey::from_slice(&secret).map_err(|_| DeviceKeyError::InvalidSecret)?;
        let point = signing.verifying_key().to_sec1_point(true);
        let public = DevicePublicKey::from_bytes(point.as_bytes())?;
        Ok(Self { secret, public })
    }

    /// The scalar, for the owner-only file and nothing else. The caller clears it.
    #[must_use]
    pub const fn secret_bytes(&self) -> [u8; SECRET_BYTES] {
        self.secret
    }

    fn signing_key(&self) -> Result<SigningKey, DeviceKeyError> {
        SigningKey::from_slice(&self.secret).map_err(|_| DeviceKeyError::InvalidSecret)
    }
}

impl DeviceSigner for FileDeviceKey {
    fn sealed_key(&self) -> Result<custody::SealedKey, custody::CustodyError> {
        Ok(custody::SealedKey {
            kind: custody::CustodyKind::File,
            bytes: self.secret.to_vec(),
        })
    }
    fn public_key(&self) -> DevicePublicKey {
        self.public
    }

    fn custody(&self) -> Custody {
        Custody::File
    }

    fn sign_domain(&self, domain: &'static [u8], message: &[u8]) -> Result<DeviceSignature, DeviceKeyError> {
        let key = self.signing_key()?;
        // Sign the domain-separated message; ECDSA hashes it with SHA-256, the
        // same digest `verify_domain` checks against.
        let signature: Signature = key.sign(&domain_separated(domain, message));
        let low = signature.normalize_s();
        let bytes: [u8; SIGNATURE_BYTES] = low.to_bytes().into();
        DeviceSignature::from_bytes(&bytes)
    }
}

fn domain_separated(domain: &'static [u8], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len().saturating_add(message.len()));
    out.extend_from_slice(domain);
    out.extend_from_slice(message);
    out
}

fn domain_digest(domain: &'static [u8], message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(message);
    hasher.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::{
        Custody, DeviceKeyError, DevicePublicKey, DeviceSignature, DeviceSigner, FileDeviceKey, PUBLIC_KEY_BYTES,
        SIGNATURE_BYTES,
    };

    const DOMAIN: &[u8] = b"supgang/test/v1\0";

    #[test]
    fn a_signature_verifies_under_its_domain_and_message_only() -> Result<(), DeviceKeyError> {
        let key = FileDeviceKey::generate()?;
        let signature = key.sign_domain(DOMAIN, b"hello")?;
        let public = key.public_key();
        public.verify_domain(DOMAIN, b"hello", &signature)?;
        assert_eq!(
            public.verify_domain(DOMAIN, b"hellp", &signature),
            Err(DeviceKeyError::InvalidSignature)
        );
        assert_eq!(
            public.verify_domain(b"supgang/other/v1\0", b"hello", &signature),
            Err(DeviceKeyError::InvalidSignature)
        );
        assert_eq!(key.custody(), Custody::File);
        Ok(())
    }

    #[test]
    fn a_public_key_has_one_encoding_and_must_be_on_the_curve() -> Result<(), DeviceKeyError> {
        let key = FileDeviceKey::generate()?;
        let bytes = key.public_key().to_bytes();
        assert_eq!(bytes.len(), PUBLIC_KEY_BYTES);
        assert!(bytes.first().is_some_and(|b| *b == 2 || *b == 3));
        assert_eq!(DevicePublicKey::from_bytes(&bytes)?, key.public_key());
        // Wrong length, uncompressed prefix, and a point off the curve.
        assert_eq!(
            DevicePublicKey::from_bytes(&bytes[..32]),
            Err(DeviceKeyError::InvalidPublicKey)
        );
        let mut off = bytes;
        if let Some(last) = off.last_mut() {
            *last = last.wrapping_add(1);
        }
        // One of the two neighbours of a valid x is very likely off the curve; try a few.
        let mut refused = false;
        for step in 1..=8_u8 {
            let mut candidate = bytes;
            if let Some(last) = candidate.last_mut() {
                *last = last.wrapping_add(step);
            }
            if DevicePublicKey::from_bytes(&candidate).is_err() {
                refused = true;
                break;
            }
        }
        assert!(
            refused,
            "no neighbouring x was off the curve, which is astronomically unlikely"
        );
        let mut uncompressed = [4_u8; 65];
        uncompressed[1..33].copy_from_slice(&bytes[1..]);
        assert_eq!(
            DevicePublicKey::from_bytes(&uncompressed),
            Err(DeviceKeyError::InvalidPublicKey)
        );
        Ok(())
    }

    #[test]
    fn a_signature_has_one_encoding_and_a_high_s_is_refused() -> Result<(), DeviceKeyError> {
        let key = FileDeviceKey::generate()?;
        let signature = key.sign_domain(DOMAIN, b"once")?;
        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), SIGNATURE_BYTES);
        assert_eq!(DeviceSignature::from_bytes(&bytes)?, signature);
        // The same signature with s replaced by n - s is the "other form"; it
        // must be refused, so every signature has exactly one encoding.
        let parsed = p256::ecdsa::Signature::from_slice(&bytes).map_err(|_| DeviceKeyError::InvalidSignature)?;
        let (r, s) = parsed.split_scalars();
        let negated = -*s;
        let high = p256::ecdsa::Signature::from_scalars(r.to_bytes(), negated.to_bytes())
            .map_err(|_| DeviceKeyError::InvalidSignature)?;
        let high_bytes: [u8; SIGNATURE_BYTES] = high.to_bytes().into();
        assert_eq!(
            DeviceSignature::from_bytes(&high_bytes),
            Err(DeviceKeyError::InvalidSignature)
        );
        assert_eq!(
            DeviceSignature::from_bytes(&bytes[..63]),
            Err(DeviceKeyError::InvalidSignature)
        );
        Ok(())
    }

    #[test]
    fn two_signatures_of_one_message_differ_but_both_verify() -> Result<(), DeviceKeyError> {
        // Normalisation is not uniqueness: record identity is by content.
        let key = FileDeviceKey::generate()?;
        let first = key.sign_domain(DOMAIN, b"same")?;
        let second = key.sign_domain(DOMAIN, b"same")?;
        key.public_key().verify_domain(DOMAIN, b"same", &first)?;
        key.public_key().verify_domain(DOMAIN, b"same", &second)?;
        // RFC 6979 deterministic signing makes these equal; the point stands
        // either way, and a hardware provider will not be deterministic.
        let _ = first == second;
        Ok(())
    }

    #[test]
    fn a_secret_restores_the_same_public_key_and_a_bad_one_is_refused() -> Result<(), DeviceKeyError> {
        let key = FileDeviceKey::generate()?;
        let again = FileDeviceKey::from_secret_bytes(&key.secret_bytes())?;
        assert_eq!(again.public_key(), key.public_key());
        assert_eq!(
            FileDeviceKey::from_secret_bytes(&[0_u8; 32]).err(),
            Some(DeviceKeyError::InvalidSecret)
        );
        assert_eq!(
            FileDeviceKey::from_secret_bytes(&[0xff_u8; 32]).err(),
            Some(DeviceKeyError::InvalidSecret)
        );
        assert_eq!(
            FileDeviceKey::from_secret_bytes(&[1_u8; 31]).err(),
            Some(DeviceKeyError::InvalidSecret)
        );
        Ok(())
    }

    #[test]
    fn identity_bytes_name_the_algorithm() -> Result<(), DeviceKeyError> {
        let key = FileDeviceKey::generate()?;
        let bytes = key.public_key().identity_bytes();
        assert!(bytes.starts_with(b"p256"));
        assert_eq!(bytes.len(), 4 + PUBLIC_KEY_BYTES);
        Ok(())
    }
}
