//! Device signing identities and domain-separated signatures.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;
use zeroize::Zeroize;

use crate::ids::NodeId;

const SIGNING_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

/// A failure while generating or loading a device identity.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdentityError {
    /// The operating system did not provide cryptographically secure random bytes.
    #[error("the operating system could not provide secure random bytes")]
    Random,
    /// Stored key material had the wrong size.
    #[error("stored signing key must contain exactly 32 bytes")]
    InvalidKeyLength,
}

/// A device's long-term Ed25519 signing identity.
///
/// Debug output intentionally contains only the public node identifier.
pub struct DeviceIdentity {
    seed: [u8; SIGNING_KEY_BYTES],
}

/// A hive's root signing identity.
///
/// This type intentionally does not expose the device-record signing API.
pub struct RootIdentity {
    seed: [u8; SIGNING_KEY_BYTES],
}

impl Drop for DeviceIdentity {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl Drop for RootIdentity {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl core::fmt::Debug for DeviceIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DeviceIdentity")
            .field("node_id", &self.node_id())
            .finish()
    }
}

impl core::fmt::Debug for RootIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RootIdentity")
            .field("hive_id", &self.hive_id())
            .finish()
    }
}

impl DeviceIdentity {
    /// Generates a new device identity from the operating system's random source.
    ///
    /// # Errors
    ///
    /// Returns an error when secure random bytes are unavailable.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut seed = [0_u8; SIGNING_KEY_BYTES];
        getrandom::fill(&mut seed).map_err(|_| IdentityError::Random)?;
        Ok(Self { seed })
    }

    /// Restores a device identity from its 32-byte secret seed.
    ///
    /// # Errors
    ///
    /// Returns an error when `bytes` is not exactly 32 bytes long.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let seed: [u8; SIGNING_KEY_BYTES] = bytes.try_into().map_err(|_| IdentityError::InvalidKeyLength)?;
        Ok(Self { seed })
    }

    /// Returns the stable node identifier derived from the verification key.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        NodeId::from_verifying_key(&self.verifying_key().to_bytes())
    }

    /// Returns the public verification key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key().verifying_key()
    }

    /// Signs bytes after a protocol-specific domain separator.
    #[must_use]
    pub(crate) fn sign_domain(&self, domain: &'static [u8], message: &[u8]) -> [u8; SIGNATURE_BYTES] {
        let mut signed = Vec::with_capacity(domain.len().saturating_add(message.len()));
        signed.extend_from_slice(domain);
        signed.extend_from_slice(message);
        self.signing_key().sign(&signed).to_bytes()
    }

    /// Copies the secret seed for transfer to an approved protected-key provider.
    ///
    /// The caller must keep the returned value out of logs and clear it promptly.
    #[must_use]
    pub(crate) const fn secret_bytes(&self) -> [u8; SIGNING_KEY_BYTES] {
        self.seed
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }
}

impl RootIdentity {
    /// Generates a new hive root from the operating system's random source.
    ///
    /// # Errors
    ///
    /// Returns an error when secure random bytes are unavailable.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut seed = [0_u8; SIGNING_KEY_BYTES];
        getrandom::fill(&mut seed).map_err(|_| IdentityError::Random)?;
        Ok(Self { seed })
    }

    /// Restores a hive root from its 32-byte secret seed.
    ///
    /// # Errors
    ///
    /// Returns an error when `bytes` is not exactly 32 bytes long.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let seed: [u8; SIGNING_KEY_BYTES] = bytes.try_into().map_err(|_| IdentityError::InvalidKeyLength)?;
        Ok(Self { seed })
    }

    /// Returns the hive identifier bound to this root key.
    #[must_use]
    pub fn hive_id(&self) -> crate::ids::HiveId {
        crate::ids::HiveId::from_root_verifying_key(&self.verifying_key().to_bytes())
    }

    /// Returns the root verification key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key().verifying_key()
    }

    pub(crate) fn sign_domain(&self, domain: &'static [u8], message: &[u8]) -> [u8; SIGNATURE_BYTES] {
        let mut signed = Vec::with_capacity(domain.len().saturating_add(message.len()));
        signed.extend_from_slice(domain);
        signed.extend_from_slice(message);
        self.signing_key().sign(&signed).to_bytes()
    }

    pub(crate) const fn secret_bytes(&self) -> [u8; SIGNING_KEY_BYTES] {
        self.seed
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }
}

/// Verifies a domain-separated Ed25519 signature.
#[must_use]
pub fn verify_domain(
    key: &VerifyingKey,
    domain: &'static [u8],
    message: &[u8],
    signature: &[u8; SIGNATURE_BYTES],
) -> bool {
    let mut signed = Vec::with_capacity(domain.len().saturating_add(message.len()));
    signed.extend_from_slice(domain);
    signed.extend_from_slice(message);
    key.verify_strict(&signed, &Signature::from_bytes(signature)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::{DeviceIdentity, RootIdentity, verify_domain};

    #[test]
    fn signatures_are_bound_to_domain_and_message() -> Result<(), Box<dyn std::error::Error>> {
        let identity = DeviceIdentity::generate()?;
        let signature = identity.sign_domain(b"supgang/test/a\0", b"message");
        let key = identity.verifying_key();

        assert!(verify_domain(&key, b"supgang/test/a\0", b"message", &signature));
        assert!(!verify_domain(&key, b"supgang/test/b\0", b"message", &signature));
        assert!(!verify_domain(&key, b"supgang/test/a\0", b"changed", &signature));
        Ok(())
    }

    #[test]
    fn debug_never_contains_secret_seed() -> Result<(), Box<dyn std::error::Error>> {
        let identity = DeviceIdentity::from_secret_bytes(&[0x5a; 32])?;
        let rendered = format!("{identity:?}");
        assert!(!rendered.contains(&"5a".repeat(32)));
        assert!(rendered.contains("node_id"));
        Ok(())
    }

    #[test]
    fn root_and_device_types_have_distinct_public_identities() -> Result<(), Box<dyn std::error::Error>> {
        let root = RootIdentity::from_secret_bytes(&[3; 32])?;
        let device = DeviceIdentity::from_secret_bytes(&[3; 32])?;
        assert_ne!(root.hive_id().as_bytes(), device.node_id().as_bytes());
        assert!(format!("{root:?}").contains("hive_id"));
        Ok(())
    }
}
