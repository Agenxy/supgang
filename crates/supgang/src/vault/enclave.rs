//! Platform custody for the vault agreement keys.

use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
use super::compressed_point;
use super::{PUBLIC_BYTES, VaultError};
use crate::device_key::custody::SealedKey;

/// The key-agreement key a vault is sealed to.
pub trait Enclave {
    /// Creates a new key, returning its restore record and compressed public key.
    ///
    /// # Errors
    /// Refuses when the platform key cannot be created.
    fn generate(&self) -> Result<(SealedKey, [u8; PUBLIC_BYTES]), VaultError>;
    /// Creates a new key whose private agreement requires owner presence.
    ///
    /// # Errors
    /// Refuses when the platform cannot create a presence-gated key.
    fn generate_presence(&self) -> Result<(SealedKey, [u8; PUBLIC_BYTES]), VaultError>;
    /// The raw P-256 shared secret between the sealed key and `peer`.
    ///
    /// # Errors
    /// Refuses a record of another kind and any platform failure.
    fn agree(&self, sealed: &SealedKey, peer: &[u8; PUBLIC_BYTES]) -> Result<Zeroizing<[u8; 32]>, VaultError>;
    /// Completes the agreement only after the platform approves owner presence.
    ///
    /// # Errors
    /// Refuses when presence is declined or unavailable.
    fn agree_presence(
        &self,
        sealed: &SealedKey,
        peer: &[u8; PUBLIC_BYTES],
        reason: &str,
    ) -> Result<Zeroizing<[u8; 32]>, VaultError>;
}

/// This Mac's Secure Enclave, through the sibling helper.
#[derive(Clone, Copy, Debug)]
pub struct SecureEnclave;

#[cfg(target_os = "macos")]
impl Enclave for SecureEnclave {
    fn generate(&self) -> Result<(SealedKey, [u8; PUBLIC_BYTES]), VaultError> {
        let (sealed, public) = crate::device_key::secure_enclave::generate_agreement()?;
        Ok((sealed, compressed_point(&public)?))
    }
    fn generate_presence(&self) -> Result<(SealedKey, [u8; PUBLIC_BYTES]), VaultError> {
        let (sealed, public) = crate::device_key::secure_enclave::generate_presence_agreement()?;
        Ok((sealed, compressed_point(&public)?))
    }
    fn agree(&self, sealed: &SealedKey, peer: &[u8; PUBLIC_BYTES]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        Ok(crate::device_key::secure_enclave::agree(sealed, peer)?)
    }
    fn agree_presence(
        &self,
        sealed: &SealedKey,
        peer: &[u8; PUBLIC_BYTES],
        reason: &str,
    ) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        Ok(crate::device_key::secure_enclave::agree_presence(sealed, peer, reason)?)
    }
}

#[cfg(not(target_os = "macos"))]
impl Enclave for SecureEnclave {
    fn generate(&self) -> Result<(SealedKey, [u8; PUBLIC_BYTES]), VaultError> {
        Err(crate::device_key::custody::CustodyError::Unavailable(
            crate::device_key::custody::UnavailableReason::WrongPlatform,
        )
        .into())
    }
    fn generate_presence(&self) -> Result<(SealedKey, [u8; PUBLIC_BYTES]), VaultError> {
        Err(crate::device_key::custody::CustodyError::Unavailable(
            crate::device_key::custody::UnavailableReason::WrongPlatform,
        )
        .into())
    }
    fn agree(&self, _sealed: &SealedKey, _peer: &[u8; PUBLIC_BYTES]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        Err(crate::device_key::custody::CustodyError::Unavailable(
            crate::device_key::custody::UnavailableReason::WrongPlatform,
        )
        .into())
    }
    fn agree_presence(
        &self,
        _sealed: &SealedKey,
        _peer: &[u8; PUBLIC_BYTES],
        _reason: &str,
    ) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        Err(crate::device_key::custody::CustodyError::Unavailable(
            crate::device_key::custody::UnavailableReason::WrongPlatform,
        )
        .into())
    }
}
