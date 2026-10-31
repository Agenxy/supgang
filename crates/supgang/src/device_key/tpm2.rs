//! Declared Linux TPM 2.0 provider, not built in this release.
//!
//! Implementing this file requires the `tss-esapi` crate (absent from the offline
//! cache), its native TSS stack, and a decision about owner access to `/dev/tpmrm0`
//! without granting the service broad privilege. Create or recreate a primary key
//! and store the wrapped child's public/private TPM blobs and primary parameters
//! inside `SealedKey::bytes`; the portable container and signer interface stay put.
//! Presence needs its own policy and tests: TPM PIN authorization is not Touch ID
//! and a remembered PIN must not silently satisfy `PresencePolicy::Required`.
//! Implement and verify those operations on a real Linux TPM before reporting
//! `Ready`. Adding them changes this provider file, not the custody interface.

use super::{
    DeviceSigner,
    custody::{Availability, CustodyError, CustodyKind, CustodyProvider, PresencePolicy, SealedKey},
};

/// The declared Linux counterpart, with no hardware or security claim yet.
#[derive(Clone, Copy, Debug)]
pub struct Tpm2Provider;

impl CustodyProvider for Tpm2Provider {
    fn kind(&self) -> CustodyKind {
        CustodyKind::Tpm2
    }
    fn availability(&self) -> Availability {
        Availability::NotBuilt
    }
    fn generate(&self, _presence: PresencePolicy) -> Result<Box<dyn DeviceSigner>, CustodyError> {
        Err(CustodyError::NotBuilt)
    }
    fn load(&self, sealed: &SealedKey) -> Result<Box<dyn DeviceSigner>, CustodyError> {
        sealed.require_kind(self.kind())?;
        Err(CustodyError::NotBuilt)
    }
}
