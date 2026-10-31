//! Explicit, extractable file custody. It cannot enforce platform presence.

use super::{
    DeviceSigner, FileDeviceKey,
    custody::{Availability, CustodyError, CustodyKind, CustodyProvider, PresencePolicy, SealedKey},
};

/// File custody is available everywhere Supgang can protect owner-only storage.
/// Choosing it is an explicit owner decision, never a hardware fallback.
#[derive(Clone, Copy, Debug)]
pub struct FileProvider;

impl CustodyProvider for FileProvider {
    fn kind(&self) -> CustodyKind {
        CustodyKind::File
    }
    fn availability(&self) -> Availability {
        Availability::Ready
    }
    fn generate(&self, presence: PresencePolicy) -> Result<Box<dyn DeviceSigner>, CustodyError> {
        if presence == PresencePolicy::Required {
            return Err(CustodyError::PresenceUnsupported);
        }
        Ok(Box::new(FileDeviceKey::generate()?))
    }
    fn load(&self, sealed: &SealedKey) -> Result<Box<dyn DeviceSigner>, CustodyError> {
        sealed.require_kind(self.kind())?;
        Ok(Box::new(FileDeviceKey::from_secret_bytes(&sealed.bytes)?))
    }
}
