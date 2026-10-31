//! Portable key custody. Choosing a provider never chooses a fallback.
//!
//! A custody label records what the owner enrolled, not an attestation. The
//! sealed bytes belong to the provider; the core only bounds and stores them.

use serde::Serialize;
use thiserror::Error;

use super::{DeviceKeyError, DeviceSigner};
pub use super::{file::FileProvider, sealed::SealedKey};

/// The providers in capability-report order, on every platform.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CustodyKind {
    /// Apple's Secure Enclave, through the optional native helper.
    SecureEnclave,
    /// A TPM 2.0 primary key and wrapped child.
    Tpm2,
    /// An external security key; no implementation is built yet.
    SecurityKey,
    /// An extractable scalar in an owner-only file, explicitly chosen.
    File,
}

/// Why a provider cannot be used now. These reasons have different remedies.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "reason", content = "code")]
pub enum UnavailableReason {
    /// The machine has no compatible hardware.
    #[error("this machine has no compatible hardware")]
    NoHardware,
    /// The optional helper was not installed beside Supgang.
    #[error("install supgang-secure-enclave beside supgang")]
    HelperMissing,
    /// The helper or native API refused, with a numeric status only.
    #[error("the custody helper refused (status {0})")]
    HelperRefused(i32),
    /// The owner cancelled the platform's presence request.
    #[error("the owner declined the presence request")]
    OwnerDeclinedPresence,
    /// This provider belongs to another operating system.
    #[error("this provider is for another platform")]
    WrongPlatform,
    /// Building the optional native helper requires its platform toolchain.
    #[error("the optional helper's platform toolchain is missing")]
    ToolchainMissing,
    /// The helper did not finish inside the operation's deadline.
    #[error("the custody helper timed out")]
    HelperTimedOut,
    /// Output did not match the bounded, versioned helper protocol.
    #[error("the custody helper returned an invalid protocol response")]
    HelperProtocol,
    /// One helper operation is already running; no queue is formed.
    #[error("a custody helper operation is already running")]
    HelperBusy,
}

/// Whether a provider can be used in this build on this machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status", content = "detail")]
pub enum Availability {
    /// The provider can accept an operation; a later operation can still refuse.
    Ready,
    /// Built but unusable here, for the stated reason.
    Unavailable(UnavailableReason),
    /// Deliberately unimplemented, rather than missing hardware.
    NotBuilt,
}

/// One row of the complete capability matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CustodyCapability {
    /// Provider identity.
    pub kind: CustodyKind,
    /// Availability on this machine, without requesting owner presence.
    pub availability: Availability,
}

/// Whether every use of the key must be gated by the platform's owner prompt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresencePolicy {
    /// Require presence; providers that cannot enforce it refuse generation.
    Required,
    /// Explicitly allow unattended signing.
    Unattended,
}

/// A refusal at the portable custody boundary. No error selects another provider.
#[derive(Debug, Error)]
pub enum CustodyError {
    /// Built but unavailable.
    #[error("custody is unavailable: {0}")]
    Unavailable(#[from] UnavailableReason),
    /// This provider has no implementation yet.
    #[error("this custody provider is not built")]
    NotBuilt,
    /// A restore record was passed to the wrong provider.
    #[error("sealed key belongs to another custody provider")]
    KindMismatch,
    /// Noncanonical, unsupported, empty, truncated or oversized restore record.
    #[error("sealed key is malformed or exceeds its size limit")]
    InvalidSealedKey,
    /// The selected provider cannot enforce presence.
    #[error("this custody provider cannot enforce owner presence")]
    PresenceUnsupported,
    /// This signer has no persistent restore representation.
    #[error("this signer does not export a restore record")]
    NotExportable,
    /// The provider returned an invalid key or signature.
    #[error(transparent)]
    Key(#[from] DeviceKeyError),
    /// Protected artifact access failed.
    #[error(transparent)]
    Artifact(#[from] crate::artifact::ArtifactError),
    /// The identity directory is not safe for protected storage.
    #[error(transparent)]
    Storage(#[from] crate::storage::StorageError),
}

/// Creates and restores signers without exposing a platform API to consumers.
pub trait CustodyProvider: Send + Sync {
    /// The provider this object represents.
    fn kind(&self) -> CustodyKind;
    /// A noninteractive capability check, not a promise that signing will succeed.
    fn availability(&self) -> Availability;
    /// Creates a key with exactly the requested presence policy.
    ///
    /// # Errors
    /// Refuses unavailable providers, unsupported presence and creation failures.
    fn generate(&self, presence: PresencePolicy) -> Result<Box<dyn DeviceSigner>, CustodyError>;
    /// Restores this provider's opaque record; never guesses at another kind.
    ///
    /// # Errors
    /// Refuses kind mismatch, unavailable providers and invalid restore bytes.
    fn load(&self, sealed: &SealedKey) -> Result<Box<dyn DeviceSigner>, CustodyError>;
}

/// Every provider exactly once: Secure Enclave, TPM 2.0, security key, file.
#[must_use]
pub fn capabilities() -> Vec<CustodyCapability> {
    let enclave = enclave_availability();
    let tpm = tpm_availability();
    [
        (CustodyKind::SecureEnclave, enclave),
        (CustodyKind::Tpm2, tpm),
        (CustodyKind::SecurityKey, Availability::NotBuilt),
        (CustodyKind::File, FileProvider.availability()),
    ]
    .into_iter()
    .map(|(kind, availability)| CustodyCapability { kind, availability })
    .collect()
}

#[cfg(target_os = "macos")]
fn enclave_availability() -> Availability {
    super::secure_enclave::SecureEnclaveProvider.availability()
}

#[cfg(not(target_os = "macos"))]
const fn enclave_availability() -> Availability {
    Availability::Unavailable(UnavailableReason::WrongPlatform)
}

#[cfg(target_os = "linux")]
fn tpm_availability() -> Availability {
    super::tpm2::Tpm2Provider.availability()
}

#[cfg(not(target_os = "linux"))]
const fn tpm_availability() -> Availability {
    Availability::Unavailable(UnavailableReason::WrongPlatform)
}
