use std::io;

use thiserror::Error;

use crate::{artifact, storage};

/// Safe update preparation, verification, or activation failure.
#[derive(Debug, Error)]
pub enum UpdateError {
    /// Protected Supgang storage failed validation.
    #[error("protected update storage failed validation")]
    Storage(#[from] storage::StorageError),
    /// The operating system rejected a bounded filesystem operation.
    #[error("update filesystem operation failed")]
    Io(#[from] io::Error),
    /// An owner-supplied artifact was unsafe or outside its bound.
    #[error("update artifact failed local safety checks")]
    Artifact(#[from] artifact::ArtifactError),
    /// The bundle framing, manifest, entry names, or hashes were invalid.
    #[error("update bundle is malformed or corrupt")]
    InvalidBundle,
    /// The locally pinned TUF root is missing.
    #[error("no update authority is pinned; run `supgang update trust ROOT.json` locally on this computer")]
    MissingTrustRoot,
    /// A trust root was already pinned and cannot be silently replaced.
    #[error("an update authority is already pinned; trust replacement requires a TUF root rotation")]
    TrustAlreadyPinned,
    /// The proposed TUF trust root was malformed or not self-authorized.
    #[error("the proposed TUF trust root is invalid")]
    InvalidTrustRoot,
    /// TUF rejected metadata freshness, signatures, threshold, rollback, or target bytes.
    #[error("the signed update repository did not pass TUF verification")]
    Tuf,
    /// The signed target is not for this exact supported OS and architecture.
    #[error("the signed update target is not for this computer")]
    WrongPlatform,
    /// The target name does not carry a valid Supgang semantic version.
    #[error("the signed update target has an invalid release name")]
    InvalidTargetName,
    /// The target is not newer than the running or already staged release.
    #[error("the signed update would not advance this computer's Supgang version")]
    Rollback,
    /// Another update operation owns the protected update state.
    #[error("another update operation is already in progress")]
    Busy,
    /// A root-signed peer carriage authorization was already reserved or spent.
    #[error("peer update authorization was already used")]
    ReplayedAuthorization,
    /// A bounded update staging area needs operator cleanup.
    #[error("bounded update storage is full; remove an unused prepared update and try again")]
    Capacity,
    /// The verified target does not look like a native executable for this platform.
    #[error("the signed update target is not a supported native executable")]
    InvalidExecutable,
    /// A verified target would break the operating system's approved Supgang identity.
    #[error("the signed update target does not match this computer's approved Supgang identity")]
    IncompatibleCodeIdentity,
}
