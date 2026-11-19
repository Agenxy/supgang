//! Public vault refusal types with no secret-bearing messages.

use crate::{artifact, device_key::custody::CustodyError, storage};
use std::io;
use thiserror::Error;

/// A vault refusal. Messages never include secret bytes.
#[derive(Debug, Error)]
pub enum VaultError {
    /// The name is empty, too long or uses other characters.
    #[error("secret names are 1 to 64 lowercase letters, digits, '.', '_' or '-', starting with a letter or digit")]
    InvalidName,
    /// The note is too long or contains control characters.
    #[error("notes are at most 200 bytes of printable text")]
    InvalidNote,
    /// The secret is empty or larger than the vault accepts.
    #[error("a secret must be 1 to 8192 bytes")]
    InvalidSecret,
    /// The signing request is malformed.
    #[error("signing context must be 1 to 64 ASCII bytes from [a-z0-9._-], and --sha256 must be 64 hex characters")]
    InvalidSigningRequest,
    /// An agent signing policy is malformed or noncanonical.
    #[error("agent signing policy must have sorted, unique, bounded contexts and member identities")]
    InvalidAgentPolicy,
    /// The key's immutable agent policy does not admit this request.
    #[error("the signing key's agent policy refuses this member or context")]
    AgentPolicyDenied,
    /// Current certified membership could not be established.
    #[error("current local hive membership could not be verified for agent signing")]
    MemberAuthority,
    /// Agent audit is missing, changed, contended or could not be synced.
    #[error("agent audit cannot be verified or made durable; no signature was released")]
    AgentAudit,
    /// All bounded agent audit segments are full.
    #[error("agent audit is full; signing is paused until a reviewed audit checkpoint can be installed")]
    AgentAuditFull,
    /// Agent key creation reached an operational rolling-day limit.
    #[error("agent key creation reached its per-member or hive 24-hour limit")]
    AgentKeyCreationLimit,
    /// A member request nonce has already been spent.
    #[error("agent signing request nonce was already used")]
    AgentNonceReplay,
    /// The bounded live member request set is full.
    #[error("agent signing request nonce capacity is full")]
    AgentNonceLimit,
    /// The purpose reached its operational hourly signing budget.
    #[error("agent signing purpose reached its per-member or hive hourly limit")]
    AgentSignLimit,
    /// Signing keys are never exportable.
    #[error("signing keys cannot be exported with vault get or vault run; use supgang sign")]
    SigningKeyNotExportable,
    /// SSH keys are never exportable.
    #[error("SSH keys cannot be exported with vault get or vault run; use supgang ssh-agent")]
    SshKeyNotExportable,
    /// LMS key material is never exported.
    #[error("LMS keys cannot be exported with vault get or vault run")]
    LmsKeyNotExportable,
    /// A key reserved for LMS cannot be overwritten or removed.
    #[error("LMS roots cannot be replaced or removed; retire the root and retain its reservation record")]
    LmsRootRetained,
    /// The entry is not an LMS root.
    #[error("the named vault entry is not an LMS root")]
    NotLmsKey,
    /// The NC0 package header, size, or contents are invalid.
    #[error("the NC0 format-2 package is invalid or changed while being read")]
    InvalidNc0Package,
    /// Local q records do not agree.
    #[error("LMS reservation records disagree; signing is refused")]
    LmsStateMismatch,
    /// The caller's independent release log does not support this q.
    #[error("LMS release-log evidence does not permit this q")]
    LmsReleaseLog,
    /// No LMS leaf remains.
    #[error("the LMS root has exhausted all 1048576 leaf numbers")]
    LmsExhausted,
    /// Forward-only recovery target is unsafe.
    #[error("LMS advance target must exceed both local records and the external release log")]
    LmsAdvanceRefused,
    /// Key generation could not prove that its orphan journal was removed.
    #[error("LMS key generation could not verify or clean its orphan journal; inspect vault state before retrying")]
    LmsOrphanCleanup,
    /// The entry is not a signing key.
    #[error("the named vault entry is not an Ed25519 signing key")]
    NotSigningKey,
    /// The entry is not an SSH key.
    #[error("the named vault entry is not an ssh-ed25519 key")]
    NotSshKey,
    /// The SSH data is too large to sign.
    #[error("SSH agent signing data exceeds 256 KiB")]
    SshDataTooLarge,
    /// No secret has this name.
    #[error("no secret named {0} in this computer's vault")]
    NotFound(String),
    /// A secret already has this name and replacement was not requested.
    #[error("a vault entry named {0} already exists")]
    AlreadyExists(String),
    /// The vault holds its maximum number of secrets.
    #[error("the vault already holds 128 secrets; remove one first")]
    Full,
    /// Another vault change holds the lock.
    #[error("another vault change is in progress; retry the command")]
    Busy,
    /// The enclave key is unusable here, for the stated reason.
    #[error("the vault needs this Mac's Secure Enclave: {0}")]
    Enclave(#[from] CustodyError),
    /// The vault file is malformed, from another computer or tampered with.
    #[error("the vault file is invalid, belongs to another computer, or was altered")]
    Corrupt,
    /// The protected state directory failed validation.
    #[error(transparent)]
    Storage(#[from] storage::StorageError),
    /// A protected file failed validation.
    #[error(transparent)]
    Artifact(#[from] artifact::ArtifactError),
    /// The audit record could not be written, so the secret was not released.
    #[error("the vault could not record this read in vault-audit.log, so it released nothing")]
    Audit,
    /// The operating system rejected a vault-file operation.
    #[error("vault filesystem operation failed")]
    Io(#[from] io::Error),
}
