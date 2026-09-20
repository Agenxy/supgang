//! Device-certified keys and authority manifests, independent of endpoint records.
//!
//! # Canonical v1 encoding
//!
//! CBOR arrays have definite lengths, integers use their shortest unsigned form,
//! strings use definite lengths, and every field is present. Decoders re-encode
//! and compare bytes; trailing data, nonminimal encodings and unknown tags fail.
//! `bN` below means a byte string of exactly N bytes; all times are UNIX seconds.
//!
//! * Certificate: `[1, hive:b32, [node:b32, epoch:u64], id:b16,
//!   [algorithm:text, key:bytes, custody:text], purpose:text, audience,
//!   operations:[text...], not_before:u64, not_after:u64, policy:u16,
//!   possession:b64]`. Algorithms are `p256` (compressed SEC1 b33) and `ed25519`
//!   (b32). Custody is `hardware`, `file`, or `synced`, always self-reported.
//! * Audience: `["publish"]`, `["service", name, instance:b16]`,
//!   `["transport-server", name, instance:b16, hostname]`,
//!   `["transport-client", hive:b32, node:b32-or-null]`, or `["attest", instance:b16]`.
//!   Its tag must equal the certificate purpose. Names use `ServiceName`;
//!   hostnames are lowercase ASCII DNS names of at most 253 bytes, no wildcard.
//! * Possession signs the **11-element array** of certificate fields preceding
//!   possession (including version), prefixed with
//!   `supgang/certified-key-possession/v1\0`. P-256 uses SHA-256 and low-s r||s;
//!   Ed25519 signs the prefix and bytes directly with strict verification.
//!   There is no additional certificate issuer signature.
//! * Revocations: `[1, [id:b16...]]`, strictly ascending unique ids, at most 64
//!   and 4096 encoded bytes. Operations are strictly ascending unique strings,
//!   at most 16, each 1..=64 bytes of visible ASCII. Certificates are strictly
//!   ascending by id, at most 16. Services are sorted by unique name, at most 4.
//! * Manifest content: `[1, epoch:u64, revision:u64, issued_at:u64,
//!   next_update:u64, [certificate...], revocations, [service...]]`.
//!   Service is `[name:text, port:u16, key_pin:b32]`, reusing `ServiceAdvert`.
//! * Signed manifest: `[1, content:bytes, signature:b64]`, at most **8192 bytes**,
//!   including this envelope. The device signs content bytes prefixed with
//!   `supgang/authority/v1\0`. Record identity excludes the outer signature.
//!
//! # Boundaries
//!
//! This library does not establish root membership or fresh protocol possession.
//! Callers must check both before using its result for authorization. A verifier
//! is scoped to one hive; device ids are SHA-256(`p256 || compressed SEC1 key`).
//! Lookup requires `issued_at <= now <= next_update` AND
//! `now - issued_at <= max_status_age` AND `not_before <= now <= not_after`.
//! Receipt time never renews authority. A five-minute future tolerance on ingest
//! does not permit use before issuance. Verifier state must be retained by its
//! owner; this package does not wire persistence into the service.

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    device_key::{DeviceKeyError, DevicePublicKey, DeviceSignature, DeviceSigner},
    ids::{HiveId, NodeId},
    record::{RecordError, ServiceAdvert, ServiceName},
};

mod codec;
mod revision_store;
mod update;
mod verifier;

pub use revision_store::{FileRevisionStore, RevisionStore};
pub use update::AuthorityUpdate;
pub use verifier::AuthorityVerifier;

#[cfg(test)]
mod adversarial_tests;
#[cfg(test)]
mod tests;

/// Maximum size of the complete signed CBOR manifest.
pub const MAX_MANIFEST_BYTES: usize = 8192;
/// Maximum live certificates carried by one device.
pub const MAX_CERTIFICATES: usize = 16;
/// Maximum revocation ids in one epoch.
pub const MAX_REVOCATIONS: usize = 64;
/// Maximum standalone canonical revocation-set encoding.
pub const MAX_REVOCATION_BYTES: usize = 4096;
/// Maximum ids remembered for lifetime non-reuse; exhaustion fails closed.
pub const MAX_USED_IDS: usize = 4096;
/// Maximum certificate lifetime in seconds.
pub const MAX_CERTIFICATE_LIFETIME: u64 = 366 * 24 * 60 * 60;
/// Maximum interval to the next manifest update in seconds.
pub const MAX_UPDATE_INTERVAL: u64 = 7 * 24 * 60 * 60;
/// Possession signature domain, including its terminal NUL.
pub const POSSESSION_DOMAIN: &[u8] = b"supgang/certified-key-possession/v1\0";
const AUTHORITY_DOMAIN: &[u8] = b"supgang/authority/v1\0";
const MAX_OPERATIONS: usize = 16;
const MAX_OPERATION_BYTES: usize = 64;

/// A certificate or consumer instance identifier, generated randomly by its owner.
pub type CertificateId = [u8; 16];

/// A rejected encoding, authority transition, or proof.
#[derive(Debug, Error)]
pub enum AuthorityError {
    /// Unsupported schema or signer policy.
    #[error("unsupported authority version or policy")]
    Version,
    /// A bounded input exceeded its ceiling.
    #[error("authority bound exceeded")]
    Bound,
    /// The CBOR shape or a field is invalid.
    #[error("invalid authority field or encoding")]
    Invalid,
    /// Encoding differs from the canonical form.
    #[error("authority encoding is not canonical")]
    NonCanonical,
    /// The closed purpose enum does not recognize a value.
    #[error("unknown certified-key purpose")]
    UnknownPurpose,
    /// The purpose does not admit this audience or operation.
    #[error("certificate does not authorize this audience or operation")]
    Scope,
    /// Hive, device, or epoch differs from the expected issuer.
    #[error("certificate issuer, hive, or epoch does not match")]
    Issuer,
    /// Possession was not proved for these exact fields.
    #[error("certified-key possession proof failed")]
    Possession,
    /// An id was already used, including in a prior epoch.
    #[error("certificate id has already been used")]
    ReusedId,
    /// A newer revocation set removed a known id.
    #[error("authority revocations must be monotonic")]
    RevocationRollback,
    /// Epoch, revision, or issuance time moved backwards.
    #[error("authority manifest is older than the retained watermark")]
    Older,
    /// Different content was signed at an already seen epoch and revision.
    #[error("authority equivocation; neither manifest is usable")]
    Equivocation,
    /// The manifest is more than five minutes in the future.
    #[error("authority issuance exceeds tolerated clock skew")]
    Future,
    /// No current, fresh, unrevoked certificate matches.
    #[error("no usable certified key matches the request")]
    Unavailable,
    /// The store's committed head differs from the proposed predecessor.
    #[error("authority revision store predecessor or reservation does not match")]
    StoreConflict,
    /// Signature or public key failure.
    #[error(transparent)]
    Key(#[from] DeviceKeyError),
    /// A service advertisement failed validation.
    #[error(transparent)]
    Service(#[from] RecordError),
    /// CBOR encoding failure.
    #[error("authority encoding failed")]
    Encode(#[from] minicbor::encode::Error<core::convert::Infallible>),
    /// CBOR decoding failure.
    #[error("authority decoding failed")]
    Decode(#[from] minicbor::decode::Error),
    /// Protected storage failure.
    #[error(transparent)]
    Storage(#[from] crate::storage::StorageError),
    /// Exclusive state ownership failure.
    #[error(transparent)]
    Lock(#[from] crate::state_lock::StateLockError),
    /// Durable storage could not complete an operation.
    #[error("authority revision storage I/O failed")]
    Io(#[from] std::io::Error),
}

/// Closed authorization purposes; an unknown wire value is always refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Purpose {
    /// Publish endpoint records.
    Publish,
    /// Speak for a consumer service instance.
    Service,
    /// Authenticate as a transport client.
    TransportClient,
    /// Serve an exact transport hostname.
    TransportServer,
    /// Attest for a consumer instance.
    Attest,
}

impl Purpose {
    const fn text(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Service => "service",
            Self::TransportClient => "transport-client",
            Self::TransportServer => "transport-server",
            Self::Attest => "attest",
        }
    }

    fn parse(value: &str) -> Result<Self, AuthorityError> {
        match value {
            "publish" => Ok(Self::Publish),
            "service" => Ok(Self::Service),
            "transport-client" => Ok(Self::TransportClient),
            "transport-server" => Ok(Self::TransportServer),
            "attest" => Ok(Self::Attest),
            _ => Err(AuthorityError::UnknownPurpose),
        }
    }
}

/// Self-reported custody of a subordinate, not independently attested storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectCustody {
    /// An owner-controlled hardware key provider.
    Hardware,
    /// An extractable file key.
    File,
    /// A credential synchronized by its provider.
    Synced,
}

/// A validated public key in one of the two implemented algorithms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubjectKey {
    /// Compressed P-256 public key.
    P256(DevicePublicKey),
    /// Ed25519 public key; weak keys are refused during validation.
    Ed25519([u8; 32]),
}

/// Exact audience schema for each purpose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Audience {
    /// Publication has no additional audience.
    Publish,
    /// One service instance.
    Service {
        /// Consumer-defined service name.
        name: ServiceName,
        /// Consumer-generated instance identity.
        instance: CertificateId,
    },
    /// One service instance and exact DNS hostname.
    TransportServer {
        /// Consumer-defined service name.
        name: ServiceName,
        /// Consumer-generated instance identity.
        instance: CertificateId,
        /// Lowercase ASCII DNS hostname.
        hostname: String,
    },
    /// This hive and, optionally, one remote device.
    TransportClient {
        /// Must equal the enclosing certificate's hive.
        hive: HiveId,
        /// Optional remote device restriction.
        node: Option<NodeId>,
    },
    /// One consumer instance.
    Attest {
        /// Consumer-generated instance identity.
        instance: CertificateId,
    },
}

impl Audience {
    const fn purpose(&self) -> Purpose {
        match self {
            Self::Publish => Purpose::Publish,
            Self::Service { .. } => Purpose::Service,
            Self::TransportClient { .. } => Purpose::TransportClient,
            Self::TransportServer { .. } => Purpose::TransportServer,
            Self::Attest { .. } => Purpose::Attest,
        }
    }

    fn permits(&self, requested: &Self) -> bool {
        match (self, requested) {
            (
                Self::TransportClient { hive, node },
                Self::TransportClient {
                    hive: requested_hive,
                    node: requested_node,
                },
            ) => hive == requested_hive && (node.is_none() || node == requested_node),
            _ => self == requested,
        }
    }
}

/// Fields authenticated by the subject's enrollment possession proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedKeyClaims {
    /// Hive in which this certificate is valid.
    pub hive: HiveId,
    /// Issuing device identity.
    pub issuer: NodeId,
    /// Issuing device's authority epoch.
    pub epoch: u64,
    /// Random certificate identity, never reused.
    pub id: CertificateId,
    /// Subordinate's public key.
    pub subject: SubjectKey,
    /// Owner-reported custody.
    pub custody: SubjectCustody,
    /// Exactly one authorization purpose.
    pub purpose: Purpose,
    /// Scope appropriate to the purpose.
    pub audience: Audience,
    /// Strictly sorted, unique consumer-defined operations.
    pub operations: Vec<String>,
    /// Inclusive start of validity, UNIX seconds.
    pub not_before: u64,
    /// Inclusive end of validity, at most 366 days after start.
    pub not_after: u64,
    /// Signer policy, currently exactly 1.
    pub policy: u16,
}

impl CertifiedKeyClaims {
    /// Validates bounds, algorithm, purpose, audience, policy and lifetime.
    ///
    /// # Errors
    /// Returns the first invalid field or exceeded bound.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        if self.policy != 1 {
            return Err(AuthorityError::Version);
        }
        if self.not_after < self.not_before || self.not_after - self.not_before > MAX_CERTIFICATE_LIFETIME {
            return Err(AuthorityError::Invalid);
        }
        if self.audience.purpose() != self.purpose {
            return Err(AuthorityError::Scope);
        }
        match &self.audience {
            Audience::TransportClient { hive, .. } if *hive != self.hive => return Err(AuthorityError::Issuer),
            Audience::TransportServer { hostname, .. } if !valid_hostname(hostname) => {
                return Err(AuthorityError::Scope);
            }
            _ => {}
        }
        if self.operations.len() > MAX_OPERATIONS {
            return Err(AuthorityError::Bound);
        }
        if !self.operations.is_sorted_by(|a, b| a < b)
            || self.operations.iter().any(|operation| {
                operation.is_empty()
                    || operation.len() > MAX_OPERATION_BYTES
                    || !operation.bytes().all(|b| b.is_ascii_graphic())
            })
        {
            return Err(AuthorityError::Invalid);
        }
        if let SubjectKey::Ed25519(bytes) = self.subject {
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| AuthorityError::Invalid)?;
            if key.is_weak() {
                return Err(AuthorityError::Invalid);
            }
        }
        Ok(())
    }

    /// Canonical possession payload, before any subject signature is attached.
    ///
    /// # Errors
    /// Rejects malformed claims or an encoding failure.
    pub fn possession_payload(&self) -> Result<Vec<u8>, AuthorityError> {
        self.validate()?;
        codec::claims_bytes(self)
    }
}

/// A statement authenticated only inside its device-signed authority manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedKey {
    /// All fields bound by the subject's proof.
    pub claims: CertifiedKeyClaims,
    /// Fixed-size signature in the subject algorithm.
    pub possession: [u8; 64],
}

impl CertifiedKey {
    /// Proves possession with a P-256 subordinate.
    ///
    /// # Errors
    /// Rejects mismatched keys, invalid fields, or provider failure.
    pub fn prove_p256(claims: CertifiedKeyClaims, subject: &impl DeviceSigner) -> Result<Self, AuthorityError> {
        if claims.subject != SubjectKey::P256(subject.public_key()) {
            return Err(AuthorityError::Possession);
        }
        let possession = subject
            .sign_domain(POSSESSION_DOMAIN, &claims.possession_payload()?)?
            .to_bytes();
        Ok(Self { claims, possession })
    }

    /// Proves possession with an Ed25519 subordinate.
    ///
    /// # Errors
    /// Rejects mismatched keys or invalid fields.
    pub fn prove_ed25519(claims: CertifiedKeyClaims, subject: &SigningKey) -> Result<Self, AuthorityError> {
        if claims.subject != SubjectKey::Ed25519(subject.verifying_key().to_bytes()) {
            return Err(AuthorityError::Possession);
        }
        let mut payload = POSSESSION_DOMAIN.to_vec();
        payload.extend_from_slice(&claims.possession_payload()?);
        Ok(Self {
            claims,
            possession: subject.sign(&payload).to_bytes(),
        })
    }

    /// Verifies enrollment possession for precisely these claims.
    ///
    /// # Errors
    /// Rejects malformed claims or an invalid proof.
    pub fn verify_possession(&self) -> Result<(), AuthorityError> {
        let payload = self.claims.possession_payload()?;
        match self.claims.subject {
            SubjectKey::P256(key) => {
                let signature =
                    DeviceSignature::from_bytes(&self.possession).map_err(|_| AuthorityError::Possession)?;
                key.verify_domain(POSSESSION_DOMAIN, &payload, &signature)
                    .map_err(|_| AuthorityError::Possession)
            }
            SubjectKey::Ed25519(bytes) => {
                let key = VerifyingKey::from_bytes(&bytes).map_err(|_| AuthorityError::Possession)?;
                if crate::identity::verify_domain(&key, POSSESSION_DOMAIN, &payload, &self.possession) {
                    Ok(())
                } else {
                    Err(AuthorityError::Possession)
                }
            }
        }
    }

    /// Checks the consumer's exact purpose, audience and operation.
    ///
    /// # Errors
    /// Refuses cross-instance, cross-purpose and unlisted operations.
    pub fn authorize(&self, purpose: Purpose, audience: &Audience, operation: &str) -> Result<(), AuthorityError> {
        if purpose != self.claims.purpose
            || !self.claims.audience.permits(audience)
            || !self.claims.operations.iter().any(|item| item == operation)
        {
            return Err(AuthorityError::Scope);
        }
        Ok(())
    }

    /// Encodes a canonical v1 certificate, including its verified possession.
    ///
    /// # Errors
    /// Refuses invalid fields or possession.
    pub fn encode(&self) -> Result<Vec<u8>, AuthorityError> {
        self.verify_possession()?;
        codec::certificate_bytes(self)
    }

    /// Decodes a bounded canonical v1 certificate and verifies possession.
    ///
    /// # Errors
    /// Refuses unknown purposes, noncanonical bytes, invalid claims and proofs.
    pub fn decode(bytes: &[u8]) -> Result<Self, AuthorityError> {
        codec::decode_certificate(bytes)
    }
}

/// Complete, sorted revocation set for one authority epoch.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CertifiedKeyRevocations {
    /// Strictly ascending unique certificate ids.
    pub ids: Vec<CertificateId>,
}

impl CertifiedKeyRevocations {
    /// Encodes the complete canonical versioned revocation set.
    ///
    /// # Errors
    /// Refuses invalid order, duplicates or exceeded bounds.
    pub fn encode(&self) -> Result<Vec<u8>, AuthorityError> {
        codec::revocation_bytes(self)
    }

    /// Decodes a canonical set, bounding counts before allocating.
    ///
    /// # Errors
    /// Refuses unsupported versions, indefinite lengths, noncanonical bytes or
    /// more than 64 ids / 4096 encoded bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, AuthorityError> {
        codec::decode_revocations(bytes)
    }

    /// Checks the per-epoch bound and strict ordering.
    ///
    /// # Errors
    /// Refuses more than 64 ids, duplicates or unsorted ids.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        if self.ids.len() > MAX_REVOCATIONS {
            return Err(AuthorityError::Bound);
        }
        if !self.ids.is_sorted_by(|a, b| a < b) {
            return Err(AuthorityError::Invalid);
        }
        Ok(())
    }

    /// Requires every prior revocation to remain in the new set.
    ///
    /// # Errors
    /// Refuses malformed sets or a removed revocation.
    pub fn extends(&self, previous: &Self) -> Result<(), AuthorityError> {
        self.validate()?;
        previous.validate()?;
        if previous.ids.iter().any(|id| self.ids.binary_search(id).is_err()) {
            return Err(AuthorityError::RevocationRollback);
        }
        Ok(())
    }
}

/// Canonical content signed by the device, excluding signature bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityContent {
    /// Device authority epoch.
    pub epoch: u64,
    /// Durable, never reused revision within this epoch.
    pub revision: u64,
    /// UNIX signing time.
    pub issued_at: u64,
    /// Promised next update, at most seven days later.
    pub next_update: u64,
    /// Sorted live certificate statements.
    pub certificates: Vec<CertifiedKey>,
    /// Complete current-epoch revocation set.
    pub revocations: CertifiedKeyRevocations,
    /// Service claims with their existing shape and bounds.
    pub services: Vec<ServiceAdvert>,
}

/// A device-signed v1 authority manifest.
///
/// Equality compares canonical content, never signature bytes. Equality does
/// not authenticate either input; verify signatures before accepting records.
#[derive(Clone, Debug)]
pub struct AuthorityManifest {
    /// The complete authenticated content.
    pub content: AuthorityContent,
    /// Device's low-s P-256 signature.
    pub signature: DeviceSignature,
}

impl PartialEq for AuthorityManifest {
    fn eq(&self, other: &Self) -> bool {
        self.content == other.content
    }
}

impl Eq for AuthorityManifest {}

impl AuthorityManifest {
    /// Encodes a bounded canonical envelope (does not authenticate its signer).
    ///
    /// # Errors
    /// Refuses malformed content or more than 8192 encoded bytes.
    pub fn encode(&self) -> Result<Vec<u8>, AuthorityError> {
        codec::encode_manifest(self)
    }

    /// Decodes canonical bytes without applying time-dependent acceptance.
    ///
    /// # Errors
    /// Refuses invalid fields, possession, encodings, or exceeded bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, AuthorityError> {
        codec::decode_manifest(bytes)
    }

    /// Verifies this manifest and every embedded certificate's issuer and hive.
    ///
    /// # Errors
    /// Refuses mismatched issuers, invalid signatures or malformed statements.
    pub fn verify(&self, hive: HiveId, key: DevicePublicKey) -> Result<(), AuthorityError> {
        self.content.validate()?;
        let node = device_node_id(key);
        for certificate in &self.content.certificates {
            let claims = &certificate.claims;
            if claims.hive != hive || claims.issuer != node || claims.epoch != self.content.epoch {
                return Err(AuthorityError::Issuer);
            }
        }
        let payload = codec::content_bytes(&self.content)?;
        key.verify_domain(AUTHORITY_DOMAIN, &payload, &self.signature)?;
        self.encode()?;
        Ok(())
    }
}

impl AuthorityContent {
    fn validate(&self) -> Result<(), AuthorityError> {
        if self.revision == 0
            || self.next_update < self.issued_at
            || self.next_update - self.issued_at > MAX_UPDATE_INTERVAL
        {
            return Err(AuthorityError::Invalid);
        }
        if self.certificates.len() > MAX_CERTIFICATES {
            return Err(AuthorityError::Bound);
        }
        self.revocations.validate()?;
        crate::record::validate_services(&self.services)?;
        if !self.certificates.is_sorted_by(|a, b| a.claims.id < b.claims.id) {
            return Err(AuthorityError::ReusedId);
        }
        for certificate in &self.certificates {
            certificate.verify_possession()?;
            if certificate.claims.epoch != self.epoch {
                return Err(AuthorityError::Issuer);
            }
            if self.revocations.ids.binary_search(&certificate.claims.id).is_ok() {
                return Err(AuthorityError::ReusedId);
            }
        }
        Ok(())
    }
}

/// ADR 0003 P-256 node identity, without changing legacy network identity types.
#[must_use]
pub fn device_node_id(key: DevicePublicKey) -> NodeId {
    NodeId::from_bytes(Sha256::digest(key.identity_bytes()).into())
}

fn valid_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
