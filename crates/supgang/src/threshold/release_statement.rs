//! Draft ADR 0007 release-statement wire codec and role-signature checks.
//!
//! This module does not prove a root role grant, status freshness, a carried
//! device assertion, version high-water state, artifact bytes, or key custody.
//! No live release-authority path imports it.

use minicbor::{Decoder, Encoder, data::Type};
use sha2::{Digest as _, Sha256};

use crate::{
    authority::SubjectKey,
    device_key::DeviceSignature,
    ids::HiveId,
    threshold::{
        Digest, Error, array, canonical, count, fixed,
        owner_action::{ACTION_DOMAIN, Assertion, REQUEST_DOMAIN},
        step::role_grant::{ReleasePresence, RoleGrant, RolePolicy},
    },
};

/// Domain prefix for statement digests and role signatures.
pub const DOMAIN: &[u8] = b"supgang/release/v1\0";
/// Maximum complete signed-statement encoding.
pub const MAX_BYTES: usize = 16 * 1024;
const MAX_ARTIFACTS: usize = 16;
const MAX_SIGNERS: usize = 3;
const MAX_LIFETIME: u64 = 30 * 24 * 60 * 60;

/// Bounded `SemVer` pre-release of the exact `label.number` form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreRelease {
    /// One to 32 lowercase ASCII letters.
    pub label: String,
    /// Numeric pre-release component.
    pub number: u64,
}

impl PreRelease {
    fn validate(&self) -> Result<(), Error> {
        if self.label.is_empty() || self.label.len() > 32 || !self.label.bytes().all(|byte| byte.is_ascii_lowercase()) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Version compared by numeric triple, then pre-release label and number.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version {
    /// Major version.
    pub major: u64,
    /// Minor version.
    pub minor: u64,
    /// Patch version.
    pub patch: u64,
    /// `None` is a release, which ranks above any pre-release of the same triple.
    pub pre: Option<PreRelease>,
}

impl Version {
    pub(crate) fn encode_into(&self, e: &mut Encoder<Vec<u8>>) -> Result<(), Error> {
        e.array(4)?.u64(self.major)?.u64(self.minor)?.u64(self.patch)?;
        if let Some(pre) = &self.pre {
            pre.validate()?;
            e.array(2)?.str(&pre.label)?.u64(pre.number)?;
        } else {
            e.null()?;
        }
        Ok(())
    }

    pub(crate) fn decode_from(d: &mut Decoder<'_>) -> Result<Self, Error> {
        array(d, 4)?;
        let major = d.u64()?;
        let minor = d.u64()?;
        let patch = d.u64()?;
        let pre = if d.datatype()? == Type::Null {
            d.null()?;
            None
        } else {
            array(d, 2)?;
            let value = PreRelease {
                label: bounded_text(d, 32)?,
                number: d.u64()?,
            };
            value.validate()?;
            Some(value)
        };
        Ok(Self {
            major,
            minor,
            patch,
            pre,
        })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (Some(_), None) => std::cmp::Ordering::Less,
                (Some(left), Some(right)) => left
                    .label
                    .as_bytes()
                    .cmp(right.label.as_bytes())
                    .then_with(|| left.number.cmp(&right.number)),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// One target artifact, whose bytes the consumer verifies independently.
#[derive(Clone, Eq, PartialEq)]
pub struct Artifact {
    /// Lowercase operating-system label.
    pub os: String,
    /// Lowercase architecture label.
    pub arch: String,
    /// Exact artifact byte length.
    pub length: u64,
    /// SHA-256 of the artifact bytes.
    pub sha256: Digest,
}

impl Artifact {
    fn validate(&self) -> Result<(), Error> {
        if !label(&self.os, 16) || !label(&self.arch, 16) {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    fn encode_into(&self, e: &mut Encoder<Vec<u8>>) -> Result<(), Error> {
        self.validate()?;
        e.array(4)?
            .str(&self.os)?
            .str(&self.arch)?
            .u64(self.length)?
            .bytes(&self.sha256)?;
        Ok(())
    }

    fn decode_from(d: &mut Decoder<'_>) -> Result<Self, Error> {
        array(d, 4)?;
        let result = Self {
            os: bounded_text(d, 16)?,
            arch: bounded_text(d, 16)?,
            length: d.u64()?,
            sha256: fixed(d)?,
        };
        result.validate()?;
        Ok(result)
    }
}

/// Canonical statement content, independent of its signatures or assertion.
#[derive(Clone, Eq, PartialEq)]
pub struct Content {
    /// Founding hive.
    pub hive: HiveId,
    /// Root-granted release role identity.
    pub role_id: [u8; 16],
    /// Exact consumer product identifier.
    pub consumer_id: String,
    /// Consumer-defined package format.
    pub package_format: String,
    /// Exact release channel.
    pub channel: String,
    /// Exact bounded `SemVer` version for this channel.
    pub version: Version,
    /// All target artifacts in ascending `(os, arch)` order.
    pub artifacts: Vec<Artifact>,
    /// Raw 20- or 32-byte source commit identity.
    pub source_commit: Vec<u8>,
    /// Optional consumer-defined provenance digest.
    pub provenance: Option<Digest>,
    /// UNIX issuance second.
    pub issued_at: u64,
    /// Last UNIX second for a new install or update.
    pub expires_at: u64,
}

impl Content {
    fn validate(&self) -> Result<(), Error> {
        if self.consumer_id.is_empty()
            || self.consumer_id.len() > 128
            || self.package_format.is_empty()
            || self.package_format.len() > 64
            || !label(&self.channel, 32)
            || !matches!(self.source_commit.len(), 20 | 32)
            || self.artifacts.is_empty()
            || self.artifacts.len() > MAX_ARTIFACTS
            || self.issued_at > self.expires_at
            || self.expires_at - self.issued_at > MAX_LIFETIME
        {
            return Err(Error::Bound);
        }
        let mut previous: Option<(&str, &str)> = None;
        for artifact in &self.artifacts {
            artifact.validate()?;
            let target = (artifact.os.as_str(), artifact.arch.as_str());
            if previous.is_some_and(|before| before >= target) {
                return Err(Error::Invalid);
            }
            previous = Some(target);
        }
        Ok(())
    }

    /// Encode the exact version-1 CBOR array.
    ///
    /// # Errors
    /// Refuses oversized fields, unordered targets, or invalid lifetime.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut e = Encoder::new(Vec::new());
        e.array(12)?
            .u8(1)?
            .bytes(self.hive.as_bytes())?
            .bytes(&self.role_id)?
            .str(&self.consumer_id)?
            .str(&self.package_format)?
            .str(&self.channel)?;
        self.version.encode_into(&mut e)?;
        e.array(u64::try_from(self.artifacts.len()).map_err(|_| Error::Bound)?)?;
        for artifact in &self.artifacts {
            artifact.encode_into(&mut e)?;
        }
        e.bytes(&self.source_commit)?;
        match self.provenance {
            Some(digest) => {
                e.bytes(&digest)?;
            }
            None => {
                e.null()?;
            }
        }
        e.u64(self.issued_at)?.u64(self.expires_at)?;
        let bytes = e.into_writer();
        if bytes.len() > MAX_BYTES {
            return Err(Error::Bound);
        }
        Ok(bytes)
    }

    /// Decode and re-encode the bounded canonical content.
    ///
    /// # Errors
    /// Refuses unsupported, oversized, trailing, nonminimal or unordered data.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 12)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let hive = HiveId::from_bytes(fixed(&mut d)?);
        let role_id = fixed(&mut d)?;
        let consumer_id = bounded_text(&mut d, 128)?;
        let package_format = bounded_text(&mut d, 64)?;
        let channel = bounded_text(&mut d, 32)?;
        let version = Version::decode_from(&mut d)?;
        let artifact_count = count(&mut d, MAX_ARTIFACTS)?;
        let mut artifacts = Vec::with_capacity(artifact_count);
        for _ in 0..artifact_count {
            artifacts.push(Artifact::decode_from(&mut d)?);
        }
        let source_commit = d.bytes()?;
        if !matches!(source_commit.len(), 20 | 32) {
            return Err(Error::Bound);
        }
        let provenance = if d.datatype()? == Type::Null {
            d.null()?;
            None
        } else {
            Some(fixed(&mut d)?)
        };
        let value = Self {
            hive,
            role_id,
            consumer_id,
            package_format,
            channel,
            version,
            artifacts,
            source_commit: source_commit.to_vec(),
            provenance,
            issued_at: d.u64()?,
            expires_at: d.u64()?,
        };
        canonical(bytes, &value.encode()?)?;
        Ok(value)
    }

    /// SHA-256 of the domain prefix followed by canonical content bytes.
    ///
    /// # Errors
    /// Refuses malformed content.
    pub fn digest(&self) -> Result<Digest, Error> {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(self.encode()?);
        Ok(hash.finalize().into())
    }
}

/// One indexed role signature in strictly ascending signer order.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RoleSignature {
    /// Index in the separately verified root role grant.
    pub signer: u8,
    /// Raw 64-byte P-256 or Ed25519 signature.
    pub bytes: [u8; 64],
}

/// Canonical envelope for a release statement and optional owner assertion.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedStatement {
    /// Exact statement content.
    pub content: Content,
    /// Canonical ADR 0005 assertion for a carried-device role, if present.
    pub assertion: Option<Assertion>,
    /// Sorted, unique indexed role signatures.
    pub signatures: Vec<RoleSignature>,
}

impl SignedStatement {
    /// Check a separately root-validated release role and consumer high-water input.
    ///
    /// Root-chain and status verification, carried assertion grant/challenge,
    /// protected high-water persistence, and artifact hashing remain the
    /// consumer's independent work. `defaults` is the consumer's protected
    /// default-install channel set, never taken from the statement.
    ///
    /// # Errors
    /// Refuses wrong role, channel, version, expiry, signature or presence.
    pub fn check_role_policy(
        &self,
        role: &RoleGrant,
        defaults: &[&str],
        now: u64,
        high_water: Option<&Version>,
    ) -> Result<(), Error> {
        role.encode()?;
        if defaults.len() > 16
            || self.content.hive != role.hive
            || self.content.role_id != role.id
            || self.content.consumer_id != role.consumer
            || now < role.not_before
            || now > role.not_after
            || now < self.content.issued_at
            || now > self.content.expires_at
            || self.content.issued_at < role.not_before
            || self.content.issued_at > role.not_after
        {
            return Err(Error::Authority);
        }
        let RolePolicy::Release {
            package_format,
            channels,
            min_version,
            presence,
        } = &role.policy
        else {
            return Err(Error::Authority);
        };
        if self.content.package_format != *package_format
            || !channels.contains(&self.content.channel)
            || self.content.version < *min_version
            || high_water.is_some_and(|version| self.content.version <= *version)
        {
            return Err(Error::Authority);
        }
        role.check_default_channels(defaults)?;
        let signers = role.signers.iter().map(|signer| signer.key.clone()).collect::<Vec<_>>();
        self.verify_role_signatures(&signers, usize::from(role.threshold))?;
        self.check_release_assertion(*presence == ReleasePresence::CarriedDevice)
    }

    fn validate_signer_indexes(&self) -> Result<(), Error> {
        if self.signatures.is_empty() || self.signatures.len() > MAX_SIGNERS {
            return Err(Error::Bound);
        }
        let mut previous = None;
        for entry in &self.signatures {
            if previous.is_some_and(|before| before >= entry.signer) {
                return Err(Error::Invalid);
            }
            previous = Some(entry.signer);
        }
        Ok(())
    }

    /// Encode the complete bounded version-1 envelope.
    ///
    /// # Errors
    /// Refuses malformed content, assertion, signer order, or size.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate_signer_indexes()?;
        let mut e = Encoder::new(Vec::new());
        e.array(4)?.u8(1)?.bytes(&self.content.encode()?)?;
        match &self.assertion {
            Some(assertion) => {
                e.bytes(&assertion.encode()?)?;
            }
            None => {
                e.null()?;
            }
        }
        e.array(u64::try_from(self.signatures.len()).map_err(|_| Error::Bound)?)?;
        for entry in &self.signatures {
            e.array(2)?.u8(entry.signer)?.bytes(&entry.bytes)?;
        }
        let bytes = e.into_writer();
        if bytes.len() > MAX_BYTES {
            return Err(Error::Bound);
        }
        Ok(bytes)
    }

    /// Decode and re-encode the exact bounded envelope.
    ///
    /// # Errors
    /// Refuses unsupported, oversized, trailing, noncanonical or unordered data.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 4)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let content = Content::decode(d.bytes()?)?;
        let assertion = if d.datatype()? == Type::Null {
            d.null()?;
            None
        } else {
            Some(Assertion::decode(d.bytes()?)?)
        };
        let signer_count = count(&mut d, MAX_SIGNERS)?;
        let mut signatures = Vec::with_capacity(signer_count);
        for _ in 0..signer_count {
            array(&mut d, 2)?;
            signatures.push(RoleSignature {
                signer: d.u8()?,
                bytes: fixed(&mut d)?,
            });
        }
        let value = Self {
            content,
            assertion,
            signatures,
        };
        canonical(bytes, &value.encode()?)?;
        Ok(value)
    }

    /// Verify only role signatures against already root-validated signer keys.
    ///
    /// The caller must independently enforce role identity, kind, channel,
    /// version, status, custody, assertion, and artifact-byte policy.
    ///
    /// # Errors
    /// Refuses invalid thresholds, indexes, keys, or signatures.
    pub fn verify_role_signatures(&self, signers: &[SubjectKey], threshold: usize) -> Result<(), Error> {
        self.validate_signer_indexes()?;
        if signers.is_empty()
            || signers.len() > MAX_SIGNERS
            || threshold == 0
            || threshold > signers.len()
            || self.signatures.len() < threshold
            || self.signatures.len() > signers.len()
        {
            return Err(Error::Bound);
        }
        for (index, signer) in signers.iter().enumerate() {
            if signers.iter().take(index).any(|before| before == signer) {
                return Err(Error::Authority);
            }
        }
        let content = self.content.encode()?;
        let mut prefixed = DOMAIN.to_vec();
        prefixed.extend_from_slice(&content);
        for entry in &self.signatures {
            let signer = signers.get(usize::from(entry.signer)).ok_or(Error::Authority)?;
            match signer {
                SubjectKey::P256(key) => {
                    let signature = DeviceSignature::from_bytes(&entry.bytes).map_err(|_| Error::Proof)?;
                    key.verify_domain(DOMAIN, &content, &signature)
                        .map_err(|_| Error::Proof)?;
                }
                SubjectKey::Ed25519(bytes) => {
                    let key = ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| Error::Proof)?;
                    if key.is_weak() {
                        return Err(Error::Proof);
                    }
                    key.verify_strict(&prefixed, &ed25519_dalek::Signature::from_bytes(&entry.bytes))
                        .map_err(|_| Error::Proof)?;
                }
            }
        }
        Ok(())
    }

    /// Check the signed envelope's assertion presence against the role mode.
    ///
    /// Full assertion and root-grant verification remains the caller's work.
    ///
    /// # Errors
    /// Refuses a null carried-device assertion or an unattended assertion.
    pub const fn check_assertion_presence(&self, carried_device: bool) -> Result<(), Error> {
        if self.assertion.is_some() != carried_device {
            return Err(Error::Authority);
        }
        Ok(())
    }

    /// Check the carried assertion's release role label, digest, and signature.
    ///
    /// This does not verify its root grant, challenge, target, expiry, or nonce
    /// spend, which a consumer must check independently before any effect.
    ///
    /// # Errors
    /// Refuses absent, mismatched, malformed, or forged assertion bytes.
    pub fn check_release_assertion(&self, carried_device: bool) -> Result<(), Error> {
        self.check_assertion_presence(carried_device)?;
        let Some(assertion) = &self.assertion else {
            return Ok(());
        };
        let mut hash = Sha256::new();
        hash.update(REQUEST_DOMAIN);
        hash.update(self.content.digest()?);
        let request_digest: Digest = hash.finalize().into();
        if assertion.hive != self.content.hive
            || assertion.consumer != "org.agenxy.supgang"
            || assertion.operation != "release.sign"
            || assertion.request_digest != request_digest
        {
            return Err(Error::Authority);
        }
        let signature = DeviceSignature::from_bytes(&assertion.signature).map_err(|_| Error::Proof)?;
        assertion
            .signer_key
            .verify_domain(ACTION_DOMAIN, &assertion.payload()?, &signature)
            .map_err(|_| Error::Proof)
    }
}

fn bounded_text(d: &mut Decoder<'_>, maximum: usize) -> Result<String, Error> {
    let text = d.str()?;
    if text.is_empty() || text.len() > maximum {
        return Err(Error::Bound);
    }
    Ok(text.to_owned())
}

fn label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
