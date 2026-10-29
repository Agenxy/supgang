//! Offline ADR 0007 release and code-signing grants under the shared root step.
//!
//! A custody label is a root-enrolled claim, never hardware attestation. No
//! runtime release authority is enabled by decoding these records.

use minicbor::{Decoder, Encoder};
use p256::elliptic_curve::sec1::ToSec1Point as _;

use super::grant::Kind;
use crate::{
    authority::{SubjectCustody, SubjectKey},
    device_key::{DevicePublicKey, DeviceSignature},
    ids::{HiveId, NodeId},
    threshold::{Digest, Error, array, canonical, count, fixed, release_statement::Version, status::Status},
};

const POSSESSION_DOMAIN: &[u8] = b"supgang/role-possession/v1\0";
const MAX_GRANT_BYTES: usize = 12 * 1024;
const MAX_LIFETIME: u64 = 366 * 24 * 60 * 60;
const MAX_UNATTENDED_LIFETIME: u64 = 90 * 24 * 60 * 60;
const MAX_SIGNERS: usize = 3;
const MAX_CHANNELS: usize = 4;
const MAX_IDENTIFIERS: usize = 8;
const MAX_CERTIFICATE_BYTES: usize = 4096;

/// An enrolled role signer and its proof of key possession.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleSigner {
    /// P-256 or Ed25519 public key.
    pub key: SubjectKey,
    /// Member device holding the role key.
    pub node: NodeId,
    /// Root-enrolled custody label; `synced` is forbidden for roles.
    pub custody: SubjectCustody,
    /// Exact 64-byte possession signature over this grant identity and signer.
    pub possession: [u8; 64],
}

impl RoleSigner {
    fn algorithm_and_key(&self) -> (&'static str, Vec<u8>) {
        match &self.key {
            SubjectKey::P256(key) => ("p256", key.to_bytes().to_vec()),
            SubjectKey::Ed25519(key) => ("ed25519", key.to_vec()),
        }
    }

    /// Canonical message proved by the signer's own key.
    ///
    /// # Errors
    /// Refuses invalid grant fields.
    pub fn possession_message(&self, grant: &RoleGrant) -> Result<Vec<u8>, Error> {
        let (algorithm, key) = self.algorithm_and_key();
        let mut e = Encoder::new(Vec::new());
        e.array(10)?
            .u8(1)?
            .bytes(grant.hive.as_bytes())?
            .bytes(&grant.id)?
            .str(grant.kind().text())?
            .str(&grant.consumer)?
            .str(algorithm)?
            .bytes(&key)?
            .bytes(self.node.as_bytes())?
            .str("role-key")?
            .str(custody_text(self.custody))?;
        Ok(e.into_writer())
    }

    fn verify_possession(&self, grant: &RoleGrant) -> Result<(), Error> {
        if self.custody == SubjectCustody::Synced {
            return Err(Error::Authority);
        }
        let message = self.possession_message(grant)?;
        match &self.key {
            SubjectKey::P256(key) => {
                let signature = DeviceSignature::from_bytes(&self.possession).map_err(|_| Error::Proof)?;
                key.verify_domain(POSSESSION_DOMAIN, &message, &signature)
                    .map_err(|_| Error::Proof)
            }
            SubjectKey::Ed25519(bytes) => {
                let key = ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| Error::Proof)?;
                if key.is_weak() {
                    return Err(Error::Proof);
                }
                let mut prefixed = POSSESSION_DOMAIN.to_vec();
                prefixed.extend_from_slice(&message);
                key.verify_strict(&prefixed, &ed25519_dalek::Signature::from_bytes(&self.possession))
                    .map_err(|_| Error::Proof)
            }
        }
    }

    fn encode_into(&self, e: &mut Encoder<Vec<u8>>) -> Result<(), Error> {
        let (algorithm, key) = self.algorithm_and_key();
        e.array(6)?
            .str(algorithm)?
            .bytes(&key)?
            .bytes(self.node.as_bytes())?
            .str("role-key")?
            .str(custody_text(self.custody))?
            .bytes(&self.possession)?;
        Ok(())
    }

    fn decode_from(d: &mut Decoder<'_>) -> Result<Self, Error> {
        array(d, 6)?;
        let key = match d.str()? {
            "p256" => SubjectKey::P256(DevicePublicKey::from_bytes(d.bytes()?).map_err(|_| Error::Invalid)?),
            "ed25519" => SubjectKey::Ed25519(fixed(d)?),
            _ => return Err(Error::Invalid),
        };
        let node = NodeId::from_bytes(fixed(d)?);
        if d.str()? != "role-key" {
            return Err(Error::Authority);
        }
        Ok(Self {
            key,
            node,
            custody: parse_custody(d.str()?)?,
            possession: fixed(d)?,
        })
    }
}

/// Whether every release statement needs a fresh carried-device assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleasePresence {
    /// Fresh owner approval for every release.
    CarriedDevice,
    /// A bounded role may sign without a prompt on opt-in channels.
    Unattended,
}

impl ReleasePresence {
    const fn text(self) -> &'static str {
        match self {
            Self::CarriedDevice => "carried-device",
            Self::Unattended => "unattended",
        }
    }

    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "carried-device" => Ok(Self::CarriedDevice),
            "unattended" => Ok(Self::Unattended),
            _ => Err(Error::Invalid),
        }
    }
}

/// Closed kind-specific role policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RolePolicy {
    /// Exact package format, opt-in channels, version floor and presence mode.
    Release {
        /// Consumer-defined package format.
        package_format: String,
        /// Strictly sorted, unique channels.
        channels: Vec<String>,
        /// Minimum accepted version.
        min_version: Version,
        /// Owner-approved release signing presence mode.
        presence: ReleasePresence,
    },
    /// Exact signing identifiers and pinned self-issued certificate.
    CodeSigning {
        /// Strictly sorted, unique code-signing identifiers.
        identifiers: Vec<String>,
        /// DER certificate, at most 4096 bytes.
        certificate: Vec<u8>,
    },
}

/// Root-authorized release or code-signing role, never an enabled runtime path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleGrant {
    /// Founding hive.
    pub hive: HiveId,
    /// Random, never-reused role identity.
    pub id: [u8; 16],
    /// Exact consumer product identifier.
    pub consumer: String,
    /// Sorted role signers and possession proofs.
    pub signers: Vec<RoleSigner>,
    /// Required number of role signatures.
    pub threshold: u8,
    /// First permitted UNIX second.
    pub not_before: u64,
    /// Last permitted UNIX second.
    pub not_after: u64,
    /// Authenticated root-step predecessor.
    pub issuer_head: Digest,
    /// Authenticated predecessor sequence.
    pub issuer_sequence: u64,
    /// Kind-specific role policy.
    pub policy: RolePolicy,
}

impl RoleGrant {
    /// Closed role kind derived from the payload.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        match self.policy {
            RolePolicy::Release { .. } => Kind::Release,
            RolePolicy::CodeSigning { .. } => Kind::CodeSigning,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if self.id == [0; 16]
            || self.consumer.is_empty()
            || self.consumer.len() > 128
            || self.not_before >= self.not_after
            || self.not_after - self.not_before > MAX_LIFETIME
            || self.signers.is_empty()
            || self.signers.len() > MAX_SIGNERS
            || self.threshold == 0
            || usize::from(self.threshold) > self.signers.len()
        {
            return Err(Error::Bound);
        }
        let mut previous: Option<(&str, Vec<u8>)> = None;
        for (index, signer) in self.signers.iter().enumerate() {
            let (algorithm, key) = signer.algorithm_and_key();
            if previous.as_ref().is_some_and(|(before_algorithm, before_key)| {
                (*before_algorithm, before_key.as_slice()) >= (algorithm, key.as_slice())
            }) || self
                .signers
                .iter()
                .take(index)
                .any(|before| before.algorithm_and_key().1 == key)
            {
                return Err(Error::Invalid);
            }
            signer.verify_possession(self)?;
            previous = Some((algorithm, key));
        }
        match &self.policy {
            RolePolicy::Release {
                package_format,
                channels,
                min_version,
                presence,
            } => {
                if package_format.is_empty()
                    || package_format.len() > 64
                    || !ordered_labels(channels, MAX_CHANNELS, valid_channel)
                {
                    return Err(Error::Bound);
                }
                min_version.encode_into(&mut Encoder::new(Vec::new()))?;
                if *presence == ReleasePresence::Unattended
                    && (self.not_after - self.not_before > MAX_UNATTENDED_LIFETIME
                        || self
                            .signers
                            .iter()
                            .any(|signer| signer.custody != SubjectCustody::Hardware))
                {
                    return Err(Error::Authority);
                }
            }
            RolePolicy::CodeSigning {
                identifiers,
                certificate,
            } => {
                if !ordered_labels(identifiers, MAX_IDENTIFIERS, valid_identifier)
                    || certificate.is_empty()
                    || certificate.len() > MAX_CERTIFICATE_BYTES
                    || !self
                        .signers
                        .iter()
                        .any(|signer| matches!(signer.key, SubjectKey::P256(_)))
                {
                    return Err(Error::Bound);
                }
                self.verify_certificate(certificate)?;
            }
        }
        Ok(())
    }

    /// Encode one exact 12-field typed grant.
    ///
    /// # Errors
    /// Refuses malformed, unproved, unordered, or unbounded role policy.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut e = Encoder::new(Vec::new());
        e.array(12)?
            .u8(1)?
            .bytes(self.hive.as_bytes())?
            .bytes(&self.id)?
            .str(self.kind().text())?
            .str(&self.consumer)?
            .array(u64::try_from(self.signers.len()).map_err(|_| Error::Bound)?)?;
        for signer in &self.signers {
            signer.encode_into(&mut e)?;
        }
        e.u8(self.threshold)?
            .u64(self.not_before)?
            .u64(self.not_after)?
            .bytes(&self.issuer_head)?
            .u64(self.issuer_sequence)?;
        match &self.policy {
            RolePolicy::Release {
                package_format,
                channels,
                min_version,
                presence,
            } => {
                e.array(4)?
                    .str(package_format)?
                    .array(u64::try_from(channels.len()).map_err(|_| Error::Bound)?)?;
                for channel in channels {
                    e.str(channel)?;
                }
                min_version.encode_into(&mut e)?;
                e.str(presence.text())?;
            }
            RolePolicy::CodeSigning {
                identifiers,
                certificate,
            } => {
                e.array(2)?
                    .array(u64::try_from(identifiers.len()).map_err(|_| Error::Bound)?)?;
                for identifier in identifiers {
                    e.str(identifier)?;
                }
                e.bytes(certificate)?;
            }
        }
        let bytes = e.into_writer();
        if bytes.len() > MAX_GRANT_BYTES {
            return Err(Error::Bound);
        }
        Ok(bytes)
    }

    /// Decode the exact bounded root role grant and verify all signer proofs.
    ///
    /// # Errors
    /// Refuses noncanonical, unsupported, malformed, or unproved bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_GRANT_BYTES {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 12)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let hive = HiveId::from_bytes(fixed(&mut d)?);
        let id = fixed(&mut d)?;
        let kind = Kind::parse(d.str()?)?;
        if kind == Kind::OwnerAction {
            return Err(Error::Invalid);
        }
        let consumer = bounded_text(&mut d, 128)?;
        let signer_count = count(&mut d, MAX_SIGNERS)?;
        let mut signers = Vec::with_capacity(signer_count);
        for _ in 0..signer_count {
            signers.push(RoleSigner::decode_from(&mut d)?);
        }
        let threshold = d.u8()?;
        let not_before = d.u64()?;
        let not_after = d.u64()?;
        let issuer_head = fixed(&mut d)?;
        let issuer_sequence = d.u64()?;
        let policy = match kind {
            Kind::Release => {
                array(&mut d, 4)?;
                let package_format = bounded_text(&mut d, 64)?;
                let channel_count = count(&mut d, MAX_CHANNELS)?;
                let mut channels = Vec::with_capacity(channel_count);
                for _ in 0..channel_count {
                    channels.push(bounded_text(&mut d, 32)?);
                }
                RolePolicy::Release {
                    package_format,
                    channels,
                    min_version: Version::decode_from(&mut d)?,
                    presence: ReleasePresence::parse(d.str()?)?,
                }
            }
            Kind::CodeSigning => {
                array(&mut d, 2)?;
                let identifier_count = count(&mut d, MAX_IDENTIFIERS)?;
                let mut identifiers = Vec::with_capacity(identifier_count);
                for _ in 0..identifier_count {
                    identifiers.push(bounded_text(&mut d, 255)?);
                }
                let certificate = d.bytes()?;
                if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES {
                    return Err(Error::Bound);
                }
                RolePolicy::CodeSigning {
                    identifiers,
                    certificate: certificate.to_vec(),
                }
            }
            Kind::OwnerAction => return Err(Error::Invalid),
        };
        let result = Self {
            hive,
            id,
            consumer,
            signers,
            threshold,
            not_before,
            not_after,
            issuer_head,
            issuer_sequence,
            policy,
        };
        canonical(bytes, &result.encode()?)?;
        Ok(result)
    }

    /// Check channels against a consumer's independently protected default set.
    ///
    /// The provider cannot infer the consumer's defaults from grant bytes.
    ///
    /// # Errors
    /// Refuses an unattended channel installed by default.
    pub fn check_default_channels(&self, defaults: &[&str]) -> Result<(), Error> {
        if defaults.len() > 16 {
            return Err(Error::Bound);
        }
        if let RolePolicy::Release {
            channels,
            presence: ReleasePresence::Unattended,
            ..
        } = &self.policy
            && channels.iter().any(|channel| defaults.contains(&channel.as_str()))
        {
            return Err(Error::Authority);
        }
        Ok(())
    }

    /// Require this grant and every role signer device in a verified status.
    ///
    /// The caller authenticates the status root signature and freshness first.
    ///
    /// # Errors
    /// Refuses a missing grant or member device.
    pub fn check_active_status(&self, status: &Status) -> Result<(), Error> {
        self.validate()?;
        if status.hive != self.hive {
            return Err(Error::Authority);
        }
        let nodes = self.signers.iter().map(|signer| signer.node).collect::<Vec<_>>();
        status.check_active_grant(&self.id, &nodes)
    }

    /// Check one consumer-supplied code-signing identifier by exact equality.
    ///
    /// # Errors
    /// Refuses a different kind or an identifier absent from the root grant.
    pub fn check_code_signing_identifier(&self, identifier: &str) -> Result<(), Error> {
        let RolePolicy::CodeSigning { identifiers, .. } = &self.policy else {
            return Err(Error::Authority);
        };
        if identifiers.iter().any(|allowed| allowed == identifier) {
            Ok(())
        } else {
            Err(Error::Authority)
        }
    }

    fn verify_certificate(&self, bytes: &[u8]) -> Result<(), Error> {
        let (remaining, certificate) = x509_parser::parse_x509_certificate(bytes).map_err(|_| Error::Invalid)?;
        if !remaining.is_empty() || certificate.subject() != certificate.issuer() {
            return Err(Error::Authority);
        }
        let expected_cn = format!(
            "{} code signing {}",
            self.consumer,
            hex::encode(self.id.get(..4).ok_or(Error::Invalid)?)
        );
        let mut common_names = certificate.subject().iter_common_name();
        if common_names.next().and_then(|name| name.as_str().ok()) != Some(expected_cn.as_str())
            || common_names.next().is_some()
        {
            return Err(Error::Authority);
        }
        certificate.verify_signature(None).map_err(|_| Error::Proof)?;
        let key_usage = certificate
            .key_usage()
            .map_err(|_| Error::Invalid)?
            .ok_or(Error::Authority)?;
        let extended = certificate
            .extended_key_usage()
            .map_err(|_| Error::Invalid)?
            .ok_or(Error::Authority)?;
        if key_usage.value.flags != 1
            || !extended.value.code_signing
            || extended.value.any
            || extended.value.server_auth
            || extended.value.client_auth
            || extended.value.email_protection
            || extended.value.time_stamping
            || extended.value.ocsp_signing
            || !extended.value.other.is_empty()
        {
            return Err(Error::Authority);
        }
        let start = u64::try_from(certificate.validity().not_before.timestamp()).map_err(|_| Error::Bound)?;
        let end = u64::try_from(certificate.validity().not_after.timestamp()).map_err(|_| Error::Bound)?;
        if start < self.not_before || end > self.not_after || start >= end {
            return Err(Error::Authority);
        }
        let spki = certificate.public_key();
        if spki.algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1"
            || spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|value| value.as_oid().ok())
                .is_none_or(|curve| curve.to_id_string() != "1.2.840.10045.3.1.7")
        {
            return Err(Error::Authority);
        }
        let point =
            p256::PublicKey::from_sec1_bytes(spki.subject_public_key.data.as_ref()).map_err(|_| Error::Proof)?;
        let encoded = point.to_sec1_point(true);
        if !self.signers.iter().any(
            |signer| matches!(&signer.key, SubjectKey::P256(key) if key.to_bytes().as_slice() == encoded.as_bytes()),
        ) {
            return Err(Error::Authority);
        }
        Ok(())
    }
}

fn bounded_text(d: &mut Decoder<'_>, maximum: usize) -> Result<String, Error> {
    let value = d.str()?;
    if value.is_empty() || value.len() > maximum {
        return Err(Error::Bound);
    }
    Ok(value.to_owned())
}

fn ordered_labels(values: &[String], maximum: usize, valid: fn(&str) -> bool) -> bool {
    !values.is_empty()
        && values.len() <= maximum
        && values.iter().all(|value| valid(value))
        && values.windows(2).all(|pair| pair.first() < pair.get(1))
}

fn valid_channel(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

const fn custody_text(value: SubjectCustody) -> &'static str {
    match value {
        SubjectCustody::Hardware => "hardware",
        SubjectCustody::File => "file",
        SubjectCustody::Synced => "synced",
    }
}

fn parse_custody(value: &str) -> Result<SubjectCustody, Error> {
    match value {
        "hardware" => Ok(SubjectCustody::Hardware),
        "file" => Ok(SubjectCustody::File),
        "synced" => Ok(SubjectCustody::Synced),
        _ => Err(Error::Invalid),
    }
}

#[cfg(test)]
mod tests;
