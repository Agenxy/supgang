//! Canonical, allocation-bounded authority CBOR.

use minicbor::{Decoder, Encoder, data::Type};

use super::{
    Audience, AuthorityContent, AuthorityError, AuthorityManifest, CertificateId, CertifiedKey, CertifiedKeyClaims,
    CertifiedKeyRevocations, MAX_CERTIFICATES, MAX_MANIFEST_BYTES, MAX_OPERATION_BYTES, MAX_OPERATIONS,
    MAX_REVOCATIONS, Purpose, SubjectCustody, SubjectKey,
};
use crate::{
    device_key::{DevicePublicKey, DeviceSignature},
    ids::{HiveId, NodeId},
    record::{ServiceAdvert, ServiceName},
};

type Writer = Encoder<Vec<u8>>;

pub(super) fn claims_bytes(claims: &CertifiedKeyClaims) -> Result<Vec<u8>, AuthorityError> {
    let mut e = Encoder::new(Vec::new());
    e.array(11)?;
    write_claims(&mut e, claims)?;
    Ok(e.into_writer())
}

pub(super) fn revocation_bytes(revocations: &CertifiedKeyRevocations) -> Result<Vec<u8>, AuthorityError> {
    revocations.validate()?;
    let mut e = Encoder::new(Vec::new());
    e.array(2)?.u8(1)?.array(length(revocations.ids.len())?)?;
    for id in &revocations.ids {
        e.bytes(id)?;
    }
    let bytes = e.into_writer();
    if bytes.len() > super::MAX_REVOCATION_BYTES {
        return Err(AuthorityError::Bound);
    }
    Ok(bytes)
}

pub(super) fn decode_revocations(bytes: &[u8]) -> Result<CertifiedKeyRevocations, AuthorityError> {
    if bytes.len() > super::MAX_REVOCATION_BYTES {
        return Err(AuthorityError::Bound);
    }
    let mut d = Decoder::new(bytes);
    array(&mut d, 2)?;
    version(&mut d)?;
    let count = count(&mut d, MAX_REVOCATIONS)?;
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        ids.push(fixed(&mut d)?);
    }
    finish(&d, bytes)?;
    let result = CertifiedKeyRevocations { ids };
    if revocation_bytes(&result)? != bytes {
        return Err(AuthorityError::NonCanonical);
    }
    Ok(result)
}

pub(super) fn certificate_bytes(certificate: &CertifiedKey) -> Result<Vec<u8>, AuthorityError> {
    let mut e = Encoder::new(Vec::new());
    write_certificate(&mut e, certificate)?;
    Ok(e.into_writer())
}

fn write_claims(e: &mut Writer, c: &CertifiedKeyClaims) -> Result<(), AuthorityError> {
    e.u8(1)?
        .bytes(c.hive.as_bytes())?
        .array(2)?
        .bytes(c.issuer.as_bytes())?
        .u64(c.epoch)?;
    e.bytes(&c.id)?.array(3)?;
    match c.subject {
        SubjectKey::P256(key) => {
            e.str("p256")?.bytes(&key.to_bytes())?;
        }
        SubjectKey::Ed25519(key) => {
            e.str("ed25519")?.bytes(&key)?;
        }
    }
    e.str(match c.custody {
        SubjectCustody::Hardware => "hardware",
        SubjectCustody::File => "file",
        SubjectCustody::Synced => "synced",
    })?
    .str(c.purpose.text())?;
    write_audience(e, &c.audience)?;
    e.array(length(c.operations.len())?)?;
    for operation in &c.operations {
        e.str(operation)?;
    }
    e.u64(c.not_before)?.u64(c.not_after)?.u16(c.policy)?;
    Ok(())
}

fn write_audience(e: &mut Writer, audience: &Audience) -> Result<(), AuthorityError> {
    match audience {
        Audience::Publish => {
            e.array(1)?.str("publish")?;
        }
        Audience::Service { name, instance } => {
            e.array(3)?.str("service")?.str(name.as_str())?.bytes(instance)?;
        }
        Audience::TransportServer {
            name,
            instance,
            hostname,
        } => {
            e.array(4)?
                .str("transport-server")?
                .str(name.as_str())?
                .bytes(instance)?
                .str(hostname)?;
        }
        Audience::TransportClient { hive, node } => {
            e.array(3)?.str("transport-client")?.bytes(hive.as_bytes())?;
            if let Some(node) = node {
                e.bytes(node.as_bytes())?;
            } else {
                e.null()?;
            }
        }
        Audience::Attest { instance } => {
            e.array(2)?.str("attest")?.bytes(instance)?;
        }
    }
    Ok(())
}

fn write_certificate(e: &mut Writer, certificate: &CertifiedKey) -> Result<(), AuthorityError> {
    e.array(12)?;
    write_claims(e, &certificate.claims)?;
    e.bytes(&certificate.possession)?;
    Ok(())
}

pub(super) fn content_bytes(content: &AuthorityContent) -> Result<Vec<u8>, AuthorityError> {
    content.validate()?;
    let mut e = Encoder::new(Vec::new());
    e.array(8)?
        .u8(1)?
        .u64(content.epoch)?
        .u64(content.revision)?
        .u64(content.issued_at)?
        .u64(content.next_update)?
        .array(length(content.certificates.len())?)?;
    for certificate in &content.certificates {
        write_certificate(&mut e, certificate)?;
    }
    e.array(2)?.u8(1)?.array(length(content.revocations.ids.len())?)?;
    for id in &content.revocations.ids {
        e.bytes(id)?;
    }
    e.array(length(content.services.len())?)?;
    for service in &content.services {
        e.array(3)?
            .str(service.name.as_str())?
            .u16(service.port)?
            .bytes(&service.key_pin)?;
    }
    Ok(e.into_writer())
}

pub(super) fn encode_manifest(manifest: &AuthorityManifest) -> Result<Vec<u8>, AuthorityError> {
    let content = content_bytes(&manifest.content)?;
    let mut e = Encoder::new(Vec::new());
    e.array(3)?
        .u8(1)?
        .bytes(&content)?
        .bytes(&manifest.signature.to_bytes())?;
    let bytes = e.into_writer();
    check_size(&bytes)?;
    Ok(bytes)
}

pub(super) fn decode_manifest(bytes: &[u8]) -> Result<AuthorityManifest, AuthorityError> {
    check_size(bytes)?;
    let mut d = Decoder::new(bytes);
    array(&mut d, 3)?;
    version(&mut d)?;
    let content = read_content(d.bytes()?)?;
    let signature = DeviceSignature::from_bytes(d.bytes()?)?;
    finish(&d, bytes)?;
    let result = AuthorityManifest { content, signature };
    if encode_manifest(&result)? != bytes {
        return Err(AuthorityError::NonCanonical);
    }
    Ok(result)
}

fn read_content(bytes: &[u8]) -> Result<AuthorityContent, AuthorityError> {
    let mut d = Decoder::new(bytes);
    array(&mut d, 8)?;
    version(&mut d)?;
    let epoch = d.u64()?;
    let revision = d.u64()?;
    let issued_at = d.u64()?;
    let next_update = d.u64()?;
    let count = count(&mut d, MAX_CERTIFICATES)?;
    let mut certificates = Vec::with_capacity(count);
    for _ in 0..count {
        certificates.push(read_certificate(&mut d)?);
    }
    array(&mut d, 2)?;
    version(&mut d)?;
    let count = self::count(&mut d, MAX_REVOCATIONS)?;
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        ids.push(fixed::<16>(&mut d)?);
    }
    let count = self::count(&mut d, crate::record::MAX_SERVICE_ADVERTS)?;
    let mut services = Vec::with_capacity(count);
    for _ in 0..count {
        array(&mut d, 3)?;
        services.push(ServiceAdvert {
            name: ServiceName::new(text(&mut d, crate::record::MAX_SERVICE_NAME_BYTES)?)?,
            port: d.u16()?,
            key_pin: fixed(&mut d)?,
        });
    }
    finish(&d, bytes)?;
    let result = AuthorityContent {
        epoch,
        revision,
        issued_at,
        next_update,
        certificates,
        revocations: CertifiedKeyRevocations { ids },
        services,
    };
    result.validate()?;
    Ok(result)
}

pub(super) fn decode_certificate(bytes: &[u8]) -> Result<CertifiedKey, AuthorityError> {
    check_size(bytes)?;
    let mut d = Decoder::new(bytes);
    let result = read_certificate(&mut d)?;
    finish(&d, bytes)?;
    if certificate_bytes(&result)? != bytes {
        return Err(AuthorityError::NonCanonical);
    }
    Ok(result)
}

fn read_certificate(d: &mut Decoder<'_>) -> Result<CertifiedKey, AuthorityError> {
    array(d, 12)?;
    version(d)?;
    let hive = HiveId::from_bytes(fixed(d)?);
    array(d, 2)?;
    let issuer = NodeId::from_bytes(fixed(d)?);
    let epoch = d.u64()?;
    let id: CertificateId = fixed(d)?;
    array(d, 3)?;
    let subject = match d.str()? {
        "p256" => SubjectKey::P256(DevicePublicKey::from_bytes(d.bytes()?)?),
        "ed25519" => SubjectKey::Ed25519(fixed(d)?),
        _ => return Err(AuthorityError::Invalid),
    };
    let custody = match d.str()? {
        "hardware" => SubjectCustody::Hardware,
        "file" => SubjectCustody::File,
        "synced" => SubjectCustody::Synced,
        _ => return Err(AuthorityError::Invalid),
    };
    let purpose = Purpose::parse(d.str()?)?;
    let audience = read_audience(d, purpose)?;
    let count = count(d, MAX_OPERATIONS)?;
    let mut operations = Vec::with_capacity(count);
    for _ in 0..count {
        operations.push(text(d, MAX_OPERATION_BYTES)?);
    }
    let not_before = d.u64()?;
    let not_after = d.u64()?;
    let policy = d.u16()?;
    let possession = fixed(d)?;
    let claims = CertifiedKeyClaims {
        hive,
        issuer,
        epoch,
        id,
        subject,
        custody,
        purpose,
        audience,
        operations,
        not_before,
        not_after,
        policy,
    };
    let certificate = CertifiedKey { claims, possession };
    certificate.verify_possession()?;
    Ok(certificate)
}

fn read_audience(d: &mut Decoder<'_>, purpose: Purpose) -> Result<Audience, AuthorityError> {
    let fields = d.array()?.ok_or(AuthorityError::Invalid)?;
    let tag = Purpose::parse(d.str()?)?;
    if tag != purpose {
        return Err(AuthorityError::Scope);
    }
    match (tag, fields) {
        (Purpose::Publish, 1) => Ok(Audience::Publish),
        (Purpose::Service, 3) => Ok(Audience::Service {
            name: ServiceName::new(text(d, crate::record::MAX_SERVICE_NAME_BYTES)?)?,
            instance: fixed(d)?,
        }),
        (Purpose::TransportServer, 4) => Ok(Audience::TransportServer {
            name: ServiceName::new(text(d, crate::record::MAX_SERVICE_NAME_BYTES)?)?,
            instance: fixed(d)?,
            hostname: text(d, 253)?,
        }),
        (Purpose::TransportClient, 3) => {
            let hive = HiveId::from_bytes(fixed(d)?);
            let node = if d.datatype()? == Type::Null {
                d.null()?;
                None
            } else {
                Some(NodeId::from_bytes(fixed(d)?))
            };
            Ok(Audience::TransportClient { hive, node })
        }
        (Purpose::Attest, 2) => Ok(Audience::Attest { instance: fixed(d)? }),
        _ => Err(AuthorityError::Scope),
    }
}

pub(super) fn array(d: &mut Decoder<'_>, fields: u64) -> Result<(), AuthorityError> {
    if d.array()? == Some(fields) {
        Ok(())
    } else {
        Err(AuthorityError::Invalid)
    }
}

pub(super) fn count(d: &mut Decoder<'_>, maximum: usize) -> Result<usize, AuthorityError> {
    let value = usize::try_from(d.array()?.ok_or(AuthorityError::Invalid)?).map_err(|_| AuthorityError::Bound)?;
    if value > maximum {
        return Err(AuthorityError::Bound);
    }
    Ok(value)
}

pub(super) fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], AuthorityError> {
    d.bytes()?.try_into().map_err(|_| AuthorityError::Invalid)
}

pub(super) fn finish(d: &Decoder<'_>, bytes: &[u8]) -> Result<(), AuthorityError> {
    if d.position() == bytes.len() {
        Ok(())
    } else {
        Err(AuthorityError::NonCanonical)
    }
}

pub(super) fn version(d: &mut Decoder<'_>) -> Result<(), AuthorityError> {
    if d.u8()? == 1 {
        Ok(())
    } else {
        Err(AuthorityError::Version)
    }
}

pub(super) fn length(size: usize) -> Result<u64, AuthorityError> {
    u64::try_from(size).map_err(|_| AuthorityError::Bound)
}

fn text(d: &mut Decoder<'_>, maximum: usize) -> Result<String, AuthorityError> {
    let text = d.str()?;
    if text.len() > maximum {
        return Err(AuthorityError::Bound);
    }
    Ok(text.to_owned())
}

const fn check_size(bytes: &[u8]) -> Result<(), AuthorityError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        Err(AuthorityError::Bound)
    } else {
        Ok(())
    }
}
