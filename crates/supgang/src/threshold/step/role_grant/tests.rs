use ed25519_dalek::SigningKey;
use p256::pkcs8::EncodePrivateKey as _;

use super::*;
use crate::{
    authority::device_node_id,
    device_key::{DeviceSigner as _, FileDeviceKey},
    threshold::{release_statement::PreRelease, step::grant::AnyGrant},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn release_grant(presence: ReleasePresence, custody: SubjectCustody) -> Result<RoleGrant, Box<dyn std::error::Error>> {
    let root = SigningKey::from_bytes(&[3; 32]);
    let key = FileDeviceKey::from_secret_bytes(&[9; 32])?;
    let public = key.public_key();
    let mut grant = RoleGrant {
        hive: HiveId::from_root_verifying_key(&root.verifying_key().to_bytes()),
        id: [4; 16],
        consumer: "org.agenxy.Remap".into(),
        signers: vec![RoleSigner {
            key: SubjectKey::P256(public),
            node: device_node_id(public),
            custody,
            possession: [0; 64],
        }],
        threshold: 1,
        not_before: 1_000,
        not_after: 1_000 + 90 * 24 * 60 * 60,
        issuer_head: [5; 32],
        issuer_sequence: 1,
        policy: RolePolicy::Release {
            package_format: "remap-package-v1".into(),
            channels: vec!["preview".into()],
            min_version: Version {
                major: 0,
                minor: 3,
                patch: 0,
                pre: Some(PreRelease {
                    label: "preview".into(),
                    number: 4,
                }),
            },
            presence,
        },
    };
    sign_grant(&mut grant, &key)?;
    Ok(grant)
}

fn sign_grant(grant: &mut RoleGrant, key: &FileDeviceKey) -> TestResult {
    let message = grant
        .signers
        .first()
        .ok_or_else(|| std::io::Error::other("missing test signer"))?
        .possession_message(grant)?;
    grant
        .signers
        .first_mut()
        .ok_or_else(|| std::io::Error::other("missing test signer"))?
        .possession = key.sign_domain(POSSESSION_DOMAIN, &message)?.to_bytes();
    Ok(())
}

#[test]
fn release_grants_dispatch_and_enforce_unattended_limits() -> TestResult {
    let carried = release_grant(ReleasePresence::CarriedDevice, SubjectCustody::File)?;
    assert_eq!(RoleGrant::decode(&carried.encode()?)?, carried);
    assert!(matches!(AnyGrant::decode(&carried.encode()?)?, AnyGrant::Role(_)));
    let unattended = release_grant(ReleasePresence::Unattended, SubjectCustody::Hardware)?;
    assert_eq!(RoleGrant::decode(&unattended.encode()?)?, unattended);
    unattended.check_default_channels(&["stable"])?;
    assert!(unattended.check_default_channels(&["preview"]).is_err());
    let mut invalid = unattended.clone();
    invalid.not_after += 1;
    assert!(invalid.encode().is_err());
    invalid = unattended;
    invalid.signers.first_mut().ok_or(Error::Invalid)?.custody = SubjectCustody::File;
    assert!(invalid.encode().is_err());
    invalid = carried.clone();
    invalid.signers.first_mut().ok_or(Error::Invalid)?.node = NodeId::from_bytes([8; 32]);
    assert!(invalid.encode().is_err());
    invalid = carried.clone();
    invalid.threshold = 0;
    assert!(invalid.encode().is_err());
    invalid = carried.clone();
    invalid.threshold = 2;
    assert!(invalid.encode().is_err());
    invalid = carried;
    if let RolePolicy::Release {
        channels, min_version, ..
    } = &mut invalid.policy
    {
        channels.push("Preview".into());
        min_version.pre.as_mut().ok_or(Error::Invalid)?.label = "Preview".into();
    }
    assert!(invalid.encode().is_err());
    Ok(())
}

fn code_signing_certificate() -> Result<(Vec<u8>, u64, u64), Box<dyn std::error::Error>> {
    let secret = p256::SecretKey::from_slice(&[9; 32])?;
    let private_der = secret.to_pkcs8_der()?;
    let pair = rcgen::KeyPair::try_from(private_der.as_bytes())?;
    let mut params = rcgen::CertificateParams::default();
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2026, 12, 31);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "org.agenxy.Remap code signing test");
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
    let certificate = params.self_signed(&pair)?;
    let der = certificate.der().to_vec();
    let (_, parsed) =
        x509_parser::parse_x509_certificate(&der).map_err(|_| std::io::Error::other("test certificate parse"))?;
    let start = u64::try_from(parsed.validity().not_before.timestamp())?;
    let end = u64::try_from(parsed.validity().not_after.timestamp())?;
    Ok((der, start, end))
}

#[test]
fn code_signing_grant_requires_matching_self_issued_p256_certificate() -> TestResult {
    let (certificate, start, end) = code_signing_certificate()?;
    let mut grant = release_grant(ReleasePresence::CarriedDevice, SubjectCustody::File)?;
    grant.not_before = start;
    grant.not_after = end;
    grant.policy = RolePolicy::CodeSigning {
        identifiers: vec!["org.agenxy.Remap".into()],
        certificate,
    };
    let key = FileDeviceKey::from_secret_bytes(&[9; 32])?;
    sign_grant(&mut grant, &key)?;
    assert_eq!(RoleGrant::decode(&grant.encode()?)?, grant);
    let mut invalid = grant.clone();
    if let RolePolicy::CodeSigning { identifiers, .. } = &mut invalid.policy {
        identifiers.push("org.agenxy.Remap".into());
    }
    assert!(invalid.encode().is_err());
    invalid = grant.clone();
    if let RolePolicy::CodeSigning { certificate, .. } = &mut invalid.policy {
        *certificate.first_mut().ok_or(Error::Invalid)? ^= 1;
    }
    assert!(invalid.encode().is_err());
    Ok(())
}
