//! Canonical wire fixtures at each implemented role-grant upper bound.
//!
//! Invalid records are encoded without the production validator so a generic
//! CBOR reader still accepts their structure before the role decoder refuses.

use minicbor::Encoder;

use super::{TestResult, save};
use crate::{
    authority::{SubjectCustody, SubjectKey, device_node_id},
    device_key::{DeviceSigner as _, FileDeviceKey},
    threshold::{
        Error,
        step::role_grant::{RoleGrant, RolePolicy, RoleSigner},
    },
};
use std::path::Path;

pub(super) fn raw_role(role: &RoleGrant) -> Result<Vec<u8>, Error> {
    let mut e = Encoder::new(Vec::new());
    e.array(12)?
        .u8(1)?
        .bytes(role.hive.as_bytes())?
        .bytes(&role.id)?
        .str(role.kind().text())?
        .str(&role.consumer)?
        .array(u64::try_from(role.signers.len()).map_err(|_| Error::Bound)?)?;
    for signer in &role.signers {
        let (algorithm, key) = match &signer.key {
            SubjectKey::P256(key) => ("p256", key.to_bytes().to_vec()),
            SubjectKey::Ed25519(key) => ("ed25519", key.to_vec()),
        };
        let custody = match signer.custody {
            SubjectCustody::Hardware => "hardware",
            SubjectCustody::File => "file",
            SubjectCustody::Synced => "synced",
        };
        e.array(6)?
            .str(algorithm)?
            .bytes(&key)?
            .bytes(signer.node.as_bytes())?
            .str("role-key")?
            .str(custody)?
            .bytes(&signer.possession)?;
    }
    e.u8(role.threshold)?
        .u64(role.not_before)?
        .u64(role.not_after)?
        .bytes(&role.issuer_head)?
        .u64(role.issuer_sequence)?;
    match &role.policy {
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
            e.array(4)?
                .u64(min_version.major)?
                .u64(min_version.minor)?
                .u64(min_version.patch)?;
            if let Some(pre) = &min_version.pre {
                e.array(2)?.str(&pre.label)?.u64(pre.number)?;
            } else {
                e.null()?;
            }
            e.str(match presence {
                crate::threshold::step::role_grant::ReleasePresence::CarriedDevice => "carried-device",
                crate::threshold::step::role_grant::ReleasePresence::Unattended => "unattended",
            })?;
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
    Ok(e.into_writer())
}

fn pair(
    output: &Path,
    records: &mut Vec<serde_json::Value>,
    name: &str,
    maximum: &RoleGrant,
    over: &RoleGrant,
) -> TestResult {
    save(
        output,
        records,
        &format!("edge-{name}-max.cbor"),
        &maximum.encode()?,
        &format!("accept: {name} at maximum"),
    )?;
    save(
        output,
        records,
        &format!("edge-{name}-over.cbor"),
        &raw_role(over)?,
        &format!("reject: {name} just past maximum"),
    )
}

fn resign_one(role: &mut RoleGrant, secret: u8) -> TestResult {
    let signer = FileDeviceKey::from_secret_bytes(&[secret; 32])?;
    let message = role.signers.first().ok_or(Error::Invalid)?.possession_message(role)?;
    role.signers.first_mut().ok_or(Error::Invalid)?.possession = signer
        .sign_domain(b"supgang/role-possession/v1\0", &message)?
        .to_bytes();
    Ok(())
}

pub(super) fn three_signers(role: &RoleGrant) -> Result<RoleGrant, Box<dyn std::error::Error>> {
    let mut pairs = Vec::new();
    for secret in [9_u8, 10, 12] {
        let key = FileDeviceKey::from_secret_bytes(&[secret; 32])?;
        let public = key.public_key();
        pairs.push((
            RoleSigner {
                key: SubjectKey::P256(public),
                node: device_node_id(public),
                custody: SubjectCustody::File,
                possession: [0; 64],
            },
            key,
        ));
    }
    pairs.sort_by(|(left, _), (right, _)| {
        let SubjectKey::P256(left) = &left.key else {
            return std::cmp::Ordering::Equal;
        };
        let SubjectKey::P256(right) = &right.key else {
            return std::cmp::Ordering::Equal;
        };
        left.to_bytes().cmp(&right.to_bytes())
    });
    let mut result = role.clone();
    result.signers = pairs.iter().map(|(signer, _)| signer.clone()).collect();
    result.threshold = 3;
    let messages = result
        .signers
        .iter()
        .map(|signer| signer.possession_message(&result))
        .collect::<Result<Vec<_>, _>>()?;
    for ((signer, (_, key)), message) in result.signers.iter_mut().zip(&pairs).zip(messages) {
        signer.possession = key.sign_domain(b"supgang/role-possession/v1\0", &message)?.to_bytes();
    }
    Ok(result)
}

/// Add role-grant limit fixtures to the single release-role manifest.
pub(super) fn write_edge_fixtures(
    output: &Path,
    records: &mut Vec<serde_json::Value>,
    release: &RoleGrant,
    unattended: &RoleGrant,
    code_signing: &RoleGrant,
    edge_certificate: &[u8],
) -> TestResult {
    let mut valid = release.clone();
    valid.consumer = "x".repeat(128);
    resign_one(&mut valid, 9)?;
    let mut invalid = valid.clone();
    invalid.consumer.push('x');
    resign_one(&mut invalid, 9)?;
    pair(output, records, "consumer-bytes", &valid, &invalid)?;

    valid = release.clone();
    valid.not_after = valid.not_before + 366 * 24 * 60 * 60;
    invalid = valid.clone();
    invalid.not_after += 1;
    pair(output, records, "validity-seconds", &valid, &invalid)?;

    valid = release.clone();
    if let RolePolicy::Release { package_format, .. } = &mut valid.policy {
        *package_format = "p".repeat(64);
    }
    invalid = valid.clone();
    if let RolePolicy::Release { package_format, .. } = &mut invalid.policy {
        package_format.push('p');
    }
    pair(output, records, "package-bytes", &valid, &invalid)?;

    valid = release.clone();
    if let RolePolicy::Release { channels, .. } = &mut valid.policy {
        *channels = vec!["a".repeat(32)];
    }
    invalid = valid.clone();
    if let RolePolicy::Release { channels, .. } = &mut invalid.policy {
        channels.first_mut().ok_or(Error::Invalid)?.push('a');
    }
    pair(output, records, "channel-bytes", &valid, &invalid)?;

    valid = release.clone();
    if let RolePolicy::Release { channels, .. } = &mut valid.policy {
        *channels = ["alpha", "beta", "gamma", "preview"]
            .into_iter()
            .map(str::to_owned)
            .collect();
    }
    invalid = valid.clone();
    if let RolePolicy::Release { channels, .. } = &mut invalid.policy {
        channels.push("zeta".into());
    }
    pair(output, records, "channels-count", &valid, &invalid)?;

    valid = release.clone();
    if let RolePolicy::Release { min_version, .. } = &mut valid.policy {
        min_version.pre.as_mut().ok_or(Error::Invalid)?.label = "a".repeat(32);
    }
    invalid = valid.clone();
    if let RolePolicy::Release { min_version, .. } = &mut invalid.policy {
        min_version.pre.as_mut().ok_or(Error::Invalid)?.label.push('a');
    }
    pair(output, records, "prerelease-label-bytes", &valid, &invalid)?;

    valid = unattended.clone();
    valid.not_after = valid.not_before + 90 * 24 * 60 * 60;
    invalid = valid.clone();
    invalid.not_after += 1;
    pair(output, records, "unattended-validity-seconds", &valid, &invalid)?;

    valid = three_signers(release)?;
    invalid = valid.clone();
    invalid
        .signers
        .push(invalid.signers.first().ok_or(Error::Invalid)?.clone());
    pair(output, records, "signers-count", &valid, &invalid)?;
    invalid = valid.clone();
    invalid.threshold = 4;
    pair(output, records, "threshold-count", &valid, &invalid)?;

    valid = code_signing.clone();
    if let RolePolicy::CodeSigning { identifiers, .. } = &mut valid.policy {
        *identifiers = (0..8).map(|index| format!("org.agenxy.id{index}")).collect();
    }
    invalid = valid.clone();
    if let RolePolicy::CodeSigning { identifiers, .. } = &mut invalid.policy {
        identifiers.push("org.agenxy.id8".into());
    }
    pair(output, records, "identifiers-count", &valid, &invalid)?;

    valid = code_signing.clone();
    if let RolePolicy::CodeSigning { identifiers, .. } = &mut valid.policy {
        *identifiers = vec!["a".repeat(255)];
    }
    invalid = valid.clone();
    if let RolePolicy::CodeSigning { identifiers, .. } = &mut invalid.policy {
        identifiers.first_mut().ok_or(Error::Invalid)?.push('a');
    }
    pair(output, records, "identifier-bytes", &valid, &invalid)?;

    valid = code_signing.clone();
    if let RolePolicy::CodeSigning { certificate, .. } = &mut valid.policy {
        *certificate = edge_certificate.to_vec();
    }
    resign_one(&mut valid, 14)?;
    invalid = valid.clone();
    if let RolePolicy::CodeSigning { certificate, .. } = &mut invalid.policy {
        certificate.push(0);
    }
    pair(output, records, "certificate-bytes", &valid, &invalid)?;
    Ok(())
}
