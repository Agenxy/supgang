use ed25519_dalek::Signer as _;
use sha2::{Digest as _, Sha256};

use crate::{
    authority::{SubjectKey, device_node_id},
    device_key::{DeviceSigner as _, FileDeviceKey},
    ids::{HiveId, NodeId},
    threshold::{
        owner_action::{ACTION_DOMAIN, Assertion, REQUEST_DOMAIN},
        release_statement::{
            Artifact, Content, DOMAIN, MAX_BYTES, PreRelease, RoleSignature, SignedStatement, Version,
        },
    },
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn content() -> Content {
    let root = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    Content {
        hive: HiveId::from_root_verifying_key(&root.verifying_key().to_bytes()),
        role_id: [4; 16],
        consumer_id: "org.agenxy.Remap".into(),
        package_format: "remap-package-v1".into(),
        channel: "preview".into(),
        version: Version {
            major: 0,
            minor: 3,
            patch: 0,
            pre: Some(PreRelease {
                label: "preview".into(),
                number: 4,
            }),
        },
        artifacts: vec![
            Artifact {
                os: "macos".into(),
                arch: "aarch64".into(),
                length: 123,
                sha256: [5; 32],
            },
            Artifact {
                os: "macos".into(),
                arch: "x86-64".into(),
                length: 456,
                sha256: [6; 32],
            },
        ],
        source_commit: vec![7; 20],
        provenance: Some([8; 32]),
        issued_at: 1_000,
        expires_at: 1_000 + 30 * 24 * 60 * 60,
    }
}

fn carried_assertion(content: &Content) -> Result<Assertion, Box<dyn std::error::Error>> {
    let signer = FileDeviceKey::from_secret_bytes(&[11; 32])?;
    let mut request_hash = Sha256::new();
    request_hash.update(REQUEST_DOMAIN);
    request_hash.update(content.encode()?);
    let mut assertion = Assertion {
        hive: content.hive,
        signer_node: device_node_id(signer.public_key()),
        signer_key: signer.public_key(),
        grant_id: [12; 16],
        target: NodeId::from_bytes([13; 32]),
        consumer: "org.agenxy.supgang".into(),
        operation: "release.sign".into(),
        request_digest: request_hash.finalize().into(),
        challenge_digest: [14; 32],
        nonce: [15; 16],
        issued_at: 1_000,
        expires_at: 1_100,
        signature: [0; 64],
    };
    assertion.signature = signer.sign_domain(ACTION_DOMAIN, &assertion.payload()?)?.to_bytes();
    Ok(assertion)
}

#[test]
fn release_content_has_one_bounded_ordered_encoding() -> TestResult {
    let content = content();
    let bytes = content.encode()?;
    assert!(Content::decode(&bytes)? == content);
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(&bytes);
    assert_eq!(content.digest()?, <[u8; 32]>::from(hasher.finalize()));
    let mut trailing = bytes;
    trailing.push(0);
    assert!(Content::decode(&trailing).is_err());

    let mut wrong = content.clone();
    wrong.artifacts.swap(0, 1);
    assert!(wrong.encode().is_err());
    wrong = content.clone();
    let first = wrong
        .artifacts
        .first()
        .ok_or_else(|| std::io::Error::other("missing test artifact"))?
        .clone();
    wrong.artifacts.push(first);
    assert!(wrong.encode().is_err());
    wrong = content.clone();
    wrong.artifacts.clear();
    assert!(wrong.encode().is_err());
    wrong = content.clone();
    wrong.channel = "Stable".into();
    assert!(wrong.encode().is_err());
    wrong = content.clone();
    wrong
        .artifacts
        .first_mut()
        .ok_or_else(|| std::io::Error::other("missing test artifact"))?
        .os = "MACOS".into();
    assert!(wrong.encode().is_err());
    wrong = content.clone();
    wrong.expires_at += 1;
    assert!(wrong.encode().is_err());
    wrong = content.clone();
    wrong.source_commit = vec![7; 21];
    assert!(wrong.encode().is_err());
    assert!(Content::decode(&vec![0; MAX_BYTES + 1]).is_err());

    wrong = content;
    wrong.provenance = None;
    wrong.source_commit = vec![7; 32];
    assert!(Content::decode(&wrong.encode()?)? == wrong);
    Ok(())
}

#[test]
fn version_orders_release_and_bounded_prereleases() -> TestResult {
    let mut preview = content();
    let mut later_number = preview.clone();
    later_number
        .version
        .pre
        .as_mut()
        .ok_or_else(|| std::io::Error::other("missing preview version"))?
        .number = 5;
    assert!(later_number.version > preview.version);
    let mut later_label = preview.clone();
    later_label
        .version
        .pre
        .as_mut()
        .ok_or_else(|| std::io::Error::other("missing preview version"))?
        .label = "rc".into();
    assert!(later_label.version > preview.version);
    let mut release = preview.clone();
    release.version.pre = None;
    assert!(release.version > later_number.version);
    assert!(Content::decode(&preview.encode()?)? == preview);
    for bad in [
        String::new(),
        "Preview".into(),
        "preview+build".into(),
        "preview.4".into(),
        "a".repeat(33),
    ] {
        preview
            .version
            .pre
            .as_mut()
            .ok_or_else(|| std::io::Error::other("missing preview"))?
            .label = bad;
        assert!(preview.encode().is_err());
    }
    Ok(())
}

#[test]
fn statement_requires_exact_indexed_role_signatures() -> TestResult {
    let content = content();
    let content_bytes = content.encode()?;
    let p256 = FileDeviceKey::from_secret_bytes(&[9; 32])?;
    let ed25519 = ed25519_dalek::SigningKey::from_bytes(&[10; 32]);
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&content_bytes);
    let signed = SignedStatement {
        assertion: Some(carried_assertion(&content)?),
        content,
        signatures: vec![
            RoleSignature {
                signer: 0,
                bytes: p256.sign_domain(DOMAIN, &content_bytes)?.to_bytes(),
            },
            RoleSignature {
                signer: 1,
                bytes: ed25519.sign(&message).to_bytes(),
            },
        ],
    };
    let signers = [
        SubjectKey::P256(p256.public_key()),
        SubjectKey::Ed25519(ed25519.verifying_key().to_bytes()),
    ];
    assert!(SignedStatement::decode(&signed.encode()?)? == signed);
    signed.verify_role_signatures(&signers, 2)?;
    signed.check_release_assertion(true)?;
    assert!(signed.check_release_assertion(false).is_err());
    let mut unattended = signed.clone();
    unattended.assertion = None;
    unattended.check_release_assertion(false)?;
    assert!(unattended.check_release_assertion(true).is_err());
    assert!(signed.verify_role_signatures(&signers, 3).is_err());
    assert!(signed.verify_role_signatures(&signers[..1], 1).is_err());
    assert!(
        signed
            .verify_role_signatures(&[signers[0].clone(), signers[0].clone()], 2)
            .is_err()
    );

    let mut changed = signed.clone();
    changed.content.version.patch += 1;
    assert!(changed.verify_role_signatures(&signers, 2).is_err());
    assert!(changed.check_release_assertion(true).is_err());
    changed = signed.clone();
    changed
        .signatures
        .first_mut()
        .ok_or_else(|| std::io::Error::other("missing test signature"))?
        .bytes[0] ^= 1;
    assert!(changed.verify_role_signatures(&signers, 2).is_err());
    changed = signed.clone();
    changed.signatures.swap(0, 1);
    assert!(changed.encode().is_err());
    changed = signed.clone();
    changed
        .signatures
        .get_mut(1)
        .ok_or_else(|| std::io::Error::other("missing second test signature"))?
        .signer = 0;
    assert!(changed.encode().is_err());
    changed = signed.clone();
    changed
        .signatures
        .get_mut(1)
        .ok_or_else(|| std::io::Error::other("missing second test signature"))?
        .signer = 2;
    assert!(changed.verify_role_signatures(&signers, 2).is_err());
    changed = signed;
    changed.signatures.clear();
    assert!(changed.encode().is_err());
    Ok(())
}
