use std::{fs, path::PathBuf};

use ed25519_dalek::Signer as _;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::{
    authority::{SubjectKey, device_node_id},
    device_key::{DevicePublicKey, DeviceSigner as _, FileDeviceKey},
    ids::{HiveId, NodeId},
    threshold::{
        owner_action::{ACTION_DOMAIN, Assertion, REQUEST_DOMAIN},
        release_statement::{Artifact, Content, DOMAIN, MAX_BYTES, RoleSignature, SignedStatement, Version},
    },
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const VECTOR_DIR: &str = "docs/vectors/release-statement-draft-v1";

fn vector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(VECTOR_DIR)
}

fn content() -> Content {
    let root = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    Content {
        hive: HiveId::from_root_verifying_key(&root.verifying_key().to_bytes()),
        role_id: [4; 16],
        consumer_id: "org.agenxy.Remap".into(),
        package_format: "remap-package-v1".into(),
        channel: "stable".into(),
        version: Version {
            major: 0,
            minor: 2,
            patch: 1,
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
    request_hash.update(content.digest()?);
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

#[test]
fn committed_draft_release_vector_hashes_match_manifest() -> TestResult {
    let directory = vector_dir();
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(directory.join("manifest.json"))?)?;
    assert_eq!(
        manifest.get("state").and_then(serde_json::Value::as_str),
        Some("DRAFT - NOT FROZEN")
    );
    let files = manifest
        .get("files")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| std::io::Error::other("release vector manifest has no file list"))?;
    assert_eq!(files.len(), 6);
    for entry in files {
        let name = entry
            .get("file")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| std::io::Error::other("release vector has no file name"))?;
        if name.contains('/') || name.contains('\\') || name.starts_with('.') {
            return Err(std::io::Error::other("release vector name is not flat").into());
        }
        let bytes = fs::read(directory.join(name))?;
        assert_eq!(
            entry.get("bytes").and_then(serde_json::Value::as_u64),
            u64::try_from(bytes.len()).ok()
        );
        let digest = hex::encode(Sha256::digest(&bytes));
        assert_eq!(
            entry.get("sha256").and_then(serde_json::Value::as_str),
            Some(digest.as_str())
        );
    }
    Ok(())
}

#[test]
fn committed_draft_release_vectors_verify_and_refuse_mutations() -> TestResult {
    let directory = vector_dir();
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(directory.join("manifest.json"))?)?;
    let p256 = DevicePublicKey::from_bytes(&hex::decode(
        manifest
            .get("p256_public_key_hex")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| std::io::Error::other("missing P-256 vector key"))?,
    )?)?;
    let ed25519: [u8; 32] = hex::decode(
        manifest
            .get("ed25519_public_key_hex")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| std::io::Error::other("missing Ed25519 vector key"))?,
    )?
    .try_into()
    .map_err(|_| std::io::Error::other("wrong Ed25519 vector key size"))?;
    let signers = [SubjectKey::P256(p256), SubjectKey::Ed25519(ed25519)];
    let content = Content::decode(&fs::read(directory.join("content.cbor"))?)?;
    let signed = SignedStatement::decode(&fs::read(directory.join("statement.cbor"))?)?;
    assert!(signed.content == content);
    signed.verify_role_signatures(&signers, 2)?;
    signed.check_release_assertion(true)?;

    let bad_signature = SignedStatement::decode(&fs::read(directory.join("statement-bad-signature.cbor"))?)?;
    assert!(bad_signature.verify_role_signatures(&signers, 2).is_err());
    let changed_content = SignedStatement::decode(&fs::read(directory.join("statement-changed-content.cbor"))?)?;
    assert!(changed_content.verify_role_signatures(&signers, 2).is_err());
    assert!(changed_content.check_release_assertion(true).is_err());
    let changed_assertion = SignedStatement::decode(&fs::read(directory.join("statement-wrong-assertion.cbor"))?)?;
    changed_assertion.verify_role_signatures(&signers, 2)?;
    assert!(changed_assertion.check_release_assertion(true).is_err());
    assert!(Content::decode(&fs::read(directory.join("content-wrong-channel.cbor"))?).is_err());
    Ok(())
}

#[test]
#[ignore = "regenerates local DRAFT release vectors only when explicitly requested"]
fn generate_release_statement_vectors() -> TestResult {
    let directory = vector_dir();
    fs::create_dir_all(&directory)?;
    let content = content();
    let p256 = FileDeviceKey::from_secret_bytes(&[9; 32])?;
    let ed25519 = ed25519_dalek::SigningKey::from_bytes(&[10; 32]);
    let presence = FileDeviceKey::from_secret_bytes(&[11; 32])?;
    let content_bytes = content.encode()?;
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
    let mut bad_signature = signed.clone();
    bad_signature
        .signatures
        .first_mut()
        .ok_or_else(|| std::io::Error::other("missing first role signature"))?
        .bytes[0] ^= 1;
    let mut changed_content = signed.clone();
    changed_content.content.version.patch += 1;
    let mut wrong_assertion = signed.clone();
    let assertion = wrong_assertion
        .assertion
        .as_mut()
        .ok_or_else(|| std::io::Error::other("missing presence assertion"))?;
    assertion.request_digest[0] ^= 1;
    assertion.signature = presence.sign_domain(ACTION_DOMAIN, &assertion.payload()?)?.to_bytes();
    let mut wrong_channel = content_bytes.clone();
    let offset = wrong_channel
        .windows(b"stable".len())
        .position(|window| window == b"stable")
        .ok_or_else(|| std::io::Error::other("missing channel marker"))?;
    *wrong_channel
        .get_mut(offset)
        .ok_or_else(|| std::io::Error::other("missing channel byte"))? = b'S';

    let records = [
        ("content.cbor", content_bytes, "accept: canonical release content"),
        (
            "statement.cbor",
            signed.encode()?,
            "accept: two role signatures and carried assertion",
        ),
        (
            "statement-bad-signature.cbor",
            bad_signature.encode()?,
            "reject: malformed role signature",
        ),
        (
            "statement-changed-content.cbor",
            changed_content.encode()?,
            "reject: changed statement digest",
        ),
        (
            "statement-wrong-assertion.cbor",
            wrong_assertion.encode()?,
            "reject: valid carried signature bound to another digest",
        ),
        (
            "content-wrong-channel.cbor",
            wrong_channel,
            "reject: non-lowercase channel",
        ),
    ];
    let mut files = Vec::new();
    for (name, bytes, expectation) in records {
        fs::write(directory.join(name), &bytes)?;
        files.push(json!({
            "file": name,
            "bytes": bytes.len(),
            "sha256": hex::encode(Sha256::digest(&bytes)),
            "expectation": expectation,
        }));
    }
    let manifest = json!({
        "state": "DRAFT - NOT FROZEN",
        "protocol": "release-statement-v1-proposal",
        "files": files,
        "p256_public_key_hex": hex::encode(p256.public_key().to_bytes()),
        "ed25519_public_key_hex": hex::encode(ed25519.verifying_key().to_bytes()),
        "threshold": 2,
        "presence": "carried-device",
        "note": "Disposable public test keys only. Root role grant, status, challenge, replay state and artifact bytes are not included or verified.",
    });
    fs::write(directory.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}
