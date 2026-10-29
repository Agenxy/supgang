//! One ADR 0005/0007 provider fixture bundle for independent consumers.
//!
//! Regenerate intentionally with `cargo test --locked --package supgang-core
//! generate_release_role_vectors -- --ignored`. All private scalars are public
//! disposable test inputs; the certificate DER is pinned as a public fixture.

use std::{
    fs,
    path::{Path, PathBuf},
};

use ed25519_dalek::Signer as _;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::{
    authority::{SubjectCustody, SubjectKey, device_node_id},
    device_key::{DeviceSigner as _, FileDeviceKey},
    ids::{HiveId, NodeId},
    threshold::{
        owner_action::{ACTION_DOMAIN, Assertion, Challenge, REQUEST_DOMAIN},
        release_statement::{
            Artifact, Content, DOMAIN as RELEASE_DOMAIN, PreRelease, RoleSignature, SignedStatement, Version,
        },
        status::{DOMAIN as STATUS_DOMAIN, SignedStatus, Status},
        status_renewal::{
            Counts, Mode, OWNER_MAX_AGE, OWNER_POLICY_CAP, OWNER_PRESENCE_CAP, OWNER_TOTAL_CAP, POLICY_DOMAIN, Policy,
            SignedPolicy,
        },
        step::{
            Operation, RootStep, SignedStep,
            grant::{AllowedOperation, Grant, Kind, Presence, SignerRole, TargetScope},
            role_grant::{ReleasePresence, RoleGrant, RolePolicy, RoleSigner},
        },
    },
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const OUTPUT: &str = "docs/vectors/release-roles-v1";
const NOW: u64 = 1_780_000_000;

mod bounds;
mod certificate;

fn output_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(OUTPUT)
}

fn role_grant(
    hive: HiveId,
    id: u8,
    issuer: ([u8; 32], u64),
    signer: (u8, SubjectCustody),
    policy: RolePolicy,
    validity: (u64, u64),
) -> Result<RoleGrant, Box<dyn std::error::Error>> {
    let key = FileDeviceKey::from_secret_bytes(&[signer.0; 32])?;
    let public = key.public_key();
    let mut role = RoleGrant {
        hive,
        id: [id; 16],
        consumer: "org.agenxy.Remap".into(),
        signers: vec![RoleSigner {
            key: SubjectKey::P256(public),
            node: device_node_id(public),
            custody: signer.1,
            possession: [0; 64],
        }],
        threshold: 1,
        not_before: validity.0,
        not_after: validity.1,
        issuer_head: issuer.0,
        issuer_sequence: issuer.1,
        policy,
    };
    let message = role
        .signers
        .first()
        .ok_or_else(|| std::io::Error::other("missing signer"))?
        .possession_message(&role)?;
    role.signers
        .first_mut()
        .ok_or_else(|| std::io::Error::other("missing signer"))?
        .possession = key.sign_domain(b"supgang/role-possession/v1\0", &message)?.to_bytes();
    Ok(role)
}

fn release_policy(presence: ReleasePresence, number: u64) -> RolePolicy {
    RolePolicy::Release {
        package_format: "remap-package-v1".into(),
        channels: vec!["preview".into()],
        min_version: Version {
            major: 0,
            minor: 3,
            patch: 0,
            pre: Some(PreRelease {
                label: "preview".into(),
                number,
            }),
        },
        presence,
    }
}

fn owner_grant(
    hive: HiveId,
    predecessor: [u8; 32],
    sequence: u64,
    target: NodeId,
) -> Result<Grant, Box<dyn std::error::Error>> {
    let key = FileDeviceKey::from_secret_bytes(&[11; 32])?;
    let public = key.public_key();
    let mut grant = Grant {
        hive,
        id: [12; 16],
        kind: Kind::OwnerAction,
        consumer: "org.agenxy.supgang".into(),
        signer: public,
        signer_node: device_node_id(public),
        signer_role: SignerRole::OwnerPresence,
        signer_custody: SubjectCustody::File,
        possession: [0; 64],
        not_before: NOW - 1000,
        not_after: NOW + 3600,
        issuer_head: predecessor,
        issuer_sequence: sequence,
        target: TargetScope::Node(target),
        operations: vec![AllowedOperation {
            name: "release.sign".into(),
            presence: Presence::Required,
        }],
    };
    grant.possession = key
        .sign_domain(b"supgang/role-possession/v1\0", &grant.possession_message()?)?
        .to_bytes();
    Ok(grant)
}

fn root_step(
    root: &ed25519_dalek::SigningKey,
    predecessor: [u8; 32],
    sequence: u64,
    payload: Vec<u8>,
    proposer: NodeId,
) -> Result<(RootStep, [u8; 64]), Box<dyn std::error::Error>> {
    let step = RootStep {
        hive: HiveId::from_root_verifying_key(&root.verifying_key().to_bytes()),
        predecessor,
        sequence,
        epoch: 0,
        recovery_gen: 0,
        operation: Operation::Grant,
        payload,
        proposed_at: NOW - 100,
        proposer,
    };
    let signature = root.sign(&step.message()?).to_bytes();
    SignedStep {
        step: step.clone(),
        signature,
    }
    .verify(&root.verifying_key().to_bytes())?;
    Ok((step, signature))
}

fn content(hive: HiveId, role_id: [u8; 16], number: u64) -> Content {
    Content {
        hive,
        role_id,
        consumer_id: "org.agenxy.Remap".into(),
        package_format: "remap-package-v1".into(),
        channel: "preview".into(),
        version: Version {
            major: 0,
            minor: 3,
            patch: 0,
            pre: Some(PreRelease {
                label: "preview".into(),
                number,
            }),
        },
        artifacts: vec![Artifact {
            os: "macos".into(),
            arch: "aarch64".into(),
            length: 123,
            sha256: [8; 32],
        }],
        source_commit: vec![7; 20],
        provenance: Some([6; 32]),
        issued_at: NOW - 10,
        expires_at: NOW + 24 * 60 * 60,
    }
}

fn save(
    output: &Path,
    records: &mut Vec<serde_json::Value>,
    name: &str,
    bytes: &[u8],
    expectation: &str,
) -> TestResult {
    fs::write(output.join(name), bytes)?;
    records.push(json!({
        "file": name,
        "bytes": bytes.len(),
        "sha256": hex::encode(Sha256::digest(bytes)),
        "expectation": expectation,
    }));
    Ok(())
}

#[test]
#[ignore = "regenerates the reviewed public role fixture bundle only when explicitly requested"]
fn generate_release_role_vectors() -> TestResult {
    let output = output_dir();
    fs::create_dir_all(&output)?;
    let root = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    let root_key = root.verifying_key().to_bytes();
    let hive = HiveId::from_root_verifying_key(&root_key);
    let release_key = FileDeviceKey::from_secret_bytes(&[9; 32])?;
    let unattended_key = FileDeviceKey::from_secret_bytes(&[10; 32])?;
    let presence_key = FileDeviceKey::from_secret_bytes(&[11; 32])?;
    let proposer = device_node_id(release_key.public_key());
    let target = NodeId::from_bytes([13; 32]);
    let mut records = Vec::new();

    let release = role_grant(
        hive,
        4,
        ([4; 32], 0),
        (9, SubjectCustody::File),
        release_policy(ReleasePresence::CarriedDevice, 4),
        (NOW - 1000, NOW + 90 * 24 * 60 * 60 - 1000),
    )?;
    let release_bytes = release.encode()?;
    let (release_step, release_signature) = root_step(&root, [4; 32], 1, release_bytes.clone(), proposer)?;
    let release_head = release_step.digest()?;
    save(
        &output,
        &mut records,
        "release-grant.cbor",
        &release_bytes,
        "accept: carried-device release role",
    )?;
    save(
        &output,
        &mut records,
        "release-grant-step.cbor",
        &release_step.encode()?,
        "accept: root-issued release role step",
    )?;
    save(
        &output,
        &mut records,
        "release-grant-step.sig",
        &release_signature,
        "accept: root signature over release role step",
    )?;

    let unattended = role_grant(
        hive,
        5,
        (release_head, 1),
        (10, SubjectCustody::Hardware),
        release_policy(ReleasePresence::Unattended, 5),
        (NOW - 1000, NOW - 1000 + 90 * 24 * 60 * 60),
    )?;
    let unattended_bytes = unattended.encode()?;
    let (unattended_step, unattended_signature) =
        root_step(&root, release_head, 2, unattended_bytes.clone(), proposer)?;
    let unattended_head = unattended_step.digest()?;
    save(
        &output,
        &mut records,
        "unattended-grant.cbor",
        &unattended_bytes,
        "accept: preview-only 90-day unattended role with enrolled hardware label",
    )?;
    save(
        &output,
        &mut records,
        "unattended-grant-step.cbor",
        &unattended_step.encode()?,
        "accept: root-issued unattended role step",
    )?;
    save(
        &output,
        &mut records,
        "unattended-grant-step.sig",
        &unattended_signature,
        "accept: root signature over unattended role step",
    )?;

    let certificate = certificate::cert_der(&output)?;
    let (_, parsed_certificate) = x509_parser::parse_x509_certificate(&certificate)
        .map_err(|_| std::io::Error::other("invalid pinned test certificate"))?;
    let certificate_start = u64::try_from(parsed_certificate.validity().not_before.timestamp())?;
    let certificate_end = u64::try_from(parsed_certificate.validity().not_after.timestamp())?;
    let code_signing = role_grant(
        hive,
        6,
        (unattended_head, 2),
        (9, SubjectCustody::File),
        RolePolicy::CodeSigning {
            identifiers: vec!["org.agenxy.Remap".into()],
            certificate: certificate.clone(),
        },
        (certificate_start, certificate_end),
    )?;
    let code_bytes = code_signing.encode()?;
    let (code_step, code_signature) = root_step(&root, unattended_head, 3, code_bytes.clone(), proposer)?;
    let code_head = code_step.digest()?;
    save(
        &output,
        &mut records,
        "code-signing-grant.cbor",
        &code_bytes,
        "accept: self-issued code-signing certificate bound to P-256 role signer",
    )?;
    save(
        &output,
        &mut records,
        "code-signing-grant-step.cbor",
        &code_step.encode()?,
        "accept: root-issued code-signing role step",
    )?;
    save(
        &output,
        &mut records,
        "code-signing-grant-step.sig",
        &code_signature,
        "accept: root signature over code-signing role step",
    )?;
    save(
        &output,
        &mut records,
        "code-signing-cert.der",
        &certificate,
        "accept: public test certificate used by code-signing role",
    )?;

    let owner = owner_grant(hive, code_head, 3, target)?;
    let owner_bytes = owner.encode()?;
    let (owner_step, owner_signature) = root_step(&root, code_head, 4, owner_bytes.clone(), proposer)?;
    let head = owner_step.digest()?;
    save(
        &output,
        &mut records,
        "owner-grant.cbor",
        &owner_bytes,
        "accept: root-enrolled presence class for release.sign",
    )?;
    save(
        &output,
        &mut records,
        "owner-grant-step.cbor",
        &owner_step.encode()?,
        "accept: root-issued owner-action grant step",
    )?;
    save(
        &output,
        &mut records,
        "owner-grant-step.sig",
        &owner_signature,
        "accept: root signature over owner-action grant step",
    )?;

    let policy = Policy {
        hive,
        root_head: head,
        budget_id: [14; 16],
        epoch: 1,
        maximum_age: OWNER_MAX_AGE,
        policy_cap: OWNER_POLICY_CAP,
        presence_cap: OWNER_PRESENCE_CAP,
        total_cap: OWNER_TOTAL_CAP,
    };
    let mut policy_message = POLICY_DOMAIN.to_vec();
    policy_message.extend_from_slice(&policy.encode()?);
    let signed_policy = SignedPolicy {
        policy,
        signature: root.sign(&policy_message).to_bytes(),
    };
    let status = Status {
        hive,
        root_head: head,
        member_serial: 0,
        grant_serial: 0,
        issued_at: NOW - 20,
        expires_at: NOW + 580,
        policy_digest: policy.content_digest()?,
        budget_id: policy.budget_id,
        epoch: policy.epoch,
        mode: Mode::Initial,
        counts: Counts::default(),
    };
    let mut status_message = STATUS_DOMAIN.to_vec();
    status_message.extend_from_slice(&status.encode()?);
    let signed_status = SignedStatus {
        status,
        signature: root.sign(&status_message).to_bytes(),
    };
    save(
        &output,
        &mut records,
        "status-policy.cbor",
        &signed_policy.encode()?,
        "accept: owner-approved root-signed status policy",
    )?;
    save(
        &output,
        &mut records,
        "status.cbor",
        &signed_status.encode()?,
        "accept: fresh status at final grant-chain head",
    )?;

    let release_content = content(hive, release.id, 4);
    let request = release_content.digest()?.to_vec();
    let challenge = Challenge {
        target,
        consumer: "org.agenxy.supgang".into(),
        operation: "release.sign".into(),
        grant_id: owner.id,
        request: request.clone(),
        nonce: [15; 16],
        expires_at: NOW + 90,
    };
    let mut request_hash = Sha256::new();
    request_hash.update(REQUEST_DOMAIN);
    request_hash.update(&request);
    let mut assertion = Assertion {
        hive,
        signer_node: owner.signer_node,
        signer_key: owner.signer,
        grant_id: owner.id,
        target,
        consumer: "org.agenxy.supgang".into(),
        operation: "release.sign".into(),
        request_digest: request_hash.finalize().into(),
        challenge_digest: challenge.digest()?,
        nonce: challenge.nonce,
        issued_at: NOW - 5,
        expires_at: NOW + 60,
        signature: [0; 64],
    };
    assertion.signature = presence_key
        .sign_domain(ACTION_DOMAIN, &assertion.payload()?)?
        .to_bytes();
    assertion.verify_binding(&owner, &challenge, &request, target, NOW)?;
    let release_content_bytes = release_content.encode()?;
    let carried = SignedStatement {
        content: release_content,
        assertion: Some(assertion.clone()),
        signatures: vec![RoleSignature {
            signer: 0,
            bytes: release_key
                .sign_domain(RELEASE_DOMAIN, &release_content_bytes)?
                .to_bytes(),
        }],
    };
    carried.check_role_policy(&release, &["stable"], NOW, None)?;
    save(
        &output,
        &mut records,
        "release-content.cbor",
        &release_content_bytes,
        "accept: Remap 0.3.0-preview.4 canonical content",
    )?;
    let mut invalid_pre = release_content_bytes.clone();
    let offset = invalid_pre
        .windows(b"preview".len())
        .rposition(|part| part == b"preview")
        .ok_or_else(|| std::io::Error::other("missing pre-release label"))?;
    *invalid_pre
        .get_mut(offset)
        .ok_or_else(|| std::io::Error::other("missing pre-release byte"))? = b'P';
    save(
        &output,
        &mut records,
        "release-content-invalid-pre.cbor",
        &invalid_pre,
        "reject: uppercase pre-release label",
    )?;
    save(
        &output,
        &mut records,
        "release-statement.cbor",
        &carried.encode()?,
        "accept: carried-device release statement and exact assertion",
    )?;
    save(
        &output,
        &mut records,
        "release-challenge.cbor",
        &challenge.encode()?,
        "accept: target-issued release.sign challenge",
    )?;
    save(
        &output,
        &mut records,
        "release-request.bin",
        &request,
        "accept: exact release statement digest as owner-action request",
    )?;
    save(
        &output,
        &mut records,
        "release-assertion.cbor",
        &assertion.encode()?,
        "accept: release.sign assertion bound to statement digest and target challenge",
    )?;

    let unattended_content = content(hive, unattended.id, 5);
    let unattended_content_bytes = unattended_content.encode()?;
    let unattended_statement = SignedStatement {
        content: unattended_content,
        assertion: None,
        signatures: vec![RoleSignature {
            signer: 0,
            bytes: unattended_key
                .sign_domain(RELEASE_DOMAIN, &unattended_content_bytes)?
                .to_bytes(),
        }],
    };
    unattended_statement.check_role_policy(&unattended, &["stable"], NOW, None)?;
    save(
        &output,
        &mut records,
        "unattended-statement.cbor",
        &unattended_statement.encode()?,
        "accept: opt-in preview release without assertion",
    )?;

    let mut bad_signature = carried.clone();
    bad_signature
        .signatures
        .first_mut()
        .ok_or_else(|| std::io::Error::other("missing signature"))?
        .bytes[0] ^= 1;
    save(
        &output,
        &mut records,
        "release-statement-bad-signature.cbor",
        &bad_signature.encode()?,
        "reject: role signature bit changed",
    )?;
    let mut wrong_assertion = carried.clone();
    let assertion_mut = wrong_assertion
        .assertion
        .as_mut()
        .ok_or_else(|| std::io::Error::other("missing assertion"))?;
    assertion_mut.request_digest[0] ^= 1;
    assertion_mut.signature = presence_key
        .sign_domain(ACTION_DOMAIN, &assertion_mut.payload()?)?
        .to_bytes();
    save(
        &output,
        &mut records,
        "release-statement-wrong-assertion.cbor",
        &wrong_assertion.encode()?,
        "reject: valid presence signature bound to a different request digest",
    )?;
    let mut expired = carried.clone();
    expired.content.expires_at = NOW - 1;
    save(
        &output,
        &mut records,
        "release-statement-expired.cbor",
        &expired.encode()?,
        "reject: statement expired before verification time",
    )?;
    let mut wrong_channel = carried;
    wrong_channel.content.channel = "stable".into();
    save(
        &output,
        &mut records,
        "release-statement-wrong-channel.cbor",
        &wrong_channel.encode()?,
        "reject: channel outside root grant",
    )?;
    let mut bad_status = signed_status;
    bad_status.signature[0] ^= 1;
    save(
        &output,
        &mut records,
        "status-bad-signature.cbor",
        &bad_status.encode()?,
        "reject: invalid current-root status signature",
    )?;
    let mut bad_grant = release_bytes.clone();
    let proof = release
        .signers
        .first()
        .ok_or_else(|| std::io::Error::other("missing role signer"))?
        .possession;
    let offset = bad_grant
        .windows(proof.len())
        .position(|part| part == proof)
        .ok_or_else(|| std::io::Error::other("missing possession bytes"))?;
    *bad_grant
        .get_mut(offset)
        .ok_or_else(|| std::io::Error::other("missing possession byte"))? ^= 1;
    save(
        &output,
        &mut records,
        "release-grant-bad-possession.cbor",
        &bad_grant,
        "reject: signer possession proof changed",
    )?;
    let mut bad_class = release_bytes;
    let class = b"role-key";
    let offset = bad_class
        .windows(class.len())
        .position(|part| part == class)
        .ok_or_else(|| std::io::Error::other("missing signer class"))?;
    *bad_class
        .get_mut(offset)
        .ok_or_else(|| std::io::Error::other("missing class byte"))? = b'R';
    save(
        &output,
        &mut records,
        "release-grant-wrong-class.cbor",
        &bad_class,
        "reject: signer class not allowed for release kind",
    )?;
    let mut bad_cert = code_bytes;
    let offset = bad_cert
        .windows(certificate.len())
        .position(|part| part == certificate)
        .ok_or_else(|| std::io::Error::other("missing cert bytes"))?;
    *bad_cert
        .get_mut(offset)
        .ok_or_else(|| std::io::Error::other("missing cert byte"))? ^= 1;
    save(
        &output,
        &mut records,
        "code-signing-grant-bad-cert.cbor",
        &bad_cert,
        "reject: malformed role certificate",
    )?;

    bounds::write_edge_fixtures(&output, &mut records, &release, &unattended, &code_signing)?;

    let manifest = json!({
        "state": "DRAFT - NOT FROZEN",
        "protocol": "owner-action-and-release-roles-v1",
        "root_public_key_hex": hex::encode(root_key),
        "hive_hex": hex::encode(hive.as_bytes()),
        "final_root_head_hex": hex::encode(head),
        "verification_time": NOW,
        "default_install_channels": ["stable"],
        "files": records,
        "note": "Disposable public test keys. Hardware custody is an enrolled label in this bundle, not physical proof. Consumer high-water storage, artifact bytes, live status issuer and installed cross-host acceptance remain outside these provider fixtures."
    });
    fs::write(output.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}
