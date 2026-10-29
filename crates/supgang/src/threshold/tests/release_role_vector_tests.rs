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
use minicbor::Encoder;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::{
    authority::{SubjectCustody, SubjectKey, device_node_id},
    device_key::{DeviceSigner as _, FileDeviceKey},
    ids::{HiveId, NodeId},
    threshold::{
        owner_action::{ACTION_DOMAIN, Assertion, Challenge, REQUEST_DOMAIN},
        release_bundle::ReleaseBundle,
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
const VERIFY_AT: u64 = NOW + 2 * 60 * 60;

mod adversarial;
mod bounds;
mod certificate;
mod encoding;
mod grant_cases;
mod helpers;
use helpers::*;
mod statement_cases;
mod statement_extra;

fn output_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(OUTPUT)
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

    let certificate = certificate::cert_der()?;
    let edge_certificate = certificate::max_cert_der()?;
    let (_, parsed_certificate) = x509_parser::parse_x509_certificate(&certificate)
        .map_err(|_| std::io::Error::other("invalid pinned test certificate"))?;
    let certificate_start = u64::try_from(parsed_certificate.validity().not_before.timestamp())?;
    let certificate_end = u64::try_from(parsed_certificate.validity().not_after.timestamp())?;
    let code_signing = role_grant(
        hive,
        6,
        (unattended_head, 2),
        (14, SubjectCustody::File),
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
    save(
        &output,
        &mut records,
        "refuse-release-with-code-signing-grant.cbor",
        &code_bytes,
        "reject: code-signing kind cannot authorize release statement",
    )?;
    save(
        &output,
        &mut records,
        "refuse-code-signing-with-release-grant.cbor",
        &release_bytes,
        "reject: release kind cannot authorize code-signing identifier",
    )?;
    save(
        &output,
        &mut records,
        "code-signing-identifier-exact.txt",
        b"org.agenxy.Remap",
        "accept: exact code-signing identifier",
    )?;
    save(
        &output,
        &mut records,
        "refuse-code-signing-prefix-identifier.txt",
        b"org.agenxy.Remap.helper",
        "reject: prefix extension is not exact identifier",
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
    let mut active_members = vec![
        release
            .signers
            .first()
            .ok_or_else(|| std::io::Error::other("missing release signer"))?
            .node,
        unattended
            .signers
            .first()
            .ok_or_else(|| std::io::Error::other("missing unattended signer"))?
            .node,
        code_signing
            .signers
            .first()
            .ok_or_else(|| std::io::Error::other("missing code signer"))?
            .node,
        owner.signer_node,
    ];
    active_members.sort_unstable();
    active_members.dedup();
    let status = Status {
        hive,
        root_head: head,
        member_serial: 0,
        grant_serial: 0,
        active_grants: vec![release.id, unattended.id, code_signing.id, owner.id],
        active_members,
        issued_at: VERIFY_AT - 20,
        expires_at: VERIFY_AT + 580,
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
    let carried_bundle = ReleaseBundle {
        role_step: release_step.encode()?,
        role_signature: release_signature,
        owner_step: Some(owner_step.encode()?),
        owner_signature: Some(owner_signature),
        status: signed_status.encode()?,
    };
    save(
        &output,
        &mut records,
        "release-authority.cbor",
        &carried_bundle.encode()?,
        "accept: canonical carried-device release authority bundle",
    )?;
    let unattended_bundle = ReleaseBundle {
        role_step: unattended_step.encode()?,
        role_signature: unattended_signature,
        owner_step: None,
        owner_signature: None,
        status: signed_status.encode()?,
    };
    save(
        &output,
        &mut records,
        "unattended-authority.cbor",
        &unattended_bundle.encode()?,
        "accept: canonical unattended release authority bundle",
    )?;
    let mut owner_step_only = Encoder::new(Vec::new());
    owner_step_only
        .array(6)?
        .u8(1)?
        .bytes(&release_step.encode()?)?
        .bytes(&release_signature)?
        .bytes(&owner_step.encode()?)?
        .null()?
        .bytes(&signed_status.encode()?)?;
    save(
        &output,
        &mut records,
        "refuse-authority-owner-step-without-signature.cbor",
        &owner_step_only.into_writer(),
        "reject: owner step and signature must both be present",
    )?;
    let mut owner_signature_only = Encoder::new(Vec::new());
    owner_signature_only
        .array(6)?
        .u8(1)?
        .bytes(&release_step.encode()?)?
        .bytes(&release_signature)?
        .null()?
        .bytes(&owner_signature)?
        .bytes(&signed_status.encode()?)?;
    save(
        &output,
        &mut records,
        "refuse-authority-owner-signature-without-step.cbor",
        &owner_signature_only.into_writer(),
        "reject: owner signature and step must both be present",
    )?;

    let release_content = content(hive, release.id, 4);
    save(
        &output,
        &mut records,
        "artifact.bin",
        &[8_u8; 123],
        "accept: bytes named by the release artifact digest",
    )?;
    let request = release_content.encode()?;
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
    carried.check_carried_authority(&owner, &signed_status.status)?;
    save(
        &output,
        &mut records,
        "release-content.cbor",
        &release_content_bytes,
        "accept: Remap 0.3.0-preview.4 canonical content",
    )?;
    save(
        &output,
        &mut records,
        "refuse-version-high-water.json",
        &serde_json::to_vec(&json!({"major":0,"minor":3,"patch":0,"pre_label":"preview","pre_number":4}))?,
        "reject: protected high-water equal to candidate version",
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
    statement_extra::write(
        &output,
        &mut records,
        &statement_extra::Context {
            release: &release,
            carried: &carried,
            release_content_bytes: &release_content_bytes,
            assertion: &assertion,
            release_key: &release_key,
            presence_key: &presence_key,
        },
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
        "accept: exact canonical release content as owner-action request",
    )?;
    save(
        &output,
        &mut records,
        "release-assertion.cbor",
        &assertion.encode()?,
        "accept: release.sign assertion bound to canonical content and target challenge",
    )?;
    encoding::write(&output, &mut records, "grant", &release_bytes)?;
    encoding::write(&output, &mut records, "status", &signed_status.encode()?)?;
    encoding::write(&output, &mut records, "statement", &carried.encode()?)?;
    encoding::write(&output, &mut records, "assertion", &assertion.encode()?)?;

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

    statement_cases::write(
        &output,
        &mut records,
        &carried,
        &unattended_statement,
        &assertion,
        &release_key,
        &presence_key,
    )?;
    grant_cases::write(
        &output,
        &mut records,
        &release,
        &release_bytes,
        &code_bytes,
        &certificate,
        &release_key,
    )?;
    bounds::write_edge_fixtures(
        &output,
        &mut records,
        &release,
        &unattended,
        &code_signing,
        &edge_certificate,
    )?;
    adversarial::write(
        &output,
        &mut records,
        &adversarial::Base {
            root: &root,
            hive,
            head,
            release: &release,
            unattended: &unattended,
            status: &signed_status,
            statement: &carried,
        },
    )?;

    let manifest = json!({
        "state": "DRAFT - NOT FROZEN",
        "protocol": "owner-action-and-release-roles-v1",
        "root_public_key_hex": hex::encode(root_key),
        "hive_hex": hex::encode(hive.as_bytes()),
        "final_root_head_hex": hex::encode(head),
        "verification_time": VERIFY_AT,
        "default_install_channels": ["stable"],
        "files": records,
        "note": "Disposable public test keys. Hardware custody is an enrolled label in this bundle, not physical proof. Consumer high-water storage, artifact bytes, live status issuer and installed cross-host acceptance remain outside these provider fixtures."
    });
    fs::write(output.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}
