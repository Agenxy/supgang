//! Independent checks for the committed four-part role fixture bundle.

use std::{
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest as _, Sha256};

use super::vector_tests::assert_one_cbor_item;
use crate::{
    ids::HiveId,
    threshold::{
        owner_action::{Assertion, Challenge},
        release_statement::{Content, SignedStatement},
        status::{Scope, SignedStatus},
        status_renewal::{Ledger, SignedPolicy},
        step::{
            DOMAIN as STEP_DOMAIN, RootStep, SignedStep,
            grant::{Grant, Kind},
            role_grant::RoleGrant,
        },
    },
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const OUTPUT: &str = "docs/vectors/release-roles-v1";
const NOW: u64 = 1_780_000_000;

fn output_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(OUTPUT)
}

fn fixture_root(output: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    Ok(hex::decode(
        manifest
            .get("root_public_key_hex")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| std::io::Error::other("missing root key"))?,
    )?
    .try_into()
    .map_err(|_| std::io::Error::other("wrong root key length"))?)
}

#[test]
fn committed_release_role_bundle_has_exact_hashes_and_one_cbor_item() -> TestResult {
    let output = output_dir();
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    assert_eq!(
        manifest.get("state").and_then(serde_json::Value::as_str),
        Some("DRAFT - NOT FROZEN")
    );
    let files = manifest
        .get("files")
        .ok_or_else(|| std::io::Error::other("missing fixture list"))?
        .as_array()
        .ok_or_else(|| std::io::Error::other("missing fixture list"))?;
    assert_eq!(files.len(), 64);
    for file in files {
        let name = file
            .get("file")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| std::io::Error::other("missing fixture name"))?;
        if name.starts_with('.') || name.contains('/') || name.contains('\\') {
            return Err(std::io::Error::other("fixture name must be flat").into());
        }
        let bytes = fs::read(output.join(name))?;
        assert_eq!(
            file.get("bytes").and_then(serde_json::Value::as_u64),
            u64::try_from(bytes.len()).ok()
        );
        assert_eq!(
            file.get("sha256").and_then(serde_json::Value::as_str),
            Some(hex::encode(Sha256::digest(&bytes)).as_str())
        );
        if Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("cbor"))
        {
            assert_one_cbor_item(&bytes)?;
        }
        if name.starts_with("edge-") {
            let should_accept = file
                .get("expectation")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|expectation| expectation.starts_with("accept:"));
            assert_eq!(RoleGrant::decode(&bytes).is_ok(), should_accept, "{name}");
        }
    }
    Ok(())
}

#[test]
fn committed_release_role_bundle_verifies_and_refuses_named_mutations() -> TestResult {
    let output = output_dir();
    let root = fixture_root(&output)?;
    let hive = HiveId::from_root_verifying_key(&root);
    let mut predecessor = [4; 32];
    for (name, signature_name) in [
        ("release-grant-step.cbor", "release-grant-step.sig"),
        ("unattended-grant-step.cbor", "unattended-grant-step.sig"),
        ("code-signing-grant-step.cbor", "code-signing-grant-step.sig"),
        ("owner-grant-step.cbor", "owner-grant-step.sig"),
    ] {
        let step = RootStep::decode(&fs::read(output.join(name))?)?;
        assert_eq!(step.predecessor, predecessor);
        let signature: [u8; 64] = fs::read(output.join(signature_name))?
            .try_into()
            .map_err(|_| std::io::Error::other("wrong root signature size"))?;
        SignedStep {
            step: step.clone(),
            signature,
        }
        .verify(&root)?;
        predecessor = step.digest()?;
    }
    let release = RoleGrant::decode(&fs::read(output.join("release-grant.cbor"))?)?;
    let unattended = RoleGrant::decode(&fs::read(output.join("unattended-grant.cbor"))?)?;
    let code_signing = RoleGrant::decode(&fs::read(output.join("code-signing-grant.cbor"))?)?;
    assert_eq!(code_signing.kind(), Kind::CodeSigning);
    code_signing.check_code_signing_identifier("org.agenxy.Remap")?;
    assert!(code_signing.check_code_signing_identifier("org.agenxy.Other").is_err());
    assert!(
        code_signing
            .check_code_signing_identifier("org.agenxy.Remap.helper")
            .is_err()
    );
    let owner = Grant::decode(&fs::read(output.join("owner-grant.cbor"))?)?;
    let policy = SignedPolicy::decode(&fs::read(output.join("status-policy.cbor"))?)?;
    policy.verify(&root, hive, predecessor)?;
    let status = SignedStatus::decode(&fs::read(output.join("status.cbor"))?)?;
    let ledger = Ledger::draft_new(&policy.policy)?;
    status.verify(
        &root,
        &Scope {
            hive,
            head: predecessor,
            member_floor: 0,
            grant_floor: 0,
            now: NOW,
            maximum_age: 600,
            policy: &policy,
            ledger: &ledger,
        },
    )?;
    let challenge = Challenge::decode(&fs::read(output.join("release-challenge.cbor"))?)?;
    let request = fs::read(output.join("release-request.bin"))?;
    let assertion = Assertion::decode(&fs::read(output.join("release-assertion.cbor"))?)?;
    assertion.verify_binding(&owner, &challenge, &request, challenge.target, NOW)?;
    let content = Content::decode(&fs::read(output.join("release-content.cbor"))?)?;
    assert!(Content::decode(&fs::read(output.join("release-content-invalid-pre.cbor"))?).is_err());
    assert_eq!(request, content.digest()?.to_vec());
    let carried = SignedStatement::decode(&fs::read(output.join("release-statement.cbor"))?)?;
    assert!(carried.content == content);
    carried.check_role_policy(&release, &["stable"], NOW, None)?;
    assert!(
        carried
            .check_role_policy(&code_signing, &["stable"], NOW, None)
            .is_err()
    );
    let unattended_statement = SignedStatement::decode(&fs::read(output.join("unattended-statement.cbor"))?)?;
    unattended_statement.check_role_policy(&unattended, &["stable"], NOW, None)?;
    assert!(
        unattended_statement
            .check_role_policy(&unattended, &["preview"], NOW, None)
            .is_err()
    );
    assert!(
        carried
            .check_role_policy(&release, &["stable"], NOW, Some(&content.version))
            .is_err()
    );

    for name in ["release-grant-bad-possession.cbor", "release-grant-wrong-class.cbor"] {
        assert!(RoleGrant::decode(&fs::read(output.join(name))?).is_err());
    }
    assert!(RoleGrant::decode(&fs::read(output.join("code-signing-grant-bad-cert.cbor"))?).is_err());
    let bad_status = SignedStatus::decode(&fs::read(output.join("status-bad-signature.cbor"))?)?;
    assert!(
        bad_status
            .verify(
                &root,
                &Scope {
                    hive,
                    head: predecessor,
                    member_floor: 0,
                    grant_floor: 0,
                    now: NOW,
                    maximum_age: 600,
                    policy: &policy,
                    ledger: &ledger,
                }
            )
            .is_err()
    );
    for name in [
        "release-statement-bad-signature.cbor",
        "release-statement-wrong-assertion.cbor",
        "release-statement-expired.cbor",
        "release-statement-wrong-channel.cbor",
    ] {
        let changed = SignedStatement::decode(&fs::read(output.join(name))?)?;
        assert!(changed.check_role_policy(&release, &["stable"], NOW, None).is_err());
    }
    Ok(())
}

#[test]
fn committed_release_role_bundle_refuses_contextual_role_and_statement_cases() -> TestResult {
    let output = output_dir();
    let release = RoleGrant::decode(&fs::read(output.join("release-grant.cbor"))?)?;
    let carried = SignedStatement::decode(&fs::read(output.join("release-statement.cbor"))?)?;
    let cross_hive = RoleGrant::decode(&fs::read(output.join("refuse-cross-hive-grant.cbor"))?)?;
    assert_ne!(cross_hive.hive, release.hive);
    assert!(RoleGrant::decode(&fs::read(output.join("refuse-unattended-file-signer.cbor"))?).is_err());
    let default_channel = RoleGrant::decode(&fs::read(output.join("refuse-unattended-default-channel.cbor"))?)?;
    assert!(default_channel.check_default_channels(&["stable"]).is_err());
    let threshold_three = RoleGrant::decode(&fs::read(output.join("refuse-fewer-than-threshold-grant.cbor"))?)?;
    assert_eq!(threshold_three.threshold, 3);
    assert!(
        carried
            .check_role_policy(&threshold_three, &["stable"], NOW, None)
            .is_err()
    );
    let wrong_consumer = SignedStatement::decode(&fs::read(output.join("refuse-wrong-consumer-statement.cbor"))?)?;
    assert!(
        wrong_consumer
            .check_role_policy(&release, &["stable"], NOW, None)
            .is_err()
    );
    Ok(())
}

#[test]
fn committed_release_role_bundle_refuses_stale_status_and_issuer_steps() -> TestResult {
    let output = output_dir();
    let root = fixture_root(&output)?;
    let hive = HiveId::from_root_verifying_key(&root);
    let release = RoleGrant::decode(&fs::read(output.join("release-grant.cbor"))?)?;
    let policy = SignedPolicy::decode(&fs::read(output.join("status-policy.cbor"))?)?;
    let ledger = Ledger::draft_new(&policy.policy)?;
    let stale_status = SignedStatus::decode(&fs::read(output.join("refuse-stale-status.cbor"))?)?;
    assert!(
        stale_status
            .verify(
                &root,
                &Scope {
                    hive,
                    head: policy.policy.root_head,
                    member_floor: 0,
                    grant_floor: 0,
                    now: NOW,
                    maximum_age: 600,
                    policy: &policy,
                    ledger: &ledger,
                }
            )
            .is_err()
    );
    let reused = RootStep::decode(&fs::read(output.join("refuse-reused-role-id-step.cbor"))?)?;
    let reused_signature: [u8; 64] = fs::read(output.join("refuse-reused-role-id-step.sig"))?
        .try_into()
        .map_err(|_| std::io::Error::other("wrong reused-step signature size"))?;
    SignedStep {
        step: reused.clone(),
        signature: reused_signature,
    }
    .verify(&root)?;
    assert_eq!(RoleGrant::decode(&reused.payload)?.id, release.id);
    assert_eq!(reused.predecessor, policy.policy.root_head);
    let stale_issuer = fs::read(output.join("refuse-stale-issuer-head-step.cbor"))?;
    let stale_signature: [u8; 64] = fs::read(output.join("refuse-stale-issuer-head-step.sig"))?
        .try_into()
        .map_err(|_| std::io::Error::other("wrong stale-step signature size"))?;
    let mut message = STEP_DOMAIN.to_vec();
    message.extend_from_slice(&stale_issuer);
    ed25519_dalek::VerifyingKey::from_bytes(&root)?
        .verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&stale_signature))?;
    assert!(RootStep::decode(&stale_issuer).is_err());
    Ok(())
}
