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
        release_bundle::ReleaseBundle,
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
const VERIFY_AT: u64 = NOW + 2 * 60 * 60;

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
    assert_eq!(files.len(), 121);
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
        if !name.starts_with("refuse-")
            && Path::new(name)
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
fn committed_release_role_bundle_refuses_noncanonical_record_forms() -> TestResult {
    let output = output_dir();
    for mutation in ["nonminimal-integer", "indefinite", "tag", "trailing", "extra-field"] {
        let name = format!("refuse-grant-{mutation}.cbor");
        assert!(RoleGrant::decode(&fs::read(output.join(&name))?).is_err(), "{name}");
        let name = format!("refuse-status-{mutation}.cbor");
        assert!(SignedStatus::decode(&fs::read(output.join(&name))?).is_err(), "{name}");
        let name = format!("refuse-statement-{mutation}.cbor");
        assert!(
            SignedStatement::decode(&fs::read(output.join(&name))?).is_err(),
            "{name}"
        );
        let name = format!("refuse-assertion-{mutation}.cbor");
        assert!(Assertion::decode(&fs::read(output.join(&name))?).is_err(), "{name}");
    }
    Ok(())
}

#[test]
fn committed_release_role_bundle_refuses_aggregate_lengths_before_parsing() -> TestResult {
    let output = output_dir();
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let files = manifest
        .get("files")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| std::io::Error::other("missing manifest files"))?;
    for name in [
        "refuse-statement-over-envelope-limit.cbor",
        "refuse-authority-over-bundle-limit.cbor",
    ] {
        let entry = files
            .iter()
            .find(|entry| entry.get("file").and_then(serde_json::Value::as_str) == Some(name))
            .ok_or_else(|| std::io::Error::other("missing aggregate bound fixture"))?;
        assert_eq!(
            entry.get("expectation").and_then(serde_json::Value::as_str),
            Some("necessarily multi-fault: pre-parse length bound")
        );
    }
    let statement = fs::read(output.join("refuse-statement-over-envelope-limit.cbor"))?;
    assert_eq!(statement.len(), crate::threshold::release_statement::MAX_BYTES + 1);
    assert!(matches!(
        SignedStatement::decode(&statement),
        Err(crate::threshold::Error::Bound)
    ));
    let bundle = fs::read(output.join("refuse-authority-over-bundle-limit.cbor"))?;
    assert_eq!(bundle.len(), crate::threshold::release_bundle::MAX_BYTES + 1);
    assert!(matches!(
        ReleaseBundle::decode(&bundle),
        Err(crate::threshold::Error::Bound)
    ));
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
        ("multi-signer-role-step.cbor", "multi-signer-role-step.sig"),
        ("owner-expiry-grant-step.cbor", "owner-expiry-grant-step.sig"),
    ] {
        let bytes = fs::read(output.join(name))?;
        let signature: [u8; 64] = fs::read(output.join(signature_name))?
            .try_into()
            .map_err(|_| std::io::Error::other("wrong root signature size"))?;
        let step = SignedStep::decode_verified(&bytes, signature, &root)?.step;
        assert_eq!(step.predecessor, predecessor);
        predecessor = step.digest()?;
    }
    let release = RoleGrant::decode(&fs::read(output.join("release-grant.cbor"))?)?;
    let unattended = RoleGrant::decode(&fs::read(output.join("unattended-grant.cbor"))?)?;
    let code_signing = RoleGrant::decode(&fs::read(output.join("code-signing-grant.cbor"))?)?;
    assert_eq!(code_signing.kind(), Kind::CodeSigning);
    code_signing.check_code_signing_identifier("org.agenxy.Remap")?;
    code_signing
        .check_code_signing_identifier(&fs::read_to_string(output.join("code-signing-identifier-exact.txt"))?)?;
    assert!(
        code_signing
            .check_code_signing_identifier(&fs::read_to_string(
                output.join("refuse-code-signing-prefix-identifier.txt")
            )?)
            .is_err()
    );
    assert!(code_signing.check_code_signing_identifier("org.agenxy.Other").is_err());
    assert!(
        code_signing
            .check_code_signing_identifier("org.agenxy.Remap.helper")
            .is_err()
    );
    let owner = Grant::decode(&fs::read(output.join("owner-grant.cbor"))?)?;
    let code_role_as_release =
        RoleGrant::decode(&fs::read(output.join("refuse-release-with-code-signing-grant.cbor"))?)?;
    assert_eq!(code_role_as_release.kind(), Kind::CodeSigning);
    let release_role_as_code =
        RoleGrant::decode(&fs::read(output.join("refuse-code-signing-with-release-grant.cbor"))?)?;
    assert!(
        release_role_as_code
            .check_code_signing_identifier("org.agenxy.Remap")
            .is_err()
    );
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
            now: VERIFY_AT,
            maximum_age: 600,
            policy: &policy,
            ledger: &ledger,
        },
    )?;
    let carried_bundle = ReleaseBundle::decode(&fs::read(output.join("release-authority.cbor"))?)?;
    for name in [
        "refuse-authority-owner-step-without-signature.cbor",
        "refuse-authority-owner-signature-without-step.cbor",
    ] {
        assert!(ReleaseBundle::decode(&fs::read(output.join(name))?).is_err(), "{name}");
    }
    let (bundled_role, bundled_owner) = carried_bundle.verify(
        &root,
        &Scope {
            hive,
            head: predecessor,
            member_floor: 0,
            grant_floor: 0,
            now: VERIFY_AT,
            maximum_age: 600,
            policy: &policy,
            ledger: &ledger,
        },
    )?;
    assert_eq!(bundled_role.id, release.id);
    assert_eq!(
        bundled_owner
            .ok_or_else(|| std::io::Error::other("missing bundled owner"))?
            .id,
        owner.id
    );
    let unattended_bundle = ReleaseBundle::decode(&fs::read(output.join("unattended-authority.cbor"))?)?;
    let (bundled_role, bundled_owner) = unattended_bundle.verify(
        &root,
        &Scope {
            hive,
            head: predecessor,
            member_floor: 0,
            grant_floor: 0,
            now: VERIFY_AT,
            maximum_age: 600,
            policy: &policy,
            ledger: &ledger,
        },
    )?;
    assert_eq!(bundled_role.id, unattended.id);
    assert!(bundled_owner.is_none());
    Ok(())
}

#[test]
fn committed_release_role_statement_cases() -> TestResult {
    let output = output_dir();
    let release = RoleGrant::decode(&fs::read(output.join("release-grant.cbor"))?)?;
    let unattended = RoleGrant::decode(&fs::read(output.join("unattended-grant.cbor"))?)?;
    let code_signing = RoleGrant::decode(&fs::read(output.join("code-signing-grant.cbor"))?)?;
    let code_role_as_release =
        RoleGrant::decode(&fs::read(output.join("refuse-release-with-code-signing-grant.cbor"))?)?;
    let owner = Grant::decode(&fs::read(output.join("owner-grant.cbor"))?)?;
    let status = SignedStatus::decode(&fs::read(output.join("status.cbor"))?)?;
    let challenge = Challenge::decode(&fs::read(output.join("release-challenge.cbor"))?)?;
    let request = fs::read(output.join("release-request.bin"))?;
    let assertion = Assertion::decode(&fs::read(output.join("release-assertion.cbor"))?)?;
    assertion.verify_binding(&owner, &challenge, &request, challenge.target, NOW)?;
    let content = Content::decode(&fs::read(output.join("release-content.cbor"))?)?;
    assert!(Content::decode(&fs::read(output.join("release-content-invalid-pre.cbor"))?).is_err());
    assert!(SignedStatement::decode(&fs::read(output.join("refuse-statement-over-thirty-days.cbor"))?).is_err());
    assert_eq!(request, content.encode()?);
    let carried = SignedStatement::decode(&fs::read(output.join("release-statement.cbor"))?)?;
    assert!(carried.content == content);
    let multi_role = RoleGrant::decode(&fs::read(output.join("multi-signer-role.cbor"))?)?;
    let multi_statement = SignedStatement::decode(&fs::read(output.join("multi-signer-statement.cbor"))?)?;
    multi_role.check_active_status(&status.status)?;
    multi_statement.check_role_policy(&multi_role, &["stable"], VERIFY_AT, None)?;
    let multi_request = fs::read(output.join("multi-signer-request.bin"))?;
    let multi_challenge = Challenge::decode(&fs::read(output.join("multi-signer-challenge.cbor"))?)?;
    assert_eq!(multi_request, multi_statement.content.encode()?);
    multi_statement
        .assertion
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing multi-signer assertion"))?
        .verify_binding(&owner, &multi_challenge, &multi_request, multi_challenge.target, NOW)?;
    let multi_keys = multi_role
        .signers
        .iter()
        .map(|signer| signer.key.clone())
        .collect::<Vec<_>>();
    multi_statement.verify_role_signatures(&multi_keys, 3)?;
    for name in ["refuse-unsorted-signers.cbor", "refuse-duplicate-signers.cbor"] {
        assert!(
            SignedStatement::decode(&fs::read(output.join(name))?).is_err(),
            "{name}"
        );
    }
    assert!(
        carried
            .check_role_policy(&code_role_as_release, &["stable"], VERIFY_AT, None)
            .is_err()
    );
    let artifact = fs::read(output.join("artifact.bin"))?;
    let expected_artifact = content
        .artifacts
        .first()
        .ok_or_else(|| std::io::Error::other("missing artifact"))?;
    assert_eq!(u64::try_from(artifact.len())?, expected_artifact.length);
    assert_eq!(Sha256::digest(&artifact).as_slice(), expected_artifact.sha256);
    carried.check_role_policy(&release, &["stable"], VERIFY_AT, None)?;
    carried.check_carried_authority(&owner, &status.status)?;
    assert!(
        carried
            .check_role_policy(&code_signing, &["stable"], NOW, None)
            .is_err()
    );
    let unattended_statement = SignedStatement::decode(&fs::read(output.join("unattended-statement.cbor"))?)?;
    unattended_statement.check_role_policy(&unattended, &["stable"], VERIFY_AT, None)?;
    assert!(
        unattended_statement
            .check_role_policy(&unattended, &["preview"], VERIFY_AT, None)
            .is_err()
    );
    let excess_assertion = SignedStatement::decode(&fs::read(output.join("refuse-unattended-with-assertion.cbor"))?)?;
    let excess_challenge = Challenge::decode(&fs::read(output.join("refuse-unattended-extra-challenge.cbor"))?)?;
    let excess_request = fs::read(output.join("refuse-unattended-extra-request.bin"))?;
    assert_eq!(excess_request, excess_assertion.content.encode()?);
    excess_assertion
        .assertion
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing forbidden assertion"))?
        .verify_binding(&owner, &excess_challenge, &excess_request, excess_challenge.target, NOW)?;
    let unattended_keys = unattended
        .signers
        .iter()
        .map(|signer| signer.key.clone())
        .collect::<Vec<_>>();
    excess_assertion.verify_role_signatures(&unattended_keys, usize::from(unattended.threshold))?;
    assert!(
        excess_assertion
            .check_role_policy(&unattended, &["stable"], VERIFY_AT, None)
            .is_err()
    );
    let missing_assertion = SignedStatement::decode(&fs::read(output.join("refuse-carried-missing-assertion.cbor"))?)?;
    assert!(
        missing_assertion
            .check_role_policy(&release, &["stable"], VERIFY_AT, None)
            .is_err()
    );
    let below_minimum = SignedStatement::decode(&fs::read(output.join("refuse-version-below-minimum.cbor"))?)?;
    assert!(
        below_minimum
            .check_role_policy(&release, &["stable"], VERIFY_AT, None)
            .is_err()
    );
    let mixed_artifact = SignedStatement::decode(&fs::read(output.join("refuse-mixed-artifact-statement.cbor"))?)?;
    mixed_artifact.check_role_policy(&release, &["stable"], VERIFY_AT, None)?;
    assert_ne!(
        Sha256::digest(&artifact).as_slice(),
        mixed_artifact
            .content
            .artifacts
            .first()
            .ok_or_else(|| std::io::Error::other("missing artifact"))?
            .sha256
    );
    Ok(())
}

#[test]
fn committed_release_role_revocation_and_high_water() -> TestResult {
    let output = output_dir();
    let root = fixture_root(&output)?;
    let hive = HiveId::from_root_verifying_key(&root);
    let release = RoleGrant::decode(&fs::read(output.join("release-grant.cbor"))?)?;
    let policy = SignedPolicy::decode(&fs::read(output.join("status-policy.cbor"))?)?;
    let ledger = Ledger::draft_new(&policy.policy)?;
    let predecessor = policy.policy.root_head;
    let content = Content::decode(&fs::read(output.join("release-content.cbor"))?)?;
    let carried = SignedStatement::decode(&fs::read(output.join("release-statement.cbor"))?)?;
    for name in ["refuse-revoked-role-status.cbor", "refuse-revoked-member-status.cbor"] {
        let revoked = SignedStatus::decode(&fs::read(output.join(name))?)?;
        revoked.verify(
            &root,
            &Scope {
                hive,
                head: predecessor,
                member_floor: 0,
                grant_floor: 0,
                now: VERIFY_AT,
                maximum_age: 600,
                policy: &policy,
                ledger: &ledger,
            },
        )?;
        assert!(release.check_active_status(&revoked.status).is_err(), "{name}");
    }
    assert!(
        carried
            .check_role_policy(&release, &["stable"], VERIFY_AT, Some(&content.version))
            .is_err()
    );
    let high_water: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("refuse-version-high-water.json"))?)?;
    assert_eq!(
        high_water.get("major").and_then(serde_json::Value::as_u64),
        Some(content.version.major)
    );
    assert_eq!(
        high_water.get("minor").and_then(serde_json::Value::as_u64),
        Some(content.version.minor)
    );
    assert_eq!(
        high_water.get("patch").and_then(serde_json::Value::as_u64),
        Some(content.version.patch)
    );
    assert_eq!(
        high_water.get("pre_label").and_then(serde_json::Value::as_str),
        content.version.pre.as_ref().map(|pre| pre.label.as_str())
    );
    assert_eq!(
        high_water.get("pre_number").and_then(serde_json::Value::as_u64),
        content.version.pre.as_ref().map(|pre| pre.number)
    );

    Ok(())
}

#[test]
fn committed_release_role_crypto_refusals() -> TestResult {
    let output = output_dir();
    let root = fixture_root(&output)?;
    let hive = HiveId::from_root_verifying_key(&root);
    let release = RoleGrant::decode(&fs::read(output.join("release-grant.cbor"))?)?;
    let policy = SignedPolicy::decode(&fs::read(output.join("status-policy.cbor"))?)?;
    let ledger = Ledger::draft_new(&policy.policy)?;
    let predecessor = policy.policy.root_head;
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
                    now: VERIFY_AT,
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
        "refuse-assertion-before-statement.cbor",
    ] {
        let changed = SignedStatement::decode(&fs::read(output.join(name))?)?;
        assert!(
            changed
                .check_role_policy(&release, &["stable"], VERIFY_AT, None)
                .is_err()
        );
    }
    let at_expiry = SignedStatement::decode(&fs::read(output.join("refuse-assertion-at-statement-expiry.cbor"))?)?;
    let owner_expiry = Grant::decode(&fs::read(output.join("owner-expiry-grant.cbor"))?)?;
    let status = SignedStatus::decode(&fs::read(output.join("status.cbor"))?)?;
    assert!(status.status.active_grants.contains(&owner_expiry.id));
    assert!(status.status.active_members.contains(&owner_expiry.signer_node));
    assert!(owner_expiry.not_before <= VERIFY_AT && VERIFY_AT <= owner_expiry.not_after);
    let expiry_request = fs::read(output.join("refuse-assertion-at-statement-expiry-request.bin"))?;
    let expiry_challenge = Challenge::decode(&fs::read(
        output.join("refuse-assertion-at-statement-expiry-challenge.cbor"),
    )?)?;
    assert_eq!(expiry_request, at_expiry.content.encode()?);
    let expiry_assertion = at_expiry
        .assertion
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing expiry assertion"))?;
    expiry_assertion.verify_binding(
        &owner_expiry,
        &expiry_challenge,
        &expiry_request,
        expiry_challenge.target,
        VERIFY_AT + 30,
    )?;
    assert!(at_expiry.content.issued_at <= VERIFY_AT && VERIFY_AT < at_expiry.content.expires_at);
    assert_eq!(at_expiry.content.expires_at, VERIFY_AT + 30);
    assert_eq!(expiry_assertion.issued_at, at_expiry.content.expires_at);
    let release_keys = release
        .signers
        .iter()
        .map(|signer| signer.key.clone())
        .collect::<Vec<_>>();
    at_expiry.verify_role_signatures(&release_keys, usize::from(release.threshold))?;
    assert!(
        at_expiry
            .check_role_policy(&release, &["stable"], VERIFY_AT, None)
            .is_err()
    );
    Ok(())
}

#[test]
fn committed_release_role_bundle_refuses_contextual_role_and_statement_cases() -> TestResult {
    let output = output_dir();
    let release = RoleGrant::decode(&fs::read(output.join("release-grant.cbor"))?)?;
    let cross_hive = RoleGrant::decode(&fs::read(output.join("refuse-cross-hive-grant.cbor"))?)?;
    assert_ne!(cross_hive.hive, release.hive);
    assert!(RoleGrant::decode(&fs::read(output.join("refuse-unattended-file-signer.cbor"))?).is_err());
    let default_channel = RoleGrant::decode(&fs::read(output.join("refuse-unattended-default-channel.cbor"))?)?;
    assert!(default_channel.check_default_channels(&["stable"]).is_err());
    let threshold_three = RoleGrant::decode(&fs::read(output.join("refuse-fewer-than-threshold-grant.cbor"))?)?;
    assert_eq!(threshold_three.threshold, 3);
    let fewer = SignedStatement::decode(&fs::read(output.join("refuse-fewer-than-threshold-statement.cbor"))?)?;
    assert_eq!(fewer.content.role_id, threshold_three.id);
    assert_eq!(fewer.signatures.len(), 1);
    let owner = Grant::decode(&fs::read(output.join("owner-grant.cbor"))?)?;
    let multi_request = fs::read(output.join("multi-signer-request.bin"))?;
    let multi_challenge = Challenge::decode(&fs::read(output.join("multi-signer-challenge.cbor"))?)?;
    assert_eq!(multi_request, fewer.content.encode()?);
    fewer
        .assertion
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing threshold refusal assertion"))?
        .verify_binding(&owner, &multi_challenge, &multi_request, multi_challenge.target, NOW)?;
    let status = SignedStatus::decode(&fs::read(output.join("status.cbor"))?)?;
    threshold_three.check_active_status(&status.status)?;
    let threshold_keys = threshold_three
        .signers
        .iter()
        .map(|signer| signer.key.clone())
        .collect::<Vec<_>>();
    assert!(fewer.verify_role_signatures(&threshold_keys, 3).is_err());
    assert!(
        fewer
            .check_role_policy(&threshold_three, &["stable"], VERIFY_AT, None)
            .is_err()
    );
    let wrong_consumer = SignedStatement::decode(&fs::read(output.join("refuse-wrong-consumer-statement.cbor"))?)?;
    assert!(
        wrong_consumer
            .check_role_policy(&release, &["stable"], VERIFY_AT, None)
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
                    now: VERIFY_AT,
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
    assert!(RootStep::decode(&stale_issuer).is_ok());
    assert!(SignedStep::decode_verified(&stale_issuer, stale_signature, &root).is_err());
    Ok(())
}

#[test]
fn invalid_root_signature_precedes_role_certificate_parsing() -> TestResult {
    let output = output_dir();
    let root = fixture_root(&output)?;
    let mut step = fs::read(output.join("code-signing-grant-step.cbor"))?;
    let certificate = fs::read(output.join("code-signing-cert.der"))?;
    let offset = step
        .windows(certificate.len())
        .position(|part| part == certificate)
        .ok_or_else(|| std::io::Error::other("missing certificate in step"))?;
    *step
        .get_mut(offset)
        .ok_or_else(|| std::io::Error::other("missing certificate byte"))? ^= 1;
    let signature: [u8; 64] = fs::read(output.join("code-signing-grant-step.sig"))?
        .try_into()
        .map_err(|_| std::io::Error::other("wrong signature size"))?;
    assert!(RootStep::decode(&step).is_ok());
    assert!(matches!(
        SignedStep::decode_verified(&step, signature, &root),
        Err(crate::threshold::Error::Proof)
    ));
    Ok(())
}
