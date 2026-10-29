//! Regenerate DRAFT provider-level wire vectors using disposable test keys.
//!
//! Run the ignored generator test from the repository root with:
//! `cargo test --locked --package supgang-core generate_owner_action_vectors -- --ignored`
//! Fixed scalars here are public test fixtures, never production identities.

use std::{fs, path::Path};

use crate::{
    authority::SubjectCustody,
    authority::device_node_id,
    device_key::{DeviceSigner as _, FileDeviceKey},
    ids::{HiveId, NodeId},
    threshold::{
        owner_action::{Assertion, Challenge},
        status::{DOMAIN as STATUS_DOMAIN, SignedStatus, Status},
        status_renewal::{
            Counts, Mode, OWNER_MAX_AGE, OWNER_POLICY_CAP, OWNER_PRESENCE_CAP, OWNER_TOTAL_CAP, POLICY_DOMAIN, Policy,
            SignedPolicy,
        },
        step::{
            Operation, RootStep,
            grant::{AllowedOperation, Grant, Kind, Presence, SignerRole, TargetScope},
        },
    },
};
use ed25519_dalek::Signer as _;
use serde_json::json;
use sha2::{Digest as _, Sha256};

const OUTPUT: &str = "docs/vectors/owner-action-draft-v1";

#[test]
fn committed_draft_vector_hashes_match_manifest() -> Result<(), Box<dyn std::error::Error>> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(OUTPUT);
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(directory.join("manifest.json"))?)?;
    assert_eq!(
        manifest.get("state").and_then(serde_json::Value::as_str),
        Some("DRAFT - NOT FROZEN")
    );
    let files = manifest
        .get("files")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| std::io::Error::other("draft vector manifest has no file list"))?;
    assert_eq!(files.len(), 12);
    for entry in files {
        let name = entry["file"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("draft vector has no file name"))?;
        if name.contains('/') || name.contains('\\') || name.starts_with('.') {
            return Err(std::io::Error::other("draft vector file name is not a flat name").into());
        }
        let bytes = fs::read(directory.join(name))?;
        if Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("cbor"))
        {
            assert_one_cbor_item(&bytes)?;
        }
        assert_eq!(entry["bytes"].as_u64(), u64::try_from(bytes.len()).ok());
        assert_eq!(entry["sha256"].as_str(), Some(sha256(&bytes).as_str()));
    }
    Ok(())
}

#[test]
fn committed_draft_vectors_verify_and_refuse_the_named_mutations() -> Result<(), Box<dyn std::error::Error>> {
    use crate::threshold::{
        status::Scope,
        status_renewal::Ledger,
        step::{SignedStep, grant::Grant},
    };

    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(OUTPUT);
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(directory.join("manifest.json"))?)?;
    let root_bytes = hex::decode(
        manifest
            .get("root_public_key_hex")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| std::io::Error::other("missing root key"))?,
    )?;
    let root_key: [u8; 32] = root_bytes
        .try_into()
        .map_err(|_| std::io::Error::other("wrong root-key length"))?;
    let hive = HiveId::from_root_verifying_key(&root_key);
    let grant = Grant::decode(&fs::read(directory.join("grant.cbor"))?)?;
    let step = RootStep::decode(&fs::read(directory.join("grant-step.cbor"))?)?;
    let signature: [u8; 64] = fs::read(directory.join("grant-step.sig"))?
        .try_into()
        .map_err(|_| std::io::Error::other("wrong root signature length"))?;
    SignedStep {
        step: step.clone(),
        signature,
    }
    .verify(&root_key)?;
    assert_eq!(grant.encode()?, step.payload);
    let policy = SignedPolicy::decode(&fs::read(directory.join("status-policy.cbor"))?)?;
    policy.verify(&root_key, hive, step.digest()?)?;
    let status = SignedStatus::decode(&fs::read(directory.join("status.cbor"))?)?;
    let ledger = Ledger::draft_new(&policy.policy)?;
    let scope = Scope {
        hive,
        head: step.digest()?,
        member_floor: 0,
        grant_floor: 0,
        now: 1020,
        maximum_age: 600,
        policy: &policy,
        ledger: &ledger,
    };
    status.verify(&root_key, &scope)?;
    let challenge = Challenge::decode(&fs::read(directory.join("challenge.cbor"))?)?;
    let request = fs::read(directory.join("request.bin"))?;
    let assertion = Assertion::decode(&fs::read(directory.join("assertion.cbor"))?)?;
    assertion.verify_binding(&grant, &challenge, &request, challenge.target, 1020)?;
    for name in ["assertion-wrong-case.cbor", "assertion-wrong-request.cbor"] {
        let changed = Assertion::decode(&fs::read(directory.join(name))?)?;
        assert!(
            changed
                .verify_binding(&grant, &challenge, &request, challenge.target, 1020)
                .is_err()
        );
    }
    for name in ["status-bad-signature.cbor", "status-wrong-budget.cbor"] {
        let changed = SignedStatus::decode(&fs::read(directory.join(name))?)?;
        assert!(changed.verify(&root_key, &scope).is_err());
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn assert_one_cbor_item(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = minicbor::Decoder::new(bytes);
    read_generic_cbor_item(&mut reader, 0)?;
    if reader.position() != bytes.len() {
        return Err(std::io::Error::other("CBOR record has trailing data or a wrong declared array length").into());
    }
    Ok(())
}

fn read_generic_cbor_item(reader: &mut minicbor::Decoder<'_>, depth: usize) -> Result<(), Box<dyn std::error::Error>> {
    use minicbor::data::Type;

    if depth > 16 {
        return Err(std::io::Error::other("CBOR nesting limit exceeded").into());
    }
    match reader.datatype()? {
        Type::Array => {
            let count = reader
                .array()?
                .ok_or_else(|| std::io::Error::other("indefinite CBOR array"))?;
            if count > 1024 {
                return Err(std::io::Error::other("CBOR item count limit exceeded").into());
            }
            for _ in 0..count {
                read_generic_cbor_item(reader, depth + 1)?;
            }
        }
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
            reader.u64()?;
        }
        Type::Bytes => {
            reader.bytes()?;
        }
        Type::String => {
            reader.str()?;
        }
        Type::Null => {
            reader.null()?;
        }
        _ => return Err(std::io::Error::other("unsupported CBOR type in wire fixture").into()),
    }
    Ok(())
}

#[test]
fn generic_cbor_reader_rejects_a_wrong_grant_array_length() -> Result<(), Box<dyn std::error::Error>> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(OUTPUT);
    let mut grant = fs::read(directory.join("grant.cbor"))?;
    assert_one_cbor_item(&grant)?;
    let top = grant
        .first_mut()
        .ok_or_else(|| std::io::Error::other("empty grant fixture"))?;
    assert_eq!(*top, 0x8c, "grant must be a definite 12-field CBOR array");
    *top = 0x8b;
    assert!(assert_one_cbor_item(&grant).is_err());
    Ok(())
}

#[test]
#[ignore = "regenerates committed draft vector files only when explicitly requested"]
fn generate_owner_action_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let output_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(OUTPUT);
    let output = output_dir.as_path();
    fs::create_dir_all(output)?;
    let root = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    let root_public = root.verifying_key().to_bytes();
    let hive = HiveId::from_root_verifying_key(&root_public);
    let signer = FileDeviceKey::from_secret_bytes(&[7; 32])?;
    let signer_key = signer.public_key();
    let signer_node = device_node_id(signer_key);
    let target = NodeId::from_bytes([8; 32]);
    let predecessor = [4; 32];
    let mut grant = Grant {
        hive,
        id: [5; 16],
        kind: Kind::OwnerAction,
        consumer: "org.agenxy.Remap".into(),
        signer: signer_key,
        signer_node,
        signer_role: SignerRole::OwnerPresence,
        signer_custody: SubjectCustody::Hardware,
        possession: [0; 64],
        not_before: 100,
        not_after: 1_000_000,
        issuer_head: predecessor,
        issuer_sequence: 0,
        target: TargetScope::Node(target),
        operations: [
            "remap.dns.activate",
            "remap.dns.deactivate",
            "remap.system.recover",
            "remap.system.update",
        ]
        .into_iter()
        .map(|name| AllowedOperation {
            name: name.into(),
            presence: Presence::Required,
        })
        .collect(),
    };
    grant.possession = signer
        .sign_domain(b"supgang/role-possession/v1\0", &grant.possession_message()?)?
        .to_bytes();
    let grant_bytes = grant.encode()?;
    let step = RootStep {
        hive,
        predecessor,
        sequence: 1,
        epoch: 0,
        recovery_gen: 0,
        operation: Operation::Grant,
        payload: grant_bytes.clone(),
        proposed_at: 100,
        proposer: signer_node,
    };
    let step_bytes = step.encode()?;
    let step_signature = root.sign(&step.message()?).to_bytes();
    let head = step.digest()?;
    let policy = Policy {
        hive,
        root_head: head,
        budget_id: [9; 16],
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
        active_grants: vec![grant.id],
        active_members: vec![signer_node],
        issued_at: 1000,
        expires_at: 1600,
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
    let request = b"draft-provider-request-not-remap-canonical-v1".to_vec();
    let challenge = Challenge {
        target,
        consumer: grant.consumer.clone(),
        operation: "remap.dns.activate".into(),
        grant_id: grant.id,
        request: request.clone(),
        nonce: [10; 16],
        expires_at: 1050,
    };
    let mut request_hash = Sha256::new();
    request_hash.update(b"supgang/action-request/v1\0");
    request_hash.update(&request);
    let mut assertion = Assertion {
        hive,
        signer_node,
        signer_key,
        grant_id: grant.id,
        target,
        consumer: grant.consumer.clone(),
        operation: challenge.operation.clone(),
        request_digest: request_hash.finalize().into(),
        challenge_digest: challenge.digest()?,
        nonce: challenge.nonce,
        issued_at: 1010,
        expires_at: 1040,
        signature: [0; 64],
    };
    assertion.signature = signer
        .sign_domain(b"supgang/owner-action/v1\0", &assertion.payload()?)?
        .to_bytes();
    assertion.verify_binding(&grant, &challenge, &request, target, 1020)?;

    let mut files = Vec::new();
    save(
        output,
        &mut files,
        "grant.cbor",
        &grant_bytes,
        "accept: typed grant payload",
    )?;
    save(
        output,
        &mut files,
        "grant-step.cbor",
        &step_bytes,
        "accept: root step content",
    )?;
    save(
        output,
        &mut files,
        "grant-step.sig",
        &step_signature,
        "accept: root signature over step domain and content",
    )?;
    save(
        output,
        &mut files,
        "status-policy.cbor",
        &signed_policy.encode()?,
        "accept: root-signed draft renewal terms",
    )?;
    save(
        output,
        &mut files,
        "status.cbor",
        &signed_status.encode()?,
        "accept: root-signed initial lease at time 1020",
    )?;
    save(
        output,
        &mut files,
        "challenge.cbor",
        &challenge.encode()?,
        "accept: provider-level target challenge",
    )?;
    save(
        output,
        &mut files,
        "request.bin",
        &request,
        "accept: opaque provider-level request bytes",
    )?;
    save(
        output,
        &mut files,
        "assertion.cbor",
        &assertion.encode()?,
        "accept: exact grant/challenge/request binding at time 1020",
    )?;

    let mut wrong_case = assertion.clone();
    wrong_case.consumer = "org.agenxy.remap".into();
    wrong_case.signature = signer
        .sign_domain(b"supgang/owner-action/v1\0", &wrong_case.payload()?)?
        .to_bytes();
    save(
        output,
        &mut files,
        "assertion-wrong-case.cbor",
        &wrong_case.encode()?,
        "reject: case-folded consumer identity",
    )?;
    let mut wrong_digest = assertion;
    wrong_digest.request_digest = [11; 32];
    wrong_digest.signature = signer
        .sign_domain(b"supgang/owner-action/v1\0", &wrong_digest.payload()?)?
        .to_bytes();
    save(
        output,
        &mut files,
        "assertion-wrong-request.cbor",
        &wrong_digest.encode()?,
        "reject: changed canonical request digest",
    )?;
    let mut bad_status = signed_status.clone();
    bad_status.signature[0] ^= 1;
    save(
        output,
        &mut files,
        "status-bad-signature.cbor",
        &bad_status.encode()?,
        "reject: invalid root signature",
    )?;
    let mut wrong_budget = signed_status;
    wrong_budget.status.budget_id = [12; 16];
    let mut wrong_budget_message = STATUS_DOMAIN.to_vec();
    wrong_budget_message.extend_from_slice(&wrong_budget.status.encode()?);
    wrong_budget.signature = root.sign(&wrong_budget_message).to_bytes();
    save(
        output,
        &mut files,
        "status-wrong-budget.cbor",
        &wrong_budget.encode()?,
        "reject: signed lease names another budget",
    )?;

    let manifest = json!({
        "state": "DRAFT - NOT FROZEN",
        "protocol": "owner-action-v1-proposal",
        "source_commit": "regenerate from current source; no immutable commit pin yet",
        "note": "Disposable test keys. Request bytes are opaque Supgang-provider input, not a canonical Remap effect request. No live issuer or physical acceptance is claimed.",
        "root_public_key_hex": hex::encode(root_public),
        "hive_hex": hex::encode(hive.as_bytes()),
        "signer_public_key_hex": hex::encode(signer_key.to_bytes()),
        "target_hex": hex::encode(target.as_bytes()),
        "root_head_hex": hex::encode(head),
        "verification_time": 1020,
        "pending": ["durable current-head issuer and target ledgers", "release-role codec and conformance vectors", "physical hardware proof"],
        "files": files,
    });
    fs::write(output.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}

fn save(
    output: &Path,
    files: &mut Vec<serde_json::Value>,
    name: &str,
    bytes: &[u8],
    expectation: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(output.join(name), bytes)?;
    files.push(json!({
        "file": name,
        "sha256": sha256(bytes),
        "bytes": bytes.len(),
        "expectation": expectation,
    }));
    Ok(())
}
