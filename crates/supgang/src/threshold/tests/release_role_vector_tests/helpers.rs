//! Disposable, deterministic public vector construction helpers.

use super::*;

pub(super) fn role_grant(
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

pub(super) fn release_policy(presence: ReleasePresence, number: u64) -> RolePolicy {
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

pub(super) fn owner_grant(
    hive: HiveId,
    id: u8,
    predecessor: [u8; 32],
    sequence: u64,
    target: NodeId,
    not_after: u64,
) -> Result<Grant, Box<dyn std::error::Error>> {
    let key = FileDeviceKey::from_secret_bytes(&[11; 32])?;
    let public = key.public_key();
    let mut grant = Grant {
        hive,
        id: [id; 16],
        kind: Kind::OwnerAction,
        consumer: "org.agenxy.supgang".into(),
        signer: public,
        signer_node: device_node_id(public),
        signer_role: SignerRole::OwnerPresence,
        signer_custody: SubjectCustody::Hardware,
        possession: [0; 64],
        not_before: NOW - 1000,
        not_after,
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

pub(super) fn root_step(
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

pub(super) fn content(hive: HiveId, role_id: [u8; 16], number: u64) -> Content {
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
            sha256: Sha256::digest([8_u8; 123]).into(),
        }],
        source_commit: vec![7; 20],
        provenance: Some([6; 32]),
        issued_at: NOW - 10,
        expires_at: NOW + 24 * 60 * 60,
    }
}

pub(super) fn save(
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

pub(super) fn resign_carried(
    statement: &mut SignedStatement,
    release_key: &FileDeviceKey,
    presence_key: &FileDeviceKey,
) -> TestResult {
    let content = statement.content.encode()?;
    statement
        .signatures
        .first_mut()
        .ok_or_else(|| std::io::Error::other("missing release signature"))?
        .bytes = release_key.sign_domain(RELEASE_DOMAIN, &content)?.to_bytes();
    let assertion = statement
        .assertion
        .as_mut()
        .ok_or_else(|| std::io::Error::other("missing carried assertion"))?;
    let mut digest = Sha256::new();
    digest.update(REQUEST_DOMAIN);
    digest.update(&content);
    assertion.request_digest = digest.finalize().into();
    assertion.signature = presence_key
        .sign_domain(ACTION_DOMAIN, &assertion.payload()?)?
        .to_bytes();
    Ok(())
}

pub(super) fn raw_statement(
    content: &[u8],
    assertion: &Assertion,
    signature: &[u8; 64],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut e = Encoder::new(Vec::new());
    e.array(4)?
        .u8(1)?
        .bytes(content)?
        .bytes(&assertion.encode()?)?
        .array(1)?
        .array(2)?
        .u8(0)?
        .bytes(signature)?;
    Ok(e.into_writer())
}

pub(super) fn raw_statement_signatures(
    content: &[u8],
    assertion: &Assertion,
    signatures: &[RoleSignature],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut e = Encoder::new(Vec::new());
    e.array(4)?
        .u8(1)?
        .bytes(content)?
        .bytes(&assertion.encode()?)?
        .array(u64::try_from(signatures.len())?)?;
    for signature in signatures {
        e.array(2)?.u8(signature.signer)?.bytes(&signature.bytes)?;
    }
    Ok(e.into_writer())
}
