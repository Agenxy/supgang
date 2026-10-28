use super::*;
use crate::{
    ids::NodeId,
    threshold::{
        owner_action::{Assertion, Challenge},
        status::{DOMAIN as STATUS_DOMAIN, Scope, SignedStatus, Status as RootStatus},
        step::grant::{AllowedOperation, Grant, Kind, Presence, SignerRole, TargetScope},
    },
};
use ed25519_dalek::Signer as _;
use sha2::{Digest as _, Sha256};

fn request_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"supgang/action-request/v1\0");
    hash.update(bytes);
    hash.finalize().into()
}

#[test]
fn required_remap_assertion_binds_exact_challenge_request_and_target() -> TestResult {
    let signer = FileDeviceKey::generate()?;
    let signer_key = signer.public_key();
    let signer_node = device_node_id(signer_key);
    let target = NodeId::from_bytes([8; 32]);
    let hive = crate::ids::HiveId::from_bytes([4; 32]);
    let mut grant = Grant {
        hive,
        id: [5; 16],
        kind: Kind::OwnerAction,
        consumer: "org.agenxy.remap".into(),
        signer: signer_key,
        signer_node,
        signer_role: SignerRole::OwnerPresence,
        possession: [0; 64],
        not_before: 100,
        not_after: 600,
        issuer_head: [6; 32],
        issuer_sequence: 3,
        target: TargetScope::Node(target),
        operations: vec![AllowedOperation {
            name: "remap.dns.activate".into(),
            presence: Presence::Required,
        }],
    };
    grant.possession = signer
        .sign_domain(b"supgang/grant-possession/v1\0", &grant.possession_message()?)?
        .to_bytes();
    let request = b"remap-plan-v1:exact-args-and-observed-state".to_vec();
    let challenge = Challenge {
        target,
        consumer: grant.consumer.clone(),
        operation: "remap.dns.activate".into(),
        grant_id: grant.id,
        request: request.clone(),
        nonce: [9; 16],
        expires_at: 210,
    };
    let mut assertion = Assertion {
        hive,
        signer_node,
        signer_key,
        grant_id: grant.id,
        target,
        consumer: grant.consumer.clone(),
        operation: challenge.operation.clone(),
        request_digest: request_digest(&request),
        challenge_digest: challenge.digest()?,
        nonce: challenge.nonce,
        issued_at: 150,
        expires_at: 200,
        signature: [0; 64],
    };
    assertion.signature = signer
        .sign_domain(b"supgang/owner-action/v1\0", &assertion.payload()?)?
        .to_bytes();
    let decoded = Assertion::decode(&assertion.encode()?)?;
    decoded.verify_binding(&grant, &challenge, &request, target, 160)?;
    assert!(
        decoded
            .verify_binding(&grant, &challenge, b"changed-plan", target, 160)
            .is_err()
    );
    assert!(
        decoded
            .verify_binding(&grant, &challenge, &request, NodeId::from_bytes([7; 32]), 160)
            .is_err()
    );
    assert!(
        decoded
            .verify_binding(&grant, &challenge, &request, target, 211)
            .is_err()
    );
    let mut downgraded = grant;
    downgraded.operations.first_mut().ok_or(Error::Invalid)?.presence = Presence::Policy;
    assert!(
        decoded
            .verify_binding(&downgraded, &challenge, &request, target, 160)
            .is_err()
    );
    Ok(())
}

#[test]
fn shared_status_requires_root_signature_current_head_serial_and_bounded_age() -> TestResult {
    let key = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
    let hive = crate::ids::HiveId::from_root_verifying_key(&key.verifying_key().to_bytes());
    let status = RootStatus {
        hive,
        root_head: [3; 32],
        member_serial: 4,
        grant_serial: 5,
        issued_at: 100,
        expires_at: 160,
    };
    let mut message = STATUS_DOMAIN.to_vec();
    message.extend_from_slice(&status.encode()?);
    let signed = SignedStatus {
        status,
        signature: key.sign(&message).to_bytes(),
    };
    assert!(SignedStatus::decode(&signed.encode()?)? == signed);
    let scope = Scope {
        hive,
        head: [3; 32],
        member_floor: 4,
        grant_floor: 5,
        now: 130,
        maximum_age: 60,
    };
    signed.verify(&key.verifying_key().to_bytes(), &scope)?;
    let mut wrong = scope;
    wrong.head = [9; 32];
    assert!(signed.verify(&key.verifying_key().to_bytes(), &wrong).is_err());
    wrong = scope;
    wrong.member_floor = 5;
    assert!(signed.verify(&key.verifying_key().to_bytes(), &wrong).is_err());
    wrong = scope;
    wrong.now = 161;
    assert!(signed.verify(&key.verifying_key().to_bytes(), &wrong).is_err());
    wrong = scope;
    wrong.maximum_age = 30;
    assert!(signed.verify(&key.verifying_key().to_bytes(), &wrong).is_err());
    let mut forged = signed;
    forged.signature = [0; 64];
    assert!(forged.verify(&key.verifying_key().to_bytes(), &scope).is_err());
    Ok(())
}
