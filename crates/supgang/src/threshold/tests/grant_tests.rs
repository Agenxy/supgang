use super::*;
use crate::{
    ids::{HiveId, NodeId},
    threshold::step::{
        Outcome,
        grant::{AllowedOperation, Grant, Kind, Presence, Revocation, SignerRole, TargetScope},
    },
};

fn owner_grant(chain: &Chain, id: u8) -> Result<Grant, Error> {
    let signer = FileDeviceKey::generate()?;
    let mut grant = Grant {
        hive: chain.hive(),
        id: [id; 16],
        kind: Kind::OwnerAction,
        consumer: "org.agenxy.Remap".into(),
        signer: signer.public_key(),
        signer_node: device_node_id(signer.public_key()),
        signer_role: SignerRole::OwnerPresence,
        possession: [0; 64],
        not_before: 100,
        not_after: 200,
        issuer_head: chain.tip(),
        issuer_sequence: chain.order().2,
        target: TargetScope::Node(NodeId::from_bytes([7; 32])),
        operations: vec![
            AllowedOperation {
                name: "remap.dns.activate".into(),
                presence: Presence::Required,
            },
            AllowedOperation {
                name: "remap.dns.deactivate".into(),
                presence: Presence::Required,
            },
        ],
    };
    grant.possession = signer
        .sign_domain(b"supgang/grant-possession/v1\0", &grant.possession_message()?)?
        .to_bytes();
    Ok(grant)
}

fn grant_step(chain: &Chain, grant: &Grant) -> Result<RootStep, Error> {
    let mut step = proposal(chain, 1)?;
    step.operation = Operation::Grant;
    step.payload = grant.encode()?;
    step.encode()?;
    Ok(step)
}

#[test]
fn typed_grant_and_monotonic_revocation_advance_only_under_root() -> TestResult {
    let f = fixture(3)?;
    let mut chain = f.chain;
    let grant = owner_grant(&chain, 1)?;
    assert_eq!(Grant::decode(&grant.encode()?)?.consumer, "org.agenxy.Remap");
    let signed = sign(&f.root, &grant_step(&chain, &grant)?, &[1, 2])?;
    assert_eq!(chain.accept(signed)?, Outcome::Accepted);
    assert!(chain.grant(&grant.id).is_some());
    let mut revoke_step = proposal(&chain, 2)?;
    revoke_step.operation = Operation::RevokeGrant;
    revoke_step.payload = Revocation {
        hive: chain.hive(),
        id: grant.id,
        kind: Kind::OwnerAction,
        serial: 1,
        issuer_head: chain.tip(),
        issuer_sequence: chain.order().2,
    }
    .encode()?;
    assert_eq!(chain.accept(sign(&f.root, &revoke_step, &[1, 2])?)?, Outcome::Accepted);
    assert!(chain.grant(&grant.id).is_none());
    assert_eq!(chain.grant_revocation_serial(), 1);
    let reused = owner_grant(&chain, 1)?;
    assert!(matches!(
        chain.accept(sign(&f.root, &grant_step(&chain, &reused)?, &[1, 2])?),
        Err(Error::Authority)
    ));
    Ok(())
}

#[test]
fn grant_refuses_cross_hive_stale_head_bad_proof_and_presence_downgrade() -> TestResult {
    let f = fixture(3)?;
    let chain = f.chain;
    let grant = owner_grant(&chain, 1)?;
    let mut bad = grant.clone();
    bad.hive = HiveId::from_bytes([3; 32]);
    assert!(grant_step(&chain, &bad).is_err());
    bad = grant.clone();
    bad.issuer_head = [4; 32];
    assert!(grant_step(&chain, &bad).is_err());
    bad = grant.clone();
    bad.possession = [0; 64];
    assert!(bad.encode().is_err());
    bad = grant.clone();
    bad.operations.first_mut().ok_or(Error::Invalid)?.name = "remap.dns.Activate".into();
    assert!(bad.encode().is_err());
    bad = grant;
    bad.signer_role = SignerRole::Device;
    assert!(bad.encode().is_err());
    Ok(())
}

#[test]
fn revoke_requires_active_matching_grant_and_exact_next_serial() -> TestResult {
    let f = fixture(3)?;
    let mut chain = f.chain;
    let grant = owner_grant(&chain, 1)?;
    let step = grant_step(&chain, &grant)?;
    chain.accept(sign(&f.root, &step, &[1, 2])?)?;
    for serial in [0, 2] {
        let mut step = proposal(&chain, 2)?;
        step.operation = Operation::RevokeGrant;
        let payload = Revocation {
            hive: chain.hive(),
            id: grant.id,
            kind: Kind::OwnerAction,
            serial,
            issuer_head: chain.tip(),
            issuer_sequence: chain.order().2,
        }
        .encode();
        if serial == 0 {
            assert!(payload.is_err());
        } else {
            step.payload = payload?;
            assert!(matches!(
                chain.accept(sign(&f.root, &step, &[1, 2])?),
                Err(Error::Authority)
            ));
        }
    }
    assert!(chain.grant(&grant.id).is_some());
    Ok(())
}
