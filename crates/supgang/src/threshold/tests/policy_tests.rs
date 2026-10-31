use super::*;
use crate::threshold::{
    regroup::{Kind, Succession},
    session::{ChainPolicy, Policy as _, Role},
};

fn binding(group: &Group, chain: &Chain) -> Result<Binding, Error> {
    Ok(Binding {
        hive: chain.hive(),
        group: group.descriptor()?.clone(),
        participant: 1,
    })
}

#[test]
fn default_policy_checks_sequence_role_reserved_tags_and_payloads() -> TestResult {
    let f = fixture(3)?;
    let policy = ChainPolicy {
        chain: &f.chain,
        role: Role::Root,
    };
    let root = binding(&f.root, &f.chain)?;
    let valid = proposal(&f.chain, 1)?;
    policy.review(&root, &valid)?;
    assert!(policy.review(&binding(&f.recovery, &f.chain)?, &valid).is_err());
    let mut wrong = valid.clone();
    wrong.sequence += 1;
    assert!(policy.review(&root, &wrong).is_err());
    wrong = valid.clone();
    wrong.payload.clear();
    assert!(policy.review(&root, &wrong).is_err());
    for operation in [Operation::Reshare, Operation::SetRecoveryGroup, Operation::Succession] {
        wrong = valid.clone();
        wrong.operation = operation;
        assert!(policy.review(&root, &wrong).is_err());
    }
    let successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let valid = transition(&f, &f.chain, &successor, Kind::Planned)?.step;
    policy.review(&root, &valid)?;
    let mut payload = Succession::decode(&valid.payload)?;
    payload.recovery.sequence += 1;
    wrong = valid.clone();
    wrong.payload = payload.encode()?;
    assert!(policy.review(&root, &wrong).is_err());
    payload = Succession::decode(&valid.payload)?;
    payload.possession = [0; 64];
    wrong.payload = payload.encode()?;
    assert!(policy.review(&root, &wrong).is_err());
    Ok(())
}

#[test]
fn successor_possession_is_distinct_from_recovery_authorization() -> TestResult {
    let f = fixture(3)?;
    let successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let x = transition(&f, &f.chain, &successor, Kind::Recovery)?.step;
    let mut other = f.chain.clone();
    other.accept(sign(&f.root, &proposal(&other, 8)?, &[1, 2])?)?;
    let y = transition(&f, &other, &successor, Kind::Recovery)?.step;
    let directory = tempfile::tempdir()?;
    let mut participants = machines(&successor, &x, &[1, 2], directory.path())?;
    for (step, chain, now) in [(&x, &f.chain, 100), (&y, &other, 1000)] {
        let proof = Succession::decode(&step.payload)?.possession_step(step)?;
        let policy = ChainPolicy {
            chain,
            role: Role::SuccessorPossession,
        };
        let package = prepare_reviewed(&successor, &proof, &mut participants, now, &policy)?;
        finish(&successor, &proof, &mut participants, &package, now + 1)?;
    }
    for participant in participants.values() {
        assert!(
            participant
                .snapshot()
                .records
                .iter()
                .all(|r| r.permanent && r.review.is_some_and(|r| r.role == Role::SuccessorPossession))
        );
    }
    let policy = ChainPolicy {
        chain: &f.chain,
        role: Role::Recovery,
    };
    assert!(policy.review(&binding(&successor, &f.chain)?, &x).is_err());
    Ok(())
}

#[test]
fn recovery_rotation_policy_requires_both_possessions() -> TestResult {
    let f = fixture(3)?;
    let successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let replacement = group(2, 3, 1, None)?;
    let mut step = transition(&f, &f.chain, &successor, Kind::Recovery)?.step;
    let mut payload = Succession::decode(&step.payload)?;
    payload.recovery = RecoveryDescriptor {
        sequence: 1,
        predecessor: f.chain.recovery().digest()?,
        group: replacement.descriptor()?.clone(),
    };
    let proof = payload.possession_step(&step)?;
    let directory = tempfile::tempdir()?;
    let mut participants = machines(&replacement, &proof, &[1, 2], directory.path())?;
    let package = prepare_reviewed(
        &replacement,
        &proof,
        &mut participants,
        100,
        &ChainPolicy {
            chain: &f.chain,
            role: Role::RecoveryPossession,
        },
    )?;
    payload.recovery_possession = finish(&replacement, &proof, &mut participants, &package, 101)?.signature;
    payload.possession = sign(&successor, &proof, &[1, 2])?.signature;
    step.payload = payload.encode()?;
    let policy = ChainPolicy {
        chain: &f.chain,
        role: Role::Recovery,
    };
    let authority = binding(&f.recovery, &f.chain)?;
    policy.review(&authority, &step)?;
    payload.recovery_possession = [0; 64];
    step.payload = payload.encode()?;
    assert!(policy.review(&authority, &step).is_err());
    Ok(())
}
