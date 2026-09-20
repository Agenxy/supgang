use super::*;
use crate::threshold::{
    MAX_RECORDS,
    regroup::{Kind, Succession},
    step::{Outcome, Status},
};

#[test]
fn unknown_predecessor_recovery_is_authoritative_without_the_missing_chain() -> TestResult {
    let f = fixture(3)?;
    let mut advanced = f.chain.clone();
    advanced.accept(sign(&f.root, &proposal(&advanced, 1)?, &[1, 2])?)?;
    let successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let recovery = transition(&f, &advanced, &successor, Kind::Recovery)?;
    let mut stale = f.chain;
    assert_eq!(stale.accept(recovery.clone())?, Outcome::Accepted);
    assert_eq!(stale.order(), (1, 1, 2));
    assert_eq!(stale.active_digests(), &[recovery.step.digest()?]);
    Ok(())
}

#[test]
fn untrusted_pending_flood_is_bounded_and_cannot_change_authority() -> TestResult {
    let f = fixture(3)?;
    let mut chain = f.chain.clone();
    let mut step = proposal(&chain, 1)?;
    step.predecessor = [9; 32];
    for index in 0..MAX_RECORDS {
        step.proposed_at = u64::try_from(index)?;
        assert_eq!(
            chain.accept(SignedStep {
                step: step.clone(),
                signature: [0; 64]
            })?,
            Outcome::Held
        );
    }
    step.proposed_at += 1;
    assert!(matches!(
        chain.accept(SignedStep {
            step,
            signature: [0; 64]
        }),
        Err(Error::Bound)
    ));
    assert_eq!(chain.tip(), f.chain.tip());
    assert_eq!(chain.status(), Status::Active);
    assert!(chain.evidence().is_empty());
    Ok(())
}

#[test]
fn malformed_held_child_is_dropped_without_poisoning_a_valid_parent() -> TestResult {
    let f = fixture(3)?;
    let parent = sign(&f.root, &proposal(&f.chain, 1)?, &[1, 2])?;
    let mut producer = f.chain.clone();
    producer.accept(parent.clone())?;
    let invalid = SignedStep {
        step: proposal(&producer, 2)?,
        signature: [0; 64],
    };
    let mut receiver = f.chain;
    assert_eq!(receiver.accept(invalid)?, Outcome::Held);
    assert_eq!(receiver.accept(parent.clone())?, Outcome::Accepted);
    assert_eq!(receiver.tip(), parent.step.digest()?);
    assert_eq!(receiver.pending_count(), 0);
    assert_eq!(receiver.status(), Status::Active);
    Ok(())
}

#[test]
fn independent_recovery_is_required_and_recovery_forks_use_the_pre_rotation_key() -> TestResult {
    let f = fixture(3)?;
    let same = RecoveryDescriptor {
        sequence: 0,
        predecessor: [0; 32],
        group: f.root.descriptor()?.clone(),
    };
    assert!(Chain::new(f.root.descriptor()?.clone(), same).is_err());
    let successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let next_recovery = group(2, 3, 1, None)?;
    let mut step = transition(&f, &f.chain, &successor, Kind::Recovery)?.step;
    let mut payload = Succession::decode(&step.payload)?;
    payload.recovery = RecoveryDescriptor {
        sequence: 1,
        predecessor: f.chain.recovery().digest()?,
        group: next_recovery.descriptor()?.clone(),
    };
    let possession = payload.possession_step(&step)?;
    payload.possession = sign(&successor, &possession, &[1, 2])?.signature;
    payload.recovery_possession = sign(&next_recovery, &possession, &[1, 2])?.signature;
    step.payload = payload.encode()?;
    let first = sign(&f.recovery, &step, &[1, 2])?;
    let mut chain = f.chain.clone();
    chain.accept(first.clone())?;
    assert_eq!(chain.accept(first)?, Outcome::Duplicate);
    let conflict = transition(&f, &f.chain, &successor, Kind::Recovery)?;
    assert_eq!(chain.accept(conflict)?, Outcome::Fork);
    assert_eq!(chain.status(), Status::Halted);
    Ok(())
}

#[test]
fn session_history_bound_and_file_corruption_fail_closed() -> TestResult {
    let f = fixture(3)?;
    let step = proposal(&f.chain, 1)?;
    let directory = tempfile::tempdir()?;
    let mut participants = machines(&f.root, &step, &[1], directory.path())?;
    let machine = participants.values_mut().next().ok_or(Error::Invalid)?;
    for index in 0..MAX_RECORDS {
        let mut id = [0; 32];
        id.get_mut(..8)
            .ok_or(Error::Invalid)?
            .copy_from_slice(&u64::try_from(index)?.to_le_bytes());
        machine.propose(id, step.clone(), 100)?;
    }
    assert!(matches!(machine.propose([9; 32], step, 100), Err(Error::Bound)));
    drop(participants);
    let path = directory.path().join("1");
    std::fs::write(path.join("threshold.state"), [0_u8])?;
    assert!(
        FileSessionStore::open(
            path,
            Binding {
                hive: f.chain.hive(),
                group: f.root.descriptor()?.clone(),
                participant: 1
            }
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn recovery_can_select_the_other_authenticated_fork_branch() -> TestResult {
    let f = fixture(4)?;
    let first = sign(&f.root, &proposal(&f.chain, 1)?, &[1, 2])?;
    let other = sign(&f.root, &proposal(&f.chain, 2)?, &[3, 4])?;
    let mut forked = f.chain.clone();
    forked.accept(first.clone())?;
    assert_eq!(forked.accept(other.clone())?, Outcome::Fork);
    let mut selected = f.chain.clone();
    selected.accept(other.clone())?;
    let successor = group(2, 3, 1, Some(selected.recovery()))?;
    let recovery = transition(&f, &selected, &successor, Kind::Recovery)?;
    forked.accept(recovery.clone())?;
    assert_eq!(
        forked.active_digests(),
        &[other.step.digest()?, recovery.step.digest()?]
    );
    assert!(!forked.active_digests().contains(&first.step.digest()?));
    assert_eq!(forked.status(), Status::Active);
    Ok(())
}
