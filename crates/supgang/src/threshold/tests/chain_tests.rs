use super::*;
use crate::threshold::{
    regroup::{Kind, Succession},
    step::{Outcome, Status},
};

#[test]
fn unknown_predecessor_is_held_then_accepted_when_the_chain_arrives() -> TestResult {
    let f = fixture(3)?;
    let first = sign(&f.root, &proposal(&f.chain, 1)?, &[1, 2])?;
    let mut producer = f.chain.clone();
    producer.accept(first.clone())?;
    let second = sign(&f.root, &proposal(&producer, 2)?, &[1, 2])?;
    let expected = second.step.digest()?;
    let mut receiver = f.chain;
    assert_eq!(receiver.accept(second)?, Outcome::Held);
    assert_eq!(receiver.pending_count(), 1);
    assert_eq!(receiver.order(), (0, 0, 0));
    assert_eq!(receiver.accept(first.clone())?, Outcome::Accepted);
    assert_eq!(receiver.tip(), expected);
    assert_eq!(receiver.pending_count(), 0);
    assert_eq!(receiver.accept(first)?, Outcome::Duplicate);
    Ok(())
}

#[test]
fn disjoint_honest_two_of_four_quorums_fork_and_halt() -> TestResult {
    let f = fixture(4)?;
    let a = sign(&f.root, &proposal(&f.chain, 1)?, &[1, 2])?;
    let b = sign(&f.root, &proposal(&f.chain, 2)?, &[3, 4])?;
    let mut chain = f.chain;
    assert_eq!(chain.accept(a.clone())?, Outcome::Accepted);
    assert_eq!(chain.accept(b.clone())?, Outcome::Fork);
    assert_eq!(chain.status(), Status::Halted);
    assert!(chain.evidence().contains_key(&a.step.digest()?));
    assert!(chain.evidence().contains_key(&b.step.digest()?));
    assert!(matches!(
        chain.accept(sign(&f.root, &proposal(&chain, 3)?, &[1, 2])?),
        Err(Error::Halted)
    ));
    Ok(())
}

#[test]
fn intersecting_two_of_three_fork_requires_a_faulty_signer_and_halts() -> TestResult {
    let f = fixture(3)?;
    // B deliberately starts with a fresh store for the second operation. This
    // models a faulty signer violating the permanent-lock contract, not recovery.
    let a = sign(&f.root, &proposal(&f.chain, 1)?, &[1, 2])?;
    let b = sign(&f.root, &proposal(&f.chain, 2)?, &[2, 3])?;
    let mut chain = f.chain;
    chain.accept(a)?;
    assert_eq!(chain.accept(b)?, Outcome::Fork);
    assert_eq!(chain.evidence().len(), 2);
    Ok(())
}

#[test]
fn invalid_signature_or_invalid_sequence_cannot_manufacture_a_fork() -> TestResult {
    let f = fixture(3)?;
    let a = sign(&f.root, &proposal(&f.chain, 1)?, &[1, 2])?;
    let mut chain = f.chain.clone();
    chain.accept(a)?;
    let mut forged = sign(&f.root, &proposal(&f.chain, 2)?, &[1, 2])?;
    forged.signature = [0; 64];
    assert!(chain.accept(forged).is_err());
    let mut malformed = proposal(&f.chain, 2)?;
    malformed.sequence = 8;
    assert!(chain.accept(sign(&f.root, &malformed, &[1, 2])?).is_err());
    assert_eq!(chain.status(), Status::Active);
    assert_eq!(chain.evidence().len(), 1);
    Ok(())
}

#[test]
fn regroup_advances_epoch_and_sequence_keeps_hive_and_exposes_stale_peer_window() -> TestResult {
    let f = fixture(3)?;
    let new_devices = devices(4)?;
    let successor = crate::threshold::regroup::fresh_dkg(
        f.root.descriptor()?,
        Parameters {
            k: 2,
            n: 4,
            accept_single_loss_failure: false,
        },
        &new_devices.iter().map(FileDeviceKey::public_key).collect::<Vec<_>>(),
        f.chain.recovery(),
        |_, _| {},
    )?;
    let succession = transition(&f, &f.chain, &successor, Kind::Planned)?;
    let mut current = f.chain.clone();
    current.accept(succession.clone())?;
    assert_eq!(current.hive(), f.chain.hive());
    assert_eq!(current.order(), (0, 1, 1));
    let next = proposal(&current, 3)?;
    assert_eq!(next.predecessor, succession.step.digest()?);
    assert_eq!(next.sequence, 2);
    assert!(current.accept(sign(&f.root, &next, &[1, 2])?).is_err());
    current.accept(sign(&successor, &next, &[1, 2])?)?;
    let mut stale = f.chain.clone();
    let old_branch = sign(&f.root, &proposal(&stale, 4)?, &[1, 2])?;
    assert_eq!(stale.accept(old_branch)?, Outcome::Accepted);
    assert_eq!(stale.group().public_key, f.root.descriptor()?.public_key);
    Ok(())
}

#[test]
fn planned_succession_requires_possession_and_preserves_pinned_recovery() -> TestResult {
    let f = fixture(3)?;
    let successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let valid = transition(&f, &f.chain, &successor, Kind::Planned)?;
    let mut without_possession = valid.step.clone();
    let mut payload = Succession::decode(&without_possession.payload)?;
    payload.possession = [0; 64];
    without_possession.payload = payload.encode()?;
    assert!(
        f.chain
            .clone()
            .accept(sign(&f.root, &without_possession, &[1, 2])?)
            .is_err()
    );
    let mut changed = valid.step;
    let mut payload = Succession::decode(&changed.payload)?;
    payload.recovery.sequence += 1;
    payload.possession = sign(&successor, &payload.possession_step(&changed)?, &[1, 2])?.signature;
    changed.payload = payload.encode()?;
    assert!(f.chain.clone().accept(sign(&f.root, &changed, &[1, 2])?).is_err());
    Ok(())
}

#[test]
fn recovery_discards_planned_descendants_and_outranks_their_epochs() -> TestResult {
    let f = fixture(3)?;
    let planned_group = group(2, 3, 1, Some(f.chain.recovery()))?;
    let planned = transition(&f, &f.chain, &planned_group, Kind::Planned)?;
    let mut advanced = f.chain.clone();
    advanced.accept(planned.clone())?;
    let next = sign(&planned_group, &proposal(&advanced, 5)?, &[1, 2])?;
    advanced.accept(next.clone())?;
    let rescued_group = group(2, 3, 1, Some(f.chain.recovery()))?;
    let rescue = transition(&f, &f.chain, &rescued_group, Kind::Recovery)?;
    advanced.accept(rescue.clone())?;
    assert_eq!(advanced.order(), (1, 1, 1));
    assert_eq!(advanced.active_digests(), &[rescue.step.digest()?]);
    assert!(!advanced.active_digests().contains(&planned.step.digest()?));
    assert!(!advanced.active_digests().contains(&next.step.digest()?));
    assert_eq!(advanced.accept(rescue)?, Outcome::Duplicate);
    assert!(advanced.accept(planned).is_err());
    assert_eq!(advanced.hive(), f.chain.hive());
    let mut old_high_epoch = proposal(&advanced, 6)?;
    old_high_epoch.recovery_gen = 0;
    old_high_epoch.epoch = u64::MAX;
    assert!(
        advanced
            .accept(sign(&planned_group, &old_high_epoch, &[1, 2])?)
            .is_err()
    );
    Ok(())
}

#[test]
fn recovery_clears_an_ordinary_fork_but_a_recovery_fork_halts_permanently() -> TestResult {
    let f = fixture(3)?;
    let mut chain = f.chain.clone();
    chain.accept(sign(&f.root, &proposal(&f.chain, 1)?, &[1, 2])?)?;
    chain.accept(sign(&f.root, &proposal(&f.chain, 2)?, &[2, 3])?)?;
    let successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let rescue = transition(&f, &f.chain, &successor, Kind::Recovery)?;
    chain.accept(rescue)?;
    assert_eq!(chain.status(), Status::Active);
    let other_successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let conflict = transition(&f, &f.chain, &other_successor, Kind::Recovery)?;
    assert_eq!(chain.accept(conflict)?, Outcome::Fork);
    assert_eq!(chain.status(), Status::Halted);
    let next_rescue = transition(&f, &chain, &other_successor, Kind::Recovery)?;
    assert!(matches!(chain.accept(next_rescue), Err(Error::Halted)));
    Ok(())
}

#[test]
fn ordinary_root_cannot_set_recovery_group_or_advance_recovery_generation() -> TestResult {
    let f = fixture(3)?;
    let mut step = proposal(&f.chain, 1)?;
    step.operation = Operation::SetRecoveryGroup;
    assert!(matches!(
        f.chain.clone().accept(sign(&f.root, &step, &[1, 2])?),
        Err(Error::Authority)
    ));
    step.operation = Operation::IssueMembership;
    step.recovery_gen += 1;
    assert!(f.chain.clone().accept(sign(&f.root, &step, &[1, 2])?).is_err());
    let successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let rescue = transition(&f, &f.chain, &successor, Kind::Recovery)?;
    assert!(f.chain.clone().accept(sign(&f.root, &rescue.step, &[1, 2])?).is_err());
    Ok(())
}

#[test]
fn recovery_descriptor_rotation_needs_old_authority_new_possession_and_monotonic_history() -> TestResult {
    let f = fixture(3)?;
    let successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let new_recovery = group(2, 3, 1, None)?;
    let mut step = transition(&f, &f.chain, &successor, Kind::Recovery)?.step;
    let mut succession = Succession::decode(&step.payload)?;
    succession.recovery = RecoveryDescriptor {
        sequence: 1,
        predecessor: f.chain.recovery().digest()?,
        group: new_recovery.descriptor()?.clone(),
    };
    let possession = succession.possession_step(&step)?;
    succession.possession = sign(&successor, &possession, &[1, 2])?.signature;
    succession.recovery_possession = sign(&new_recovery, &possession, &[1, 2])?.signature;
    step.payload = succession.encode()?;
    let signed = sign(&f.recovery, &step, &[1, 2])?;
    let mut chain = f.chain.clone();
    chain.accept(signed)?;
    assert_eq!(chain.recovery().sequence, 1);
    // A stale descriptor cannot be installed even by the current recovery key.
    let mut rollback = proposal(&chain, 1)?;
    rollback.operation = Operation::Succession;
    rollback.recovery_gen += 1;
    succession.previous_key = successor.descriptor()?.public_key;
    let next_root = group(2, 3, 2, Some(chain.recovery()))?;
    succession.successor = next_root.descriptor()?.clone();
    succession.recovery = f.chain.recovery().clone();
    let possession = succession.possession_step(&rollback)?;
    succession.possession = sign(&next_root, &possession, &[1, 2])?.signature;
    succession.recovery_possession = sign(&f.recovery, &possession, &[1, 2])?.signature;
    rollback.payload = succession.encode()?;
    assert!(chain.accept(sign(&new_recovery, &rollback, &[1, 2])?).is_err());
    Ok(())
}
