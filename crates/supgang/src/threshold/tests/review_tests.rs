//! Regression fixtures for the independent package 5 security review.

use super::*;
use crate::threshold::session::{ChainPolicy, Phase, Role};
use crate::threshold::{
    MAX_RECORDS,
    regroup::Kind,
    step::{Outcome, Status},
};

fn fill(chain: &mut Chain, root: &Group) -> Result<(), Error> {
    while chain.evidence().len() < MAX_RECORDS {
        chain.accept(raw_sign(root, &proposal(chain, 8)?)?)?;
    }
    Ok(())
}

#[test]
fn recovery_generation_lock_survives_restart_and_coordinator_replacement() -> TestResult {
    let f = fixture(3)?;
    let successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let x = transition(&f, &f.chain, &successor, Kind::Recovery)?.step;
    let mut other_view = f.chain.clone();
    other_view.accept(sign(&f.root, &proposal(&other_view, 7)?, &[1, 2])?)?;
    let y = transition(&f, &other_view, &successor, Kind::Recovery)?.step;
    assert_ne!(x.predecessor, y.predecessor);
    assert_eq!(x.recovery_gen, y.recovery_gen);
    let directory = tempfile::tempdir()?;
    let mut ab = machines(&f.recovery, &x, &[1, 2], directory.path())?;
    let policy = ChainPolicy {
        chain: &f.chain,
        role: Role::Recovery,
    };
    let first = prepare_reviewed(&f.recovery, &x, &mut ab, 100, &policy)?;
    finish(&f.recovery, &x, &mut ab, &first, 101)?;
    drop(ab);
    // A replacement coordinator resumes the same transition with fresh nonces.
    let mut ab = machines(&f.recovery, &x, &[1, 2], directory.path())?;
    let resumed = prepare_reviewed(&f.recovery, &x, &mut ab, 1000, &policy)?;
    assert_ne!(first.id, resumed.id);
    finish(&f.recovery, &x, &mut ab, &resumed, 1001)?;
    drop(ab);
    let mut bc = machines(&f.recovery, &y, &[2, 3], directory.path())?;
    let policy = ChainPolicy {
        chain: &other_view,
        role: Role::Recovery,
    };
    assert!(matches!(
        prepare_reviewed(&f.recovery, &y, &mut bc, 2000, &policy),
        Err(Error::Locked)
    ));
    Ok(())
}

#[test]
fn ordinary_fork_at_evidence_limit_halts() -> TestResult {
    let f = fixture(3)?;
    let conflict = sign(&f.root, &proposal(&f.chain, 9)?, &[2, 3])?;
    let mut chain = f.chain;
    fill(&mut chain, &f.root)?;
    assert_eq!(chain.evidence().len(), MAX_RECORDS);
    let conflicting_digest = conflict.step.digest()?;
    assert_eq!(chain.accept(conflict)?, Outcome::Fork);
    assert_eq!(chain.status(), Status::Halted);
    let evidence = chain.conflict().ok_or(Error::Invalid)?;
    assert!(chain.evidence().contains_key(&evidence.first));
    assert_eq!(evidence.second.step.digest()?, conflicting_digest);
    assert_eq!(chain.evidence().len(), MAX_RECORDS);
    Ok(())
}

#[test]
fn recovery_fork_at_evidence_limit_halts() -> TestResult {
    let f = fixture(3)?;
    let successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let rescue = transition(&f, &f.chain, &successor, Kind::Recovery)?;
    let mut conflict = rescue.step.clone();
    conflict.proposed_at += 1;
    let mut payload = crate::threshold::regroup::Succession::decode(&conflict.payload)?;
    payload.possession = sign(&successor, &payload.possession_step(&conflict)?, &[1, 2])?.signature;
    conflict.payload = payload.encode()?;
    let conflict = sign(&f.recovery, &conflict, &[2, 3])?;
    let mut chain = f.chain;
    chain.accept(rescue)?;
    fill(&mut chain, &successor)?;
    assert_eq!(chain.evidence().len(), MAX_RECORDS);
    let conflicting_digest = conflict.step.digest()?;
    assert_eq!(chain.accept(conflict)?, Outcome::Fork);
    assert_eq!(chain.status(), Status::Halted);
    let evidence = chain.conflict().ok_or(Error::Invalid)?;
    assert!(chain.evidence().contains_key(&evidence.first));
    assert_eq!(evidence.second.step.digest()?, conflicting_digest);
    assert_eq!(chain.evidence().len(), MAX_RECORDS);
    Ok(())
}

#[test]
fn pending_capacity_failure_is_reported() -> TestResult {
    let f = fixture(3)?;
    let mut chain = f.chain;
    while chain.evidence().len() < MAX_RECORDS - 1 {
        chain.accept(raw_sign(&f.root, &proposal(&chain, 1)?)?)?;
    }
    let parent = sign(&f.root, &proposal(&chain, 2)?, &[1, 2])?;
    let mut ahead = chain.clone();
    ahead.accept(parent.clone())?;
    let child = sign(&f.root, &proposal(&ahead, 3)?, &[1, 2])?;
    assert_eq!(chain.accept(child)?, Outcome::Held);
    assert!(matches!(chain.accept(parent), Err(Error::Bound)));
    assert_eq!(chain.status(), Status::Exhausted);
    Ok(())
}

#[test]
fn pending_fork_at_evidence_limit_halts() -> TestResult {
    let f = fixture(3)?;
    let mut chain = f.chain;
    while chain.evidence().len() < MAX_RECORDS - 2 {
        chain.accept(raw_sign(&f.root, &proposal(&chain, 1)?)?)?;
    }
    let parent = raw_sign(&f.root, &proposal(&chain, 2)?)?;
    let mut ahead = chain.clone();
    ahead.accept(parent.clone())?;
    for payload in [3, 4] {
        assert_eq!(
            chain.accept(raw_sign(&f.root, &proposal(&ahead, payload)?)?)?,
            Outcome::Held
        );
    }
    assert_eq!(chain.accept(parent)?, Outcome::Fork);
    assert_eq!(chain.status(), Status::Halted);
    assert_eq!(chain.evidence().len(), MAX_RECORDS);
    assert!(chain.conflict().is_some());
    Ok(())
}

// Build authenticated capacity fixtures without hundreds of irrelevant file-store
// lifecycles. This is deliberately unchecked FROST, never an honest signer model.
fn raw_sign(group: &Group, step: &RootStep) -> Result<SignedStep, Error> {
    let mut commitments = BTreeMap::new();
    let mut nonces = BTreeMap::new();
    for output in group.outputs.iter().take(2) {
        let (nonce, commitment) = frost::round1::commit(output.key.signing_share(), &mut super::super::rng()?);
        commitments.insert(*output.key.identifier(), commitment);
        nonces.insert(*output.key.identifier(), nonce);
    }
    let package = frost::SigningPackage::new(commitments, &step.message()?);
    let mut shares = BTreeMap::new();
    for output in group.outputs.iter().take(2) {
        shares.insert(
            *output.key.identifier(),
            frost::round2::sign(
                &package,
                nonces.get(output.key.identifier()).ok_or(Error::Invalid)?,
                &output.key,
            )?,
        );
    }
    let signature = frost::aggregate(&package, &shares, &group.descriptor()?.public_package()?)?;
    Ok(SignedStep {
        step: step.clone(),
        signature: signature
            .serialize()?
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid)?,
    })
}

#[test]
fn policy_refuses_stale_tip_before_presence_commitment_or_nonces() -> TestResult {
    let f = fixture(3)?;
    let stale = proposal(&f.chain, 1)?;
    let mut current = f.chain.clone();
    current.accept(sign(&f.root, &stale, &[1, 2])?)?;
    let directory = tempfile::tempdir()?;
    let mut signers = machines(&f.root, &stale, &[1], directory.path())?;
    let signer = signers.values_mut().next().ok_or(Error::Invalid)?;
    let id = Session::<FileSessionStore>::new_id()?;
    signer.propose(id, stale, 100)?;
    let mut presence_called = false;
    assert!(matches!(
        signer.commit(
            id,
            100,
            &ChainPolicy {
                chain: &current,
                role: Role::Root
            },
            |_| {
                presence_called = true;
                true
            }
        ),
        Err(Error::Authority)
    ));
    assert!(!presence_called);
    let record = signer.snapshot().records.first().ok_or(Error::Invalid)?;
    assert_eq!(record.phase, Phase::Proposed);
    assert!(record.review.is_none());
    assert!(record.commitment.is_none());
    let step = proposal(&current, 2)?;
    let id = Session::<FileSessionStore>::new_id()?;
    signer.propose(id, step, 101)?;
    signer.commit(
        id,
        101,
        &ChainPolicy {
            chain: &current,
            role: Role::Root,
        },
        |_| true,
    )?;
    assert_eq!(
        signer.snapshot().records.last().ok_or(Error::Invalid)?.review,
        Some(session::Review {
            tip: current.tip(),
            role: Role::Root
        })
    );
    drop(signers);
    let reopened = machines(&f.root, &proposal(&current, 2)?, &[1], directory.path())?;
    assert_eq!(
        reopened
            .values()
            .next()
            .ok_or(Error::Invalid)?
            .snapshot()
            .records
            .last()
            .ok_or(Error::Invalid)?
            .review,
        Some(session::Review {
            tip: current.tip(),
            role: Role::Root
        })
    );
    Ok(())
}

#[test]
fn succession_cannot_merge_root_and_recovery_keys() -> TestResult {
    let f = fixture(3)?;
    let successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let mut current = f.chain.clone();
    current.accept(transition(&f, &f.chain, &successor, Kind::Planned)?)?;
    let mut step = proposal(&current, 1)?;
    step.operation = Operation::Succession;
    step.recovery_gen += 1;
    let shared = group(2, 3, 2, None)?;
    let mut transition = crate::threshold::regroup::Succession {
        kind: Kind::Recovery,
        previous_key: current.group().public_key,
        successor: shared.descriptor()?.clone(),
        retained: crate::threshold::regroup::empty_retained_digest(),
        recovery: RecoveryDescriptor {
            sequence: 1,
            predecessor: current.recovery().digest()?,
            group: shared.descriptor()?.clone(),
        },
        possession: [0; 64],
        recovery_possession: [0; 64],
    };
    // Keep the replacement descriptor's generation valid for recovery, while
    // retaining the exact same key as the successor root.
    transition.recovery.group.generation = 1;
    let proof = raw_sign(&shared, &transition.possession_step(&step)?)?.signature;
    transition.possession = proof;
    transition.recovery_possession = proof;
    step.payload = transition.encode()?;
    let directory = tempfile::tempdir()?;
    let mut signers = machines(&f.recovery, &step, &[1], directory.path())?;
    assert!(matches!(
        prepare_reviewed(
            &f.recovery,
            &step,
            &mut signers,
            100,
            &ChainPolicy {
                chain: &current,
                role: Role::Recovery
            }
        ),
        Err(Error::Authority)
    ));
    assert!(
        signers
            .values()
            .next()
            .ok_or(Error::Invalid)?
            .snapshot()
            .records
            .iter()
            .all(|r| r.phase == Phase::Proposed && r.commitment.is_none())
    );
    assert!(matches!(
        current.accept(raw_sign(&f.recovery, &step)?),
        Err(Error::Authority)
    ));
    assert_eq!(current.status(), Status::Active);
    Ok(())
}

#[test]
fn retired_root_competing_branch_halts_an_already_succeeded_receiver() -> TestResult {
    let f = fixture(3)?;
    let successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let succession = transition(&f, &f.chain, &successor, Kind::Planned)?;
    let old_branch = sign(&f.root, &proposal(&f.chain, 9)?, &[1, 2])?;
    let mut receiver = f.chain;
    receiver.accept(succession)?;
    receiver.accept(sign(&successor, &proposal(&receiver, 3)?, &[1, 2])?)?;
    assert_eq!(receiver.group().public_key, successor.descriptor()?.public_key);
    assert_eq!(receiver.accept(old_branch)?, Outcome::Fork);
    assert_eq!(receiver.status(), Status::Halted);
    assert_eq!(receiver.group().public_key, successor.descriptor()?.public_key);
    Ok(())
}
