use super::*;
use crate::threshold::session::{Phase, SessionStore, Snapshot};

struct FailStore {
    file: FileSessionStore,
    fail: Phase,
}

impl SessionStore for FailStore {
    fn binding(&self) -> &Binding {
        self.file.binding()
    }
    fn snapshot(&self) -> &Snapshot {
        self.file.snapshot()
    }
    fn replace(&mut self, expected: u64, next: Snapshot) -> Result<(), Error> {
        if next.records.iter().any(|r| r.phase == self.fail) {
            return Err(Error::Store);
        }
        self.file.replace(expected, next)
    }
}

#[test]
fn consumption_is_durable_before_share_computation_and_crash_keeps_lock() -> TestResult {
    let f = fixture(3)?;
    let step = proposal(&f.chain, 1)?;
    let directory = tempfile::tempdir()?;
    let output = f.root.outputs.first().ok_or(Error::Invalid)?;
    let binding = Binding {
        hive: step.hive,
        group: output.descriptor.clone(),
        participant: 1,
    };
    let file = FileSessionStore::open(directory.path().join("a"), binding.clone())?;
    let mut a = Session::open(
        FailStore {
            file,
            fail: Phase::Signed,
        },
        output.key.clone(),
    )?;
    let mut others = machines(&f.root, &step, &[2], directory.path())?;
    let id = Session::<FileSessionStore>::new_id()?;
    a.propose(id, step.clone(), 100)?;
    let mut commitments = BTreeMap::from([(
        frost::Identifier::try_from(1)?,
        a.commit(id, 100, &FixturePolicy, |_| true)?,
    )]);
    for (identifier, machine) in &mut others {
        machine.propose(id, step.clone(), 100)?;
        commitments.insert(*identifier, machine.commit(id, 100, &FixturePolicy, |_| true)?);
    }
    let package = Package {
        id,
        descriptor: output.descriptor.digest()?,
        generation: 0,
        signing: frost::SigningPackage::new(commitments, &step.message()?),
    };
    assert!(matches!(a.sign(&package, 101), Err(Error::Store)));
    let record = a.snapshot().records.first().ok_or(Error::Invalid)?;
    assert_eq!(record.phase, Phase::NoncesConsumed);
    assert_eq!(record.package_digest, Some(package.digest()?));
    assert!(record.permanent);
    assert!(record.cached_share.is_none());
    assert!(a.sign(&package, 102).is_err());
    drop(a);
    let file = FileSessionStore::open(directory.path().join("a"), binding)?;
    let mut recovered = Session::open(file, output.key.clone())?;
    assert_eq!(
        recovered.snapshot().records.first().ok_or(Error::Invalid)?.phase,
        Phase::Discarded
    );
    assert!(recovered.sign(&package, 1000).is_err());
    let other = Session::<FileSessionStore>::new_id()?;
    recovered.propose(other, proposal(&f.chain, 2)?, 1000)?;
    assert!(matches!(
        recovered.commit(other, 1000, &FixturePolicy, |_| true),
        Err(Error::Locked)
    ));
    let resumed = Session::<FileSessionStore>::new_id()?;
    recovered.propose(resumed, step, 1000)?;
    recovered.commit(resumed, 1000, &FixturePolicy, |_| true)?;
    Ok(())
}

#[test]
fn failed_consumption_write_releases_no_share_and_poisons_the_session() -> TestResult {
    let f = fixture(3)?;
    let step = proposal(&f.chain, 1)?;
    let output = f.root.outputs.first().ok_or(Error::Invalid)?;
    let directory = tempfile::tempdir()?;
    let file = FileSessionStore::open(
        directory.path().join("state"),
        Binding {
            hive: step.hive,
            group: output.descriptor.clone(),
            participant: 1,
        },
    )?;
    let mut machine = Session::open(
        FailStore {
            file,
            fail: Phase::NoncesConsumed,
        },
        output.key.clone(),
    )?;
    let id = Session::<FileSessionStore>::new_id()?;
    machine.propose(id, step.clone(), 100)?;
    let own = machine.commit(id, 100, &FixturePolicy, |_| true)?;
    let second = f.root.outputs.get(1).ok_or(Error::Invalid)?;
    let (_, second_commitment) = frost::round1::commit(second.key.signing_share(), &mut crate::threshold::rng()?);
    let package = Package {
        id,
        descriptor: output.descriptor.digest()?,
        generation: 0,
        signing: frost::SigningPackage::new(
            BTreeMap::from([
                (*output.key.identifier(), own),
                (*second.key.identifier(), second_commitment),
            ]),
            &step.message()?,
        ),
    };
    assert!(machine.sign(&package, 101).is_err());
    assert_eq!(
        machine.snapshot().records.first().ok_or(Error::Invalid)?.phase,
        Phase::NoncesIssued
    );
    assert!(machine.sign(&package, 102).is_err());
    Ok(())
}

#[test]
fn restart_returns_cached_share_and_preserves_permanent_predecessor_lock() -> TestResult {
    let f = fixture(3)?;
    let step = proposal(&f.chain, 1)?;
    let directory = tempfile::tempdir()?;
    let mut original = machines(&f.root, &step, &[1, 2], directory.path())?;
    let package = prepare(&f.root, &step, &mut original, 100)?;
    let before = finish(&f.root, &step, &mut original, &package, 101)?;
    drop(original);
    let mut restored = machines(&f.root, &step, &[1, 2], directory.path())?;
    let after = finish(&f.root, &step, &mut restored, &package, 1000)?;
    assert_eq!(before.signature, after.signature);
    for machine in restored.values_mut() {
        let id = Session::<FileSessionStore>::new_id()?;
        machine.propose(id, proposal(&f.chain, 2)?, 1001)?;
        assert!(matches!(
            machine.commit(id, 1001, &FixturePolicy, |_| true),
            Err(Error::Locked)
        ));
    }
    Ok(())
}

#[test]
fn restarted_unsigned_attempt_burns_nonces_and_rejects_clock_rollback() -> TestResult {
    let f = fixture(3)?;
    let step = proposal(&f.chain, 1)?;
    let directory = tempfile::tempdir()?;
    let mut original = machines(&f.root, &step, &[1, 2], directory.path())?;
    let package = prepare(&f.root, &step, &mut original, 100)?;
    drop(original);
    let mut restored = machines(&f.root, &step, &[1, 2], directory.path())?;
    for machine in restored.values_mut() {
        assert!(machine.sign(&package, 101).is_err());
        assert_eq!(
            machine.snapshot().records.first().ok_or(Error::Invalid)?.phase,
            Phase::Discarded
        );
        assert!(machine.propose([9; 32], step.clone(), 99).is_err());
    }
    let fresh = prepare(&f.root, &step, &mut restored, 102)?;
    assert_ne!(fresh.id, package.id);
    assert_ne!(
        fresh.signing.signing_commitments(),
        package.signing.signing_commitments()
    );
    Ok(())
}

#[test]
fn store_refuses_parallel_ownership_other_scope_and_restored_old_group_share() -> TestResult {
    let f = fixture(3)?;
    let directory = tempfile::tempdir()?;
    let binding = Binding {
        hive: f.chain.hive(),
        group: f.root.descriptor()?.clone(),
        participant: 1,
    };
    let file = FileSessionStore::open(directory.path().join("state"), binding.clone())?;
    assert!(FileSessionStore::open(directory.path().join("state"), binding.clone()).is_err());
    drop(file);
    let mut changed = binding.clone();
    changed.group.generation += 1;
    assert!(FileSessionStore::open(directory.path().join("state"), changed).is_err());
    let mut changed = binding;
    changed.hive = crate::ids::HiveId::from_bytes([9; 32]);
    assert!(FileSessionStore::open(directory.path().join("state"), changed).is_err());
    let successor = group(2, 3, 1, Some(f.chain.recovery()))?;
    let file = FileSessionStore::open(
        directory.path().join("new"),
        Binding {
            hive: f.chain.hive(),
            group: successor.descriptor()?.clone(),
            participant: 1,
        },
    )?;
    assert!(Session::open(file, f.root.outputs.first().ok_or(Error::Invalid)?.key.clone()).is_err());
    Ok(())
}
