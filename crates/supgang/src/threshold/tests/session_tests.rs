use super::*;
use crate::threshold::session::{DEADLINE_SECONDS, Phase};

#[test]
fn presence_is_required_before_commitment_or_nonce_release() -> TestResult {
    let f = fixture(3)?;
    let step = proposal(&f.chain, 1)?;
    let directory = tempfile::tempdir()?;
    let mut machines = machines(&f.root, &step, &[1], directory.path())?;
    let machine = machines.values_mut().next().ok_or(Error::Invalid)?;
    let id = Session::<FileSessionStore>::new_id()?;
    machine.propose(id, step, 100)?;
    assert!(matches!(machine.commit(id, 100, |_| false), Err(Error::Presence)));
    assert_eq!(
        machine.snapshot().records.first().ok_or(Error::Invalid)?.phase,
        Phase::Proposed
    );
    machine.commit(id, 100, |_| true)?;
    assert_eq!(
        machine.snapshot().records.first().ok_or(Error::Invalid)?.phase,
        Phase::NoncesIssued
    );
    Ok(())
}

#[test]
fn another_step_is_locked_until_the_unsigned_ten_minute_deadline() -> TestResult {
    let f = fixture(3)?;
    let step = proposal(&f.chain, 1)?;
    let directory = tempfile::tempdir()?;
    let mut machines = machines(&f.root, &step, &[1], directory.path())?;
    let machine = machines.values_mut().next().ok_or(Error::Invalid)?;
    let first = Session::<FileSessionStore>::new_id()?;
    let second = Session::<FileSessionStore>::new_id()?;
    machine.propose(first, step, 100)?;
    machine.commit(first, 100, |_| true)?;
    machine.propose(second, proposal(&f.chain, 2)?, 101)?;
    assert!(matches!(
        machine.commit(second, 100 + DEADLINE_SECONDS - 1, |_| true),
        Err(Error::Locked)
    ));
    machine.commit(second, 100 + DEADLINE_SECONDS, |_| true)?;
    assert_eq!(
        machine.snapshot().records.first().ok_or(Error::Invalid)?.phase,
        Phase::Discarded
    );
    Ok(())
}

#[test]
fn delayed_publication_never_releases_the_shared_signers_lock() -> TestResult {
    let f = fixture(3)?;
    let step = proposal(&f.chain, 1)?;
    let directory = tempfile::tempdir()?;
    let mut machines = machines(&f.root, &step, &[1, 2], directory.path())?;
    let package = prepare(&f.root, &step, &mut machines, 100)?;
    let signed = finish(&f.root, &step, &mut machines, &package, 101)?;
    let b = machines
        .get_mut(&frost::Identifier::try_from(2)?)
        .ok_or(Error::Invalid)?;
    let other = Session::<FileSessionStore>::new_id()?;
    b.propose(other, proposal(&f.chain, 2)?, 1_000_000)?;
    assert!(matches!(b.commit(other, 1_000_000, |_| true), Err(Error::Locked)));
    b.discard(package.id, 1_000_001)?;
    assert!(matches!(b.commit(other, 1_000_002, |_| true), Err(Error::Locked)));
    let mut chain = f.chain.clone();
    assert_eq!(chain.accept(signed)?, crate::threshold::step::Outcome::Accepted);
    assert_eq!(chain.status(), crate::threshold::step::Status::Active);
    Ok(())
}

#[test]
fn identical_package_returns_cached_share_but_changed_commitments_are_refused() -> TestResult {
    let f = fixture(3)?;
    let step = proposal(&f.chain, 1)?;
    let directory = tempfile::tempdir()?;
    let mut machines = machines(&f.root, &step, &[1, 2], directory.path())?;
    let package = prepare(&f.root, &step, &mut machines, 100)?;
    let machine = machines.values_mut().next().ok_or(Error::Invalid)?;
    let first = machine.sign(&package, 101)?;
    assert_eq!(first, machine.sign(&package, 102)?);
    let mut changed = package.clone();
    let mut commitments = changed.signing.signing_commitments().clone();
    let (_, alternate) = frost::round1::commit(
        f.root.outputs.last().ok_or(Error::Invalid)?.key.signing_share(),
        &mut crate::threshold::rng()?,
    );
    commitments.insert(frost::Identifier::try_from(2)?, alternate);
    changed.signing = frost::SigningPackage::new(commitments, package.signing.message());
    assert!(matches!(machine.sign(&changed, 103), Err(Error::Proof)));
    assert_eq!(machine.sign(&package, 104)?, first);
    Ok(())
}

#[test]
fn substituted_message_and_wrong_generation_are_refused_before_consumption() -> TestResult {
    let f = fixture(3)?;
    let step = proposal(&f.chain, 1)?;
    let directory = tempfile::tempdir()?;
    let mut machines = machines(&f.root, &step, &[1, 2], directory.path())?;
    let package = prepare(&f.root, &step, &mut machines, 100)?;
    let machine = machines.values_mut().next().ok_or(Error::Invalid)?;
    let mut substituted = package.clone();
    substituted.signing = frost::SigningPackage::new(
        package.signing.signing_commitments().clone(),
        &proposal(&f.chain, 2)?.message()?,
    );
    assert!(matches!(machine.sign(&substituted, 101), Err(Error::Proof)));
    let mut retired = package.clone();
    retired.generation += 1;
    assert!(machine.sign(&retired, 101).is_err());
    let mut other_descriptor = package.clone();
    other_descriptor.descriptor = [4; 32];
    assert!(machine.sign(&other_descriptor, 101).is_err());
    assert_eq!(
        machine.snapshot().records.first().ok_or(Error::Invalid)?.phase,
        Phase::NoncesIssued
    );
    machine.sign(&package, 101)?;
    Ok(())
}

#[test]
fn resumed_session_uses_new_id_fresh_nonces_and_the_same_step_lock() -> TestResult {
    let f = fixture(3)?;
    let step = proposal(&f.chain, 1)?;
    let directory = tempfile::tempdir()?;
    let mut machines = machines(&f.root, &step, &[1, 2], directory.path())?;
    let first = prepare(&f.root, &step, &mut machines, 100)?;
    for machine in machines.values_mut() {
        machine.sign(&first, 101)?;
    }
    let resumed = prepare(&f.root, &step, &mut machines, 1000)?;
    assert_ne!(resumed.id, first.id);
    assert_ne!(
        resumed.signing.signing_commitments(),
        first.signing.signing_commitments()
    );
    let mut replay = first.clone();
    replay.id = resumed.id;
    for machine in machines.values_mut() {
        assert!(machine.propose(first.id, step.clone(), 1000).is_err());
        assert!(machine.sign(&replay, 1001).is_err());
    }
    finish(&f.root, &step, &mut machines, &resumed, 1001)?.verify(&f.root.descriptor()?.public_key)?;
    Ok(())
}

#[test]
fn expired_signing_attempt_discards_nonces_and_cannot_be_replayed() -> TestResult {
    let f = fixture(3)?;
    let step = proposal(&f.chain, 1)?;
    let directory = tempfile::tempdir()?;
    let mut machines = machines(&f.root, &step, &[1, 2], directory.path())?;
    let package = prepare(&f.root, &step, &mut machines, 100)?;
    for machine in machines.values_mut() {
        assert!(machine.sign(&package, 700).is_err());
        assert_eq!(
            machine.snapshot().records.first().ok_or(Error::Invalid)?.phase,
            Phase::Discarded
        );
        assert!(machine.sign(&package, 701).is_err());
    }
    Ok(())
}

#[test]
fn aggregate_is_an_ordinary_ed25519_signature_and_bad_shares_fail() -> TestResult {
    use ed25519_dalek::Verifier as _;
    let f = fixture(3)?;
    let step = proposal(&f.chain, 1)?;
    let directory = tempfile::tempdir()?;
    let mut machines = machines(&f.root, &step, &[1, 2], directory.path())?;
    let package = prepare(&f.root, &step, &mut machines, 100)?;
    let signed = finish(&f.root, &step, &mut machines, &package, 101)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&f.root.descriptor()?.public_key)?;
    key.verify(
        &step.message()?,
        &ed25519_dalek::Signature::from_bytes(&signed.signature),
    )?;
    key.verify_strict(
        &step.message()?,
        &ed25519_dalek::Signature::from_bytes(&signed.signature),
    )?;
    let mut shares = machines
        .iter_mut()
        .map(|(id, m)| Ok((*id, m.sign(&package, 102)?)))
        .collect::<Result<BTreeMap<_, _>, Error>>()?;
    shares.insert(
        frost::Identifier::try_from(2)?,
        frost::round2::SignatureShare::deserialize(&[0; 32])?,
    );
    assert!(frost::aggregate(&package.signing, &shares, &f.root.descriptor()?.public_package()?).is_err());
    Ok(())
}
