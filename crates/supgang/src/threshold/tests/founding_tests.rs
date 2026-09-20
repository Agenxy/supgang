use super::*;
use crate::threshold::{
    founding::{GroupDescriptor, founding_digest},
    step::RootStep,
};

#[test]
fn participants_agree_on_dkg_outputs_and_recovery_bound_founding_digest() -> TestResult {
    let f = fixture(3)?;
    for output in &f.root.outputs {
        assert_eq!(output.founding_digest, f.chain.tip());
        assert_eq!(output.public, f.root.descriptor()?.public_package()?);
        assert_eq!(*output.key.verifying_key(), *output.public.verifying_key());
    }
    let mut changed = f.chain.recovery().clone();
    changed.sequence += 1;
    assert_ne!(founding_digest(f.root.descriptor()?, Some(&changed))?, f.chain.tip());
    let mut changed = f.root.descriptor()?.clone();
    changed.label = "other-hive".to_owned();
    assert_ne!(founding_digest(&changed, Some(f.chain.recovery()))?, f.chain.tip());
    let bytes = f.root.descriptor()?.encode()?;
    assert_eq!(GroupDescriptor::decode(&bytes)?, *f.root.descriptor()?);
    Ok(())
}

#[test]
fn a_tampered_round_two_share_is_refused_by_its_recipient() -> TestResult {
    let keys = devices(3)?;
    let result = founding::run(
        "test-hive",
        Parameters {
            k: 2,
            n: 3,
            accept_single_loss_failure: false,
        },
        0,
        &keys.iter().map(FileDeviceKey::public_key).collect::<Vec<_>>(),
        None,
        |round, channel| {
            if round == 2
                // A valid scalar encoding carrying a false polynomial evaluation.
                && let Ok(share) = frost::keys::SigningShare::deserialize(&[0; 32])
                && let Some(package) = channel.round2.values_mut().next()
            {
                *package = frost::keys::dkg::round2::Package::new(share);
            }
        },
    );
    assert!(matches!(result, Err(Error::Frost(_))));
    Ok(())
}

#[test]
fn loss_policy_bounds_and_pinned_library_threshold_one_limit_are_explicit() -> TestResult {
    assert!(matches!(
        Parameters {
            k: 2,
            n: 2,
            accept_single_loss_failure: false
        }
        .validate(),
        Err(Error::SingleLoss)
    ));
    let keys = devices(2)?;
    let group = founding::run(
        "loss-accepted",
        Parameters {
            k: 2,
            n: 2,
            accept_single_loss_failure: true,
        },
        0,
        &keys.iter().map(FileDeviceKey::public_key).collect::<Vec<_>>(),
        None,
        |_, _| {},
    )?;
    assert_eq!(group.outputs.len(), 2);
    for (k, n) in [(0, 3), (4, 3), (2, 17)] {
        assert!(matches!(
            Parameters {
                k,
                n,
                accept_single_loss_failure: true
            }
            .validate(),
            Err(Error::Invalid)
        ));
    }
    for n in [1, 2, 16] {
        assert!(matches!(
            Parameters {
                k: 1,
                n,
                accept_single_loss_failure: true
            }
            .validate(),
            Err(Error::ThresholdOne)
        ));
        assert!(matches!(
            frost_core::keys::dkg::part1::<frost::Ed25519Sha512, _>(
                frost::Identifier::try_from(1)?,
                n,
                1,
                &mut crate::threshold::rng()?
            ),
            Err(frost::Error::InvalidMinSigners)
        ));
    }
    Ok(())
}

#[test]
fn duplicate_device_identities_and_missing_packages_are_refused() -> TestResult {
    let key = FileDeviceKey::generate()?.public_key();
    let parameters = Parameters {
        k: 2,
        n: 3,
        accept_single_loss_failure: false,
    };
    assert!(founding::run("test", parameters, 0, &[key; 3], None, |_, _| {}).is_err());
    let keys = devices(3)?;
    assert!(
        founding::run(
            "test",
            parameters,
            0,
            &keys.iter().map(FileDeviceKey::public_key).collect::<Vec<_>>(),
            None,
            |round, channel| {
                if round == 1 {
                    channel.round1.pop_first();
                }
            }
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn root_step_has_one_encoding_and_binds_every_field() -> TestResult {
    let f = fixture(3)?;
    let step = proposal(&f.chain, 1)?;
    let bytes = step.encode()?;
    assert_eq!(bytes.first(), Some(&0x8a));
    assert_eq!(RootStep::decode(&bytes)?, step);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(RootStep::decode(&trailing).is_err());
    let mut nonminimal = vec![0x8a, 0x18, 0x01];
    nonminimal.extend_from_slice(bytes.get(2..).ok_or(Error::Invalid)?);
    assert!(RootStep::decode(&nonminimal).is_err());
    let signed = sign(&f.root, &step, &[1, 2])?;
    signed.verify(&f.root.descriptor()?.public_key)?;
    let mutations: [fn(&mut RootStep); 9] = [
        |s| s.hive = crate::ids::HiveId::from_bytes([8; 32]),
        |s| s.predecessor = [8; 32],
        |s| s.sequence += 1,
        |s| s.epoch += 1,
        |s| s.recovery_gen += 1,
        |s| s.operation = Operation::Revoke,
        |s| s.payload.push(2),
        |s| s.proposed_at += 1,
        |s| s.proposer = crate::ids::NodeId::from_bytes([8; 32]),
    ];
    for mutation in mutations {
        let mut changed = signed.clone();
        mutation(&mut changed.step);
        assert_ne!(changed.step.digest()?, step.digest()?);
        assert!(changed.verify(&f.root.descriptor()?.public_key).is_err());
    }
    Ok(())
}
