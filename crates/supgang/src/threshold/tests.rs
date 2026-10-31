//! Offline disposable-key fixtures. The `sign` helper creates fresh stores for
//! cryptographic fixtures, including deliberately conflicting retired/faulty
//! quorums. Honest signer lock and restart tests retain each device's history.

use frost_ed25519 as frost;
use std::collections::BTreeMap;

use super::{
    Error,
    founding::{self, Group, Parameters, RecoveryDescriptor},
    session,
    session::{Binding, FileSessionStore, Package, Session},
    step::{Chain, Operation, RootStep, SignedStep},
};
use crate::{
    authority::device_node_id,
    device_key::{DeviceSigner as _, FileDeviceKey},
};

mod boundary_tests;
mod chain_tests;
mod control_tests;
mod founding_tests;
mod grant_tests;
mod owner_action_tests;
mod policy_tests;
mod release_role_vector_checks;
mod release_role_vector_tests;
mod release_statement_tests;
mod review_tests;
mod session_tests;
mod storage_tests;
mod vector_tests;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Machines = BTreeMap<frost::Identifier, Session<FileSessionStore>>;

// Explicitly permissive ONLY for cryptographic adversarial fixtures. Production
// callers use ChainPolicy; invalid signed steps are needed to test the verifier.
struct FixturePolicy;

impl session::Policy for FixturePolicy {
    fn review(&self, binding: &Binding, step: &RootStep) -> Result<session::Review, Error> {
        use super::{
            regroup::{Kind, Succession},
            session::Role,
        };
        let role = if step.operation == Operation::Succession {
            let transition = Succession::decode(&step.payload)?;
            if binding.group == transition.successor {
                Role::SuccessorPossession
            } else if transition.kind == Kind::Recovery {
                Role::Recovery
            } else {
                Role::Root
            }
        } else {
            Role::Root
        };
        Ok(session::Review {
            tip: step.predecessor,
            role,
        })
    }
}

struct Fixture {
    root: Group,
    recovery: Group,
    chain: Chain,
}

fn devices(n: u16) -> Result<Vec<FileDeviceKey>, Error> {
    (0..n).map(|_| Ok(FileDeviceKey::generate()?)).collect()
}

fn group(k: u16, n: u16, generation: u64, recovery: Option<&RecoveryDescriptor>) -> Result<Group, Error> {
    let keys = devices(n)?;
    founding::run(
        "test-hive",
        Parameters {
            k,
            n,
            accept_single_loss_failure: false,
        },
        generation,
        &keys.iter().map(FileDeviceKey::public_key).collect::<Vec<_>>(),
        recovery,
        |_, _| {},
    )
}

fn fixture(n: u16) -> Result<Fixture, Error> {
    let recovery = group(2, 3, 0, None)?;
    let descriptor = RecoveryDescriptor {
        sequence: 0,
        predecessor: [0; 32],
        group: recovery.descriptor()?.clone(),
    };
    let root = group(2, n, 0, Some(&descriptor))?;
    let chain = Chain::new(root.descriptor()?.clone(), descriptor)?;
    Ok(Fixture { root, recovery, chain })
}

fn proposal(chain: &Chain, payload: u8) -> Result<RootStep, Error> {
    let (recovery_gen, epoch, sequence) = chain.order();
    let device = chain.group().participants.first().ok_or(Error::Invalid)?.device;
    Ok(RootStep {
        hive: chain.hive(),
        predecessor: chain.tip(),
        sequence: sequence + 1,
        epoch,
        recovery_gen,
        operation: Operation::IssueMembership,
        payload: vec![payload],
        proposed_at: 100,
        proposer: device_node_id(device),
    })
}

fn machines(group: &Group, step: &RootStep, ids: &[u16], directory: &std::path::Path) -> Result<Machines, Error> {
    let mut result = BTreeMap::new();
    for id in ids {
        let identifier = frost::Identifier::try_from(*id)?;
        let output = group
            .outputs
            .iter()
            .find(|o| *o.key.identifier() == identifier)
            .ok_or(Error::Invalid)?;
        let binding = Binding {
            hive: step.hive,
            group: output.descriptor.clone(),
            participant: *id,
        };
        let store = FileSessionStore::open(directory.join(id.to_string()), binding)?;
        result.insert(identifier, Session::open(store, output.key.clone())?);
    }
    Ok(result)
}

fn prepare(group: &Group, step: &RootStep, machines: &mut Machines, now: u64) -> Result<Package, Error> {
    prepare_reviewed(group, step, machines, now, &FixturePolicy)
}

fn prepare_reviewed(
    group: &Group,
    step: &RootStep,
    machines: &mut Machines,
    now: u64,
    policy: &impl session::Policy,
) -> Result<Package, Error> {
    let id = Session::<FileSessionStore>::new_id()?;
    let mut commitments = BTreeMap::new();
    for (identifier, machine) in machines {
        machine.propose(id, step.clone(), now)?;
        commitments.insert(*identifier, machine.commit(id, now, policy, |_| true)?);
    }
    let descriptor = group.descriptor()?;
    Ok(Package {
        id,
        descriptor: descriptor.digest()?,
        generation: descriptor.generation,
        signing: frost::SigningPackage::new(commitments, &step.message()?),
    })
}

fn finish(
    group: &Group,
    step: &RootStep,
    machines: &mut Machines,
    package: &Package,
    now: u64,
) -> Result<SignedStep, Error> {
    let shares = machines
        .iter_mut()
        .map(|(id, machine)| Ok((*id, machine.sign(package, now)?)))
        .collect::<Result<BTreeMap<_, _>, Error>>()?;
    let signature = frost::aggregate(&package.signing, &shares, &group.descriptor()?.public_package()?)?;
    Ok(SignedStep {
        step: step.clone(),
        signature: signature
            .serialize()?
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid)?,
    })
}

fn sign(group: &Group, step: &RootStep, ids: &[u16]) -> Result<SignedStep, Error> {
    let directory = tempfile::tempdir()?;
    let mut machines = machines(group, step, ids, directory.path())?;
    let package = prepare(group, step, &mut machines, 100)?;
    finish(group, step, &mut machines, &package, 101)
}

fn transition(f: &Fixture, source: &Chain, successor: &Group, kind: super::regroup::Kind) -> Result<SignedStep, Error> {
    let mut step = proposal(source, 1)?;
    step.operation = Operation::Succession;
    if kind == super::regroup::Kind::Recovery {
        step.recovery_gen += 1;
    }
    let mut succession = super::regroup::Succession {
        kind,
        previous_key: source.group().public_key,
        successor: successor.descriptor()?.clone(),
        retained: super::regroup::empty_retained_digest(),
        recovery: source.recovery().clone(),
        possession: [0; 64],
        recovery_possession: [0; 64],
    };
    let possession = succession.possession_step(&step)?;
    succession.possession = sign(successor, &possession, &[1, 2])?.signature;
    step.payload = succession.encode()?;
    sign(
        if kind == super::regroup::Kind::Planned {
            &f.root
        } else {
            &f.recovery
        },
        &step,
        &[1, 2],
    )
}
