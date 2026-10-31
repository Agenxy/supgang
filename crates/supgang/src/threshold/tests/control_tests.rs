use super::*;
use crate::threshold::control_auth::{Challenge, Proof};

#[test]
fn control_proof_is_bound_to_challenge_generation_peer_hive_and_exporter() -> TestResult {
    let devices = devices(3)?;
    let group = founding::run(
        "test",
        Parameters {
            k: 2,
            n: 3,
            accept_single_loss_failure: false,
        },
        8,
        &devices.iter().map(FileDeviceKey::public_key).collect::<Vec<_>>(),
        None,
        |_, _| {},
    )?;
    let signer = devices.first().ok_or(Error::Invalid)?;
    let peer = devices.last().ok_or(Error::Invalid)?;
    let descriptor = group.descriptor()?;
    let challenge = Challenge {
        hive: crate::ids::HiveId::from_root_verifying_key(&descriptor.public_key),
        descriptor: descriptor.digest()?,
        generation: 8,
        self_node: device_node_id(signer.public_key()),
        peer_node: device_node_id(peer.public_key()),
        challenge: [1; 32],
        channel_binding: [2; 32],
    };
    let proof = Proof::sign(&challenge, signer)?;
    proof.verify(&challenge, descriptor)?;
    let mutations: [fn(&mut Challenge); 6] = [
        |c| c.challenge = [3; 32],
        |c| c.generation += 1,
        |c| c.peer_node = c.self_node,
        |c| c.channel_binding = [3; 32],
        |c| c.hive = crate::ids::HiveId::from_bytes([4; 32]),
        |c| c.descriptor = [5; 32],
    ];
    for mutation in mutations {
        let mut replay = challenge.clone();
        mutation(&mut replay);
        assert!(proof.verify(&replay, descriptor).is_err());
    }
    Ok(())
}

#[test]
fn a_valid_device_signature_outside_the_current_roster_grants_nothing() -> TestResult {
    let f = fixture(3)?;
    let outsider = FileDeviceKey::generate()?;
    let descriptor = f.root.descriptor()?;
    let challenge = Challenge {
        hive: f.chain.hive(),
        descriptor: descriptor.digest()?,
        generation: descriptor.generation,
        self_node: device_node_id(outsider.public_key()),
        peer_node: device_node_id(descriptor.participants.first().ok_or(Error::Invalid)?.device),
        challenge: [1; 32],
        channel_binding: [2; 32],
    };
    let proof = Proof::sign(&challenge, &outsider)?;
    assert!(matches!(proof.verify(&challenge, descriptor), Err(Error::Authority)));
    Ok(())
}
