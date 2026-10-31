//! Canonical authoritative-state events and deterministic replay.

use std::collections::BTreeMap;

use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};

use super::{LocalState, MAX_HIVE_MEMBERS, StateError};
use crate::{
    identity::verify_domain,
    ids::{HiveId, NodeId},
    journal::Journal,
    membership::{SignedMembership, decode_signed_membership, encode_signed_membership},
    revocation::{SignedRevocationList, decode_signed_revocations, encode_signed_revocations},
    state_lock::StateLock,
    storage::LocalIdentity,
};

const STATE_EVENT_VERSION: u16 = 1;
const EVENT_GENESIS: u8 = 1;
const EVENT_SEQUENCE: u8 = 2;
const EVENT_MEMBERSHIP: u8 = 3;
const EVENT_REVOCATION: u8 = 4;
const EVENT_CHECKPOINT: u8 = 5;
const CHECKPOINT_VERSION: u16 = 1;
const CHECKPOINT_DOMAIN: &[u8] = b"supgang/state-checkpoint/v1\0";
const CHECKPOINT_SNAPSHOT_DOMAIN: &[u8] = b"supgang/state-checkpoint-snapshot/v1\0";
const CHECKPOINT_SIGNATURE_FIELDS: u64 = 7;
const GENESIS_FIELDS: u64 = 4;
const SEQUENCE_FIELDS: u64 = 4;
const MEMBERSHIP_FIELDS: u64 = 3;
const REVOCATION_FIELDS: u64 = 3;
const CHECKPOINT_FIELDS: u64 = 9;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum StateEvent {
    Genesis {
        membership: SignedMembership,
        revocations: SignedRevocationList,
    },
    Sequence {
        generation: u64,
        sequence: u64,
    },
    Membership(SignedMembership),
    Revocation(SignedRevocationList),
    Checkpoint {
        hive_id: HiveId,
        node_id: NodeId,
        generation: u64,
        sequence: u64,
        snapshot_digest: [u8; 32],
        signature: [u8; 64],
    },
}

pub(super) fn signed_checkpoint(
    identity: &LocalIdentity,
    generation: u64,
    sequence: u64,
    snapshot_frames: &[Vec<u8>],
) -> Result<StateEvent, StateError> {
    let hive_id = identity.hive_id;
    let node_id = identity.device.node_id();
    let snapshot_digest = snapshot_digest(snapshot_frames)?;
    let payload = checkpoint_signature_payload(hive_id, node_id, generation, sequence, snapshot_digest)?;
    let signature = identity.device.sign_domain(CHECKPOINT_DOMAIN, &payload);
    Ok(StateEvent::Checkpoint {
        hive_id,
        node_id,
        generation,
        sequence,
        snapshot_digest,
        signature,
    })
}

pub(super) fn replay(
    identity: LocalIdentity,
    journal: Option<Journal>,
    lock: Option<StateLock>,
    frames: &[Vec<u8>],
) -> Result<LocalState, StateError> {
    let Some(first) = frames.first() else {
        return Err(StateError::MissingGenesis);
    };
    let StateEvent::Genesis {
        membership: founder,
        revocations,
    } = decode_event(first)?
    else {
        return Err(StateError::InvalidGenesis);
    };
    founder.verify(&identity.root_verifying_key)?;
    revocations.verify(&identity.root_verifying_key)?;
    if founder.certificate.hive_id != identity.hive_id
        || founder.certificate.node_id != identity.device.node_id()
        || founder.certificate.device_verifying_key != identity.device.verifying_key().to_bytes()
    {
        return Err(StateError::IdentityMismatch);
    }
    let founder_serial = founder.certificate.serial;
    let mut state = LocalState {
        identity,
        memberships: BTreeMap::from([(founder.certificate.node_id, founder)]),
        revocations,
        generation: 0,
        sequence: 0,
        last_membership_serial: founder_serial,
        event_count: 1,
        journal,
        lock,
    };
    let mut checkpoint_seen = false;
    for (index, frame) in frames.iter().enumerate().skip(1) {
        let event = decode_event(frame)?;
        match event {
            StateEvent::Checkpoint {
                hive_id,
                node_id,
                generation,
                sequence,
                snapshot_digest: expected_digest,
                signature,
            } => {
                if checkpoint_seen || state.sequence != 0 || generation != state.generation {
                    return Err(StateError::InvalidCheckpoint);
                }
                if hive_id != state.identity.hive_id || node_id != state.identity.device.node_id() {
                    return Err(StateError::IdentityMismatch);
                }
                let snapshot_frames = frames.get(..index).ok_or(StateError::InvalidCheckpoint)?;
                let actual_digest = snapshot_digest(snapshot_frames)?;
                let payload = checkpoint_signature_payload(hive_id, node_id, generation, sequence, expected_digest)?;
                if actual_digest != expected_digest
                    || !verify_domain(
                        &state.identity.device.verifying_key(),
                        CHECKPOINT_DOMAIN,
                        &payload,
                        &signature,
                    )
                {
                    return Err(StateError::InvalidCheckpoint);
                }
                state.sequence = sequence;
                state.event_count = state.event_count.saturating_add(1);
                checkpoint_seen = true;
            }
            other => apply_replayed(&mut state, other)?,
        }
    }
    Ok(state)
}

fn apply_replayed(state: &mut LocalState, event: StateEvent) -> Result<(), StateError> {
    match event {
        StateEvent::Genesis { .. } => return Err(StateError::InvalidGenesis),
        StateEvent::Checkpoint { .. } => return Err(StateError::InvalidCheckpoint),
        StateEvent::Sequence { generation, sequence } => {
            if generation != state.generation
                || sequence != state.sequence.checked_add(1).ok_or(StateError::CounterExhausted)?
            {
                return Err(StateError::InvalidSequence);
            }
            state.sequence = sequence;
        }
        StateEvent::Membership(signed) => {
            signed.verify(&state.identity.root_verifying_key)?;
            if signed.certificate.serial
                != state
                    .last_membership_serial
                    .checked_add(1)
                    .ok_or(StateError::CounterExhausted)?
            {
                return Err(StateError::InvalidMembershipSerial);
            }
            if state.memberships.len() >= MAX_HIVE_MEMBERS {
                return Err(StateError::HiveFull);
            }
            if state
                .memberships
                .insert(signed.certificate.node_id, signed.clone())
                .is_some()
            {
                return Err(StateError::DuplicateMember);
            }
            state.last_membership_serial = signed.certificate.serial;
        }
        StateEvent::Revocation(signed) => {
            signed.verify(&state.identity.root_verifying_key)?;
            if signed.list.serial <= state.revocations.list.serial
                || signed.list.issued_at < state.revocations.list.issued_at
                || state
                    .revocations
                    .list
                    .revoked_nodes
                    .iter()
                    .any(|node_id| !signed.contains(node_id))
            {
                return Err(StateError::RevocationRollback);
            }
            state.revocations = signed;
        }
    }
    state.event_count = state.event_count.saturating_add(1);
    Ok(())
}

pub(super) fn encode_event(event: &StateEvent) -> Result<Vec<u8>, StateError> {
    let mut output = Vec::with_capacity(256);
    let mut encoder = Encoder::new(&mut output);
    match event {
        StateEvent::Genesis {
            membership,
            revocations,
        } => {
            encoder.array(GENESIS_FIELDS)?;
            encoder.u16(STATE_EVENT_VERSION)?;
            encoder.u8(EVENT_GENESIS)?;
            encoder.bytes(&encode_signed_membership(membership)?)?;
            encoder.bytes(&encode_signed_revocations(revocations)?)?;
        }
        StateEvent::Sequence { generation, sequence } => {
            encoder.array(SEQUENCE_FIELDS)?;
            encoder.u16(STATE_EVENT_VERSION)?;
            encoder.u8(EVENT_SEQUENCE)?;
            encoder.u64(*generation)?;
            encoder.u64(*sequence)?;
        }
        StateEvent::Membership(membership) => {
            encoder.array(MEMBERSHIP_FIELDS)?;
            encoder.u16(STATE_EVENT_VERSION)?;
            encoder.u8(EVENT_MEMBERSHIP)?;
            encoder.bytes(&encode_signed_membership(membership)?)?;
        }
        StateEvent::Revocation(revocations) => {
            encoder.array(REVOCATION_FIELDS)?;
            encoder.u16(STATE_EVENT_VERSION)?;
            encoder.u8(EVENT_REVOCATION)?;
            encoder.bytes(&encode_signed_revocations(revocations)?)?;
        }
        StateEvent::Checkpoint {
            hive_id,
            node_id,
            generation,
            sequence,
            snapshot_digest,
            signature,
        } => {
            encoder.array(CHECKPOINT_FIELDS)?;
            encoder.u16(STATE_EVENT_VERSION)?;
            encoder.u8(EVENT_CHECKPOINT)?;
            encoder.u16(CHECKPOINT_VERSION)?;
            encoder.bytes(hive_id.as_bytes())?;
            encoder.bytes(node_id.as_bytes())?;
            encoder.u64(*generation)?;
            encoder.u64(*sequence)?;
            encoder.bytes(snapshot_digest)?;
            encoder.bytes(signature)?;
        }
    }
    Ok(output)
}

fn decode_event(input: &[u8]) -> Result<StateEvent, StateError> {
    let mut decoder = Decoder::new(input);
    let fields = decoder.array()?.ok_or(StateError::InvalidEvent)?;
    if decoder.u16()? != STATE_EVENT_VERSION {
        return Err(StateError::InvalidEvent);
    }
    let event = match decoder.u8()? {
        EVENT_GENESIS if fields == GENESIS_FIELDS => StateEvent::Genesis {
            membership: decode_signed_membership(decoder.bytes()?)?,
            revocations: decode_signed_revocations(decoder.bytes()?)?,
        },
        EVENT_SEQUENCE if fields == SEQUENCE_FIELDS => StateEvent::Sequence {
            generation: decoder.u64()?,
            sequence: decoder.u64()?,
        },
        EVENT_MEMBERSHIP if fields == MEMBERSHIP_FIELDS => {
            StateEvent::Membership(decode_signed_membership(decoder.bytes()?)?)
        }
        EVENT_REVOCATION if fields == REVOCATION_FIELDS => {
            StateEvent::Revocation(decode_signed_revocations(decoder.bytes()?)?)
        }
        EVENT_CHECKPOINT if fields == CHECKPOINT_FIELDS => {
            if decoder.u16()? != CHECKPOINT_VERSION {
                return Err(StateError::InvalidCheckpoint);
            }
            StateEvent::Checkpoint {
                hive_id: HiveId::from_bytes(read_fixed(&mut decoder)?),
                node_id: NodeId::from_bytes(read_fixed(&mut decoder)?),
                generation: decoder.u64()?,
                sequence: decoder.u64()?,
                snapshot_digest: read_fixed(&mut decoder)?,
                signature: read_fixed(&mut decoder)?,
            }
        }
        _ => return Err(StateError::InvalidEvent),
    };
    if decoder.position() != input.len() {
        return Err(StateError::InvalidEvent);
    }
    if encode_event(&event)?.as_slice() != input {
        return Err(StateError::NonCanonical);
    }
    Ok(event)
}

fn snapshot_digest(frames: &[Vec<u8>]) -> Result<[u8; 32], StateError> {
    let mut hasher = Sha256::new();
    hasher.update(CHECKPOINT_SNAPSHOT_DOMAIN);
    hasher.update(
        u64::try_from(frames.len())
            .map_err(|_| StateError::InvalidCheckpoint)?
            .to_be_bytes(),
    );
    for frame in frames {
        hasher.update(
            u64::try_from(frame.len())
                .map_err(|_| StateError::InvalidCheckpoint)?
                .to_be_bytes(),
        );
        hasher.update(frame);
    }
    Ok(hasher.finalize().into())
}

fn checkpoint_signature_payload(
    hive_id: HiveId,
    node_id: NodeId,
    generation: u64,
    sequence: u64,
    snapshot_digest: [u8; 32],
) -> Result<Vec<u8>, StateError> {
    let mut output = Vec::with_capacity(128);
    let mut encoder = Encoder::new(&mut output);
    encoder.array(CHECKPOINT_SIGNATURE_FIELDS)?;
    encoder.u16(CHECKPOINT_VERSION)?;
    encoder.bytes(hive_id.as_bytes())?;
    encoder.bytes(node_id.as_bytes())?;
    encoder.u64(generation)?;
    encoder.u64(sequence)?;
    encoder.bytes(&snapshot_digest)?;
    encoder.str("authoritative-state")?;
    Ok(output)
}

fn read_fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], StateError> {
    decoder.bytes()?.try_into().map_err(|_| StateError::InvalidCheckpoint)
}
