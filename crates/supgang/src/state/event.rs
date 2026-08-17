//! Canonical authoritative-state events and deterministic replay.

use std::collections::BTreeMap;

use minicbor::{Decoder, Encoder};

use super::{LocalState, MAX_HIVE_MEMBERS, StateError};
use crate::{
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
const GENESIS_FIELDS: u64 = 4;
const SEQUENCE_FIELDS: u64 = 4;
const MEMBERSHIP_FIELDS: u64 = 3;
const REVOCATION_FIELDS: u64 = 3;

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
}

pub(super) fn replay(
    identity: LocalIdentity,
    journal: Journal,
    lock: StateLock,
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
    for frame in frames.iter().skip(1) {
        apply_replayed(&mut state, decode_event(frame)?)?;
    }
    Ok(state)
}

fn apply_replayed(state: &mut LocalState, event: StateEvent) -> Result<(), StateError> {
    match event {
        StateEvent::Genesis { .. } => return Err(StateError::InvalidGenesis),
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
