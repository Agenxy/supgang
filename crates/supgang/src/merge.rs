//! Deterministic merge rules for a node's single-writer endpoint register.

use crate::record::SignedEndpointRecord;

/// The result of comparing an incoming record with locally retained state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeDecision {
    /// No record existed, so the incoming record becomes current.
    AcceptFirst,
    /// The incoming record has a greater sequence in the current generation.
    AcceptNewer,
    /// The incoming record is byte-for-byte equivalent to the current record.
    Duplicate,
    /// The incoming sequence is older than the current record.
    RejectStale,
    /// The node produced different signed content at the same generation and sequence.
    Equivocation,
    /// A generation change requires a separately authorized recovery transition.
    GenerationTransitionRequired,
}

/// Chooses a deterministic action for an incoming signed endpoint record.
#[must_use]
pub fn decide(current: Option<&SignedEndpointRecord>, incoming: &SignedEndpointRecord) -> MergeDecision {
    let Some(current) = current else {
        return MergeDecision::AcceptFirst;
    };
    if current.record.generation != incoming.record.generation {
        return MergeDecision::GenerationTransitionRequired;
    }
    match incoming.record.sequence.cmp(&current.record.sequence) {
        core::cmp::Ordering::Greater => MergeDecision::AcceptNewer,
        core::cmp::Ordering::Less => MergeDecision::RejectStale,
        core::cmp::Ordering::Equal if current == incoming => MergeDecision::Duplicate,
        core::cmp::Ordering::Equal => MergeDecision::Equivocation,
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{MergeDecision, decide};
    use crate::{
        candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
        identity::DeviceIdentity,
        ids::{HiveId, TransportKeyId},
        record::{Capabilities, ENDPOINT_RECORD_VERSION, EndpointRecord, SignedEndpointRecord},
    };

    fn signed(sequence: u64, generation: u64) -> Result<SignedEndpointRecord, Box<dyn std::error::Error>> {
        let identity = DeviceIdentity::from_secret_bytes(&[9; 32])?;
        SignedEndpointRecord::sign(
            EndpointRecord {
                protocol_version: ENDPOINT_RECORD_VERSION,
                hive_id: HiveId::from_bytes([1; 32]),
                node_id: identity.node_id(),
                transport_key_id: TransportKeyId::from_public_material(b"transport"),
                generation,
                sequence,
                issued_at: sequence,
                expires_at: sequence.saturating_add(100),
                candidates: vec![EndpointCandidate::new(
                    CandidateKind::Direct,
                    CandidateTransport::QuicV1,
                    SocketAddr::from(([1, 1, 1, 1], 4_433)),
                )?],
                capabilities: Capabilities::NONE,
            },
            &identity,
        )
        .map_err(Into::into)
    }

    #[test]
    fn decisions_do_not_depend_on_arrival_order() -> Result<(), Box<dyn std::error::Error>> {
        let first = signed(1, 0)?;
        let newer = signed(2, 0)?;
        assert_eq!(decide(None, &first), MergeDecision::AcceptFirst);
        assert_eq!(decide(Some(&first), &newer), MergeDecision::AcceptNewer);
        assert_eq!(decide(Some(&newer), &first), MergeDecision::RejectStale);
        assert_eq!(decide(Some(&newer), &newer), MergeDecision::Duplicate);
        assert_eq!(
            decide(Some(&newer), &signed(2, 1)?),
            MergeDecision::GenerationTransitionRequired
        );
        Ok(())
    }
}
