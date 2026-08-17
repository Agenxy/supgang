//! Canonical, bounded CBOR encoding for signed endpoint records.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use minicbor::{Decoder, Encoder, decode, encode};
use thiserror::Error;

use crate::{
    candidate::{CandidateError, CandidateKind, CandidateTransport, EndpointCandidate, MAX_CANDIDATES},
    ids::{HiveId, NodeId, TransportKeyId},
    record::{Capabilities, EndpointRecord, SignedEndpointRecord},
};

/// Maximum accepted size of a canonical unsigned endpoint record.
pub const MAX_ENDPOINT_RECORD_BYTES: usize = 3_584;
/// Maximum accepted size of a signed endpoint-record envelope.
pub const MAX_SIGNED_ENDPOINT_RECORD_BYTES: usize = 4_096;

const SIGNED_ENVELOPE_VERSION: u16 = 1;
const RECORD_FIELDS: u64 = 10;
const CANDIDATE_FIELDS: u64 = 4;

/// An encoding or decoding failure at the network boundary.
#[derive(Debug, Error)]
pub enum WireError {
    /// The input exceeded the fixed protocol budget.
    #[error("wire message exceeds the protocol size limit")]
    Oversized,
    /// A CBOR encoder failed.
    #[error("wire message could not be encoded")]
    Encode(#[from] encode::Error<std::convert::Infallible>),
    /// A CBOR decoder rejected malformed input.
    #[error("wire message is malformed")]
    Decode(#[from] decode::Error),
    /// A fixed array had the wrong number of fields.
    #[error("wire message has the wrong number of fields")]
    WrongFieldCount,
    /// An integer did not fit its protocol field.
    #[error("wire integer is outside the supported range")]
    IntegerRange,
    /// An address byte string was neither IPv4 nor IPv6.
    #[error("wire address must contain exactly 4 or 16 bytes")]
    AddressLength,
    /// An endpoint candidate violated protocol invariants.
    #[error("wire candidate is invalid")]
    Candidate(#[from] CandidateError),
    /// A capability bit is not defined by this protocol version.
    #[error("wire record contains an unknown capability")]
    Capability,
    /// The signed envelope has an unsupported version.
    #[error("signed envelope version is not supported")]
    EnvelopeVersion,
    /// Signature bytes did not have the required size.
    #[error("wire signature must contain exactly 64 bytes")]
    SignatureLength,
    /// The message used a valid but non-canonical representation.
    #[error("wire message is not canonically encoded")]
    NonCanonical,
    /// Bytes remained after the complete top-level item.
    #[error("wire message contains trailing data")]
    TrailingData,
}

/// Encodes an unsigned endpoint record in Supgang's deterministic CBOR profile.
///
/// # Errors
///
/// Returns an error if encoding fails or exceeds the protocol size budget.
pub fn encode_endpoint_record(record: &EndpointRecord) -> Result<Vec<u8>, WireError> {
    let mut output = Vec::with_capacity(256);
    let mut encoder = Encoder::new(&mut output);
    encoder.array(RECORD_FIELDS)?;
    encoder.u16(record.protocol_version)?;
    encoder.bytes(record.hive_id.as_bytes())?;
    encoder.bytes(record.node_id.as_bytes())?;
    encoder.bytes(record.transport_key_id.as_bytes())?;
    encoder.u64(record.generation)?;
    encoder.u64(record.sequence)?;
    encoder.u64(record.issued_at)?;
    encoder.u64(record.expires_at)?;
    encoder.array(u64::try_from(record.candidates.len()).map_err(|_| WireError::IntegerRange)?)?;
    for candidate in &record.candidates {
        encode_candidate(&mut encoder, candidate)?;
    }
    encoder.u64(record.capabilities.bits())?;
    if output.len() > MAX_ENDPOINT_RECORD_BYTES {
        return Err(WireError::Oversized);
    }
    Ok(output)
}

/// Decodes and re-encodes an unsigned record to enforce canonical bytes.
///
/// # Errors
///
/// Rejects malformed, oversized, trailing, and non-canonical input.
pub fn decode_endpoint_record(input: &[u8]) -> Result<EndpointRecord, WireError> {
    if input.len() > MAX_ENDPOINT_RECORD_BYTES {
        return Err(WireError::Oversized);
    }
    let mut decoder = Decoder::new(input);
    require_array(&mut decoder, RECORD_FIELDS)?;
    let protocol_version = decoder.u16()?;
    let hive_id = HiveId::from_bytes(read_fixed::<32>(&mut decoder)?);
    let node_id = NodeId::from_bytes(read_fixed::<32>(&mut decoder)?);
    let transport_key_id = TransportKeyId::from_bytes(read_fixed::<32>(&mut decoder)?);
    let generation = decoder.u64()?;
    let sequence = decoder.u64()?;
    let issued_at = decoder.u64()?;
    let expires_at = decoder.u64()?;
    let candidate_count = read_array_len(&mut decoder)?;
    if candidate_count > MAX_CANDIDATES {
        return Err(WireError::Oversized);
    }
    let mut candidates = Vec::with_capacity(candidate_count);
    for _ in 0..candidate_count {
        candidates.push(decode_candidate(&mut decoder)?);
    }
    let capabilities = Capabilities::from_bits(decoder.u64()?).map_err(|_| WireError::Capability)?;
    ensure_finished(&decoder, input)?;
    let record = EndpointRecord {
        protocol_version,
        hive_id,
        node_id,
        transport_key_id,
        generation,
        sequence,
        issued_at,
        expires_at,
        candidates,
        capabilities,
    };
    if encode_endpoint_record(&record)?.as_slice() != input {
        return Err(WireError::NonCanonical);
    }
    Ok(record)
}

/// Encodes a signed endpoint-record envelope.
///
/// # Errors
///
/// Returns an error for an invalid signature length or an oversized message.
pub fn encode_signed_endpoint_record(signed: &SignedEndpointRecord) -> Result<Vec<u8>, WireError> {
    if signed.signature.len() != 64 {
        return Err(WireError::SignatureLength);
    }
    let payload = encode_endpoint_record(&signed.record)?;
    let mut output = Vec::with_capacity(payload.len().saturating_add(80));
    let mut encoder = Encoder::new(&mut output);
    encoder.array(3)?;
    encoder.u16(SIGNED_ENVELOPE_VERSION)?;
    encoder.bytes(&payload)?;
    encoder.bytes(&signed.signature)?;
    if output.len() > MAX_SIGNED_ENDPOINT_RECORD_BYTES {
        return Err(WireError::Oversized);
    }
    Ok(output)
}

/// Decodes a canonical signed endpoint-record envelope.
///
/// # Errors
///
/// Rejects malformed, oversized, trailing, and non-canonical input.
pub fn decode_signed_endpoint_record(input: &[u8]) -> Result<SignedEndpointRecord, WireError> {
    if input.len() > MAX_SIGNED_ENDPOINT_RECORD_BYTES {
        return Err(WireError::Oversized);
    }
    let mut decoder = Decoder::new(input);
    require_array(&mut decoder, 3)?;
    if decoder.u16()? != SIGNED_ENVELOPE_VERSION {
        return Err(WireError::EnvelopeVersion);
    }
    let payload = decoder.bytes()?;
    if payload.len() > MAX_ENDPOINT_RECORD_BYTES {
        return Err(WireError::Oversized);
    }
    let signature = decoder.bytes()?;
    if signature.len() != 64 {
        return Err(WireError::SignatureLength);
    }
    ensure_finished(&decoder, input)?;
    let signed = SignedEndpointRecord {
        record: decode_endpoint_record(payload)?,
        signature: signature.to_vec(),
    };
    if encode_signed_endpoint_record(&signed)?.as_slice() != input {
        return Err(WireError::NonCanonical);
    }
    Ok(signed)
}

fn encode_candidate<W: encode::Write>(
    encoder: &mut Encoder<W>,
    candidate: &EndpointCandidate,
) -> Result<(), encode::Error<W::Error>> {
    encoder.array(CANDIDATE_FIELDS)?;
    encoder.u8(candidate.kind() as u8)?;
    encoder.u8(candidate.transport() as u8)?;
    match candidate.address().ip() {
        IpAddr::V4(ip) => encoder.bytes(&ip.octets())?,
        IpAddr::V6(ip) => encoder.bytes(&ip.octets())?,
    };
    encoder.u16(candidate.address().port())?;
    Ok(())
}

fn decode_candidate(decoder: &mut Decoder<'_>) -> Result<EndpointCandidate, WireError> {
    require_array(decoder, CANDIDATE_FIELDS)?;
    let kind = CandidateKind::try_from(decoder.u8()?)?;
    let transport = CandidateTransport::try_from(decoder.u8()?)?;
    let address_bytes = decoder.bytes()?;
    let ip = match address_bytes.len() {
        4 => {
            let octets: [u8; 4] = address_bytes.try_into().map_err(|_| WireError::AddressLength)?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        16 => {
            let octets: [u8; 16] = address_bytes.try_into().map_err(|_| WireError::AddressLength)?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return Err(WireError::AddressLength),
    };
    let port = decoder.u16()?;
    EndpointCandidate::new(kind, transport, SocketAddr::new(ip, port)).map_err(Into::into)
}

fn require_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), WireError> {
    match decoder.array()? {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(WireError::WrongFieldCount),
    }
}

fn read_array_len(decoder: &mut Decoder<'_>) -> Result<usize, WireError> {
    let length = decoder.array()?.ok_or(WireError::WrongFieldCount)?;
    usize::try_from(length).map_err(|_| WireError::IntegerRange)
}

fn read_fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], WireError> {
    decoder.bytes()?.try_into().map_err(|_| WireError::AddressLength)
}

fn ensure_finished(decoder: &Decoder<'_>, input: &[u8]) -> Result<(), WireError> {
    if decoder.position() == input.len() {
        Ok(())
    } else {
        Err(WireError::TrailingData)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use proptest::prelude::*;

    use super::{WireError, decode_signed_endpoint_record, encode_signed_endpoint_record};
    use crate::{
        candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
        identity::DeviceIdentity,
        ids::{HiveId, TransportKeyId},
        record::{Capabilities, ENDPOINT_RECORD_VERSION, EndpointRecord, SignedEndpointRecord},
    };

    fn signed_record() -> Result<(DeviceIdentity, SignedEndpointRecord), Box<dyn std::error::Error>> {
        let identity = DeviceIdentity::generate()?;
        let record = EndpointRecord {
            protocol_version: ENDPOINT_RECORD_VERSION,
            hive_id: HiveId::from_bytes([7; 32]),
            node_id: identity.node_id(),
            transport_key_id: TransportKeyId::from_public_material(b"transport"),
            generation: 0,
            sequence: 1,
            issued_at: 10,
            expires_at: 100,
            candidates: vec![EndpointCandidate::new(
                CandidateKind::Direct,
                CandidateTransport::QuicV1,
                SocketAddr::from(([8, 8, 4, 4], 7_777)),
            )?],
            capabilities: Capabilities::NONE,
        };
        let signed = SignedEndpointRecord::sign(record, &identity)?;
        Ok((identity, signed))
    }

    #[test]
    fn canonical_signed_record_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let (identity, signed) = signed_record()?;
        let bytes = encode_signed_endpoint_record(&signed)?;
        let decoded = decode_signed_endpoint_record(&bytes)?;
        assert_eq!(decoded, signed);
        decoded.verify(&identity.verifying_key())?;
        Ok(())
    }

    #[test]
    fn rejects_trailing_data() -> Result<(), Box<dyn std::error::Error>> {
        let (_, signed) = signed_record()?;
        let mut bytes = encode_signed_endpoint_record(&signed)?;
        bytes.push(0);
        assert!(matches!(
            decode_signed_endpoint_record(&bytes),
            Err(WireError::TrailingData)
        ));
        Ok(())
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..5_000)) {
            let _result = decode_signed_endpoint_record(&bytes);
        }
    }
}
