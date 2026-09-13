//! Short-lived, provenance-preserving reachability claims.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ed25519_dalek::VerifyingKey;
use minicbor::{Decoder, Encoder, decode};
use thiserror::Error;

use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
    identity::{DeviceIdentity, verify_domain},
    ids::{HiveId, NodeId},
    membership::{SignedMembership, decode_signed_membership, encode_signed_membership},
};

/// Maximum canonical wire size of one reachability claim.
pub const MAX_REACHABILITY_CLAIM_BYTES: usize = 2 * 1024;
/// Maximum reachability claims accepted in one bounded exchange.
pub const MAX_REACHABILITY_CLAIMS: usize = 16;
/// Maximum lifetime of an ephemeral reachability claim.
pub const MAX_CLAIM_LIFETIME_SECONDS: u64 = 10 * 60;
const MAX_FUTURE_SKEW_SECONDS: u64 = 5 * 60;
const CLAIM_VERSION: u16 = 1;
const CLAIM_FIELDS: u64 = 12;
const PAYLOAD_FIELDS: u64 = 11;
const CLAIM_DOMAIN: &[u8] = b"supgang/reachability-claim/v1\0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
/// How the reporting device learned an address.
pub enum ReachabilitySource {
    /// An address reported by the subject's local gateway.
    Gateway = 1,
    /// An address that a different authenticated peer observed for the subject.
    PeerObserved = 2,
}

impl TryFrom<u8> for ReachabilitySource {
    type Error = ReachabilityError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Gateway),
            2 => Ok(Self::PeerObserved),
            _ => Err(ReachabilityError::InvalidShape),
        }
    }
}

/// A short-lived, reporter-signed statement about a peer's reachable address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReachabilityClaim {
    /// Hive whose root authorized the reporter.
    pub hive_id: HiveId,
    /// Device whose address is described.
    pub subject: NodeId,
    /// Device that signed the observation.
    pub reporter: NodeId,
    /// Root-signed authority for the reporting device.
    pub reporter_membership: SignedMembership,
    /// Observed or gateway-reported transport address.
    pub address: SocketAddr,
    /// Provenance of the address.
    pub source: ReachabilitySource,
    /// Unix time when the report was created.
    pub issued_at: u64,
    /// Unix time after which the report must not be used.
    pub expires_at: u64,
    /// Reporter signature over the canonical claim payload.
    pub signature: Vec<u8>,
}

impl ReachabilityClaim {
    /// Creates a bounded reachability claim signed by its reporter.
    ///
    /// # Errors
    ///
    /// Rejects invalid provenance, address, membership, or canonical encoding.
    pub fn sign(
        reporter_membership: SignedMembership,
        reporter: &DeviceIdentity,
        subject: NodeId,
        address: SocketAddr,
        source: ReachabilitySource,
        issued_at: u64,
    ) -> Result<Self, ReachabilityError> {
        let mut claim = Self {
            hive_id: reporter_membership.certificate.hive_id,
            subject,
            reporter: reporter.node_id(),
            reporter_membership,
            address,
            source,
            issued_at,
            expires_at: issued_at.saturating_add(MAX_CLAIM_LIFETIME_SECONDS),
            signature: Vec::new(),
        };
        claim.validate_shape()?;
        claim.signature = reporter.sign_domain(CLAIM_DOMAIN, &encode_payload(&claim)?).to_vec();
        Ok(claim)
    }

    /// Verifies reporter authority, time bounds, provenance, and signature.
    ///
    /// # Errors
    ///
    /// Rejects invalid authority, timing, provenance, shape, or signature.
    pub fn verify(&self, root_key: &VerifyingKey, now: u64) -> Result<(), ReachabilityError> {
        self.validate_shape()?;
        self.reporter_membership
            .verify(root_key)
            .map_err(|_| ReachabilityError::Membership)?;
        self.reporter_membership
            .certificate
            .validate_time(now)
            .map_err(|_| ReachabilityError::Membership)?;
        if self.hive_id != HiveId::from_root_verifying_key(&root_key.to_bytes())
            || self.reporter_membership.certificate.hive_id != self.hive_id
            || self.reporter_membership.certificate.node_id != self.reporter
        {
            return Err(ReachabilityError::AuthorityMismatch);
        }
        if self.expires_at < now || self.issued_at > now.saturating_add(MAX_FUTURE_SKEW_SECONDS) {
            return Err(ReachabilityError::Expired);
        }
        let key = VerifyingKey::from_bytes(&self.reporter_membership.certificate.device_verifying_key)
            .map_err(|_| ReachabilityError::Membership)?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| ReachabilityError::Signature)?;
        if verify_domain(&key, CLAIM_DOMAIN, &encode_payload(self)?, &signature) {
            Ok(())
        } else {
            Err(ReachabilityError::Signature)
        }
    }

    /// Returns the corresponding ephemeral dial candidate.
    ///
    /// # Errors
    ///
    /// Rejects addresses that cannot be safely classified for dialing.
    pub fn candidate(&self) -> Result<EndpointCandidate, ReachabilityError> {
        match self.source {
            ReachabilitySource::Gateway => {
                EndpointCandidate::new(CandidateKind::Mapped, CandidateTransport::QuicV1, self.address)
            }
            ReachabilitySource::PeerObserved => {
                EndpointCandidate::new(CandidateKind::Reflexive, CandidateTransport::QuicV1, self.address)
                    .or_else(|_| EndpointCandidate::new(CandidateKind::Local, CandidateTransport::QuicV1, self.address))
            }
        }
        .map_err(|_| ReachabilityError::InvalidAddress)
    }

    fn validate_shape(&self) -> Result<(), ReachabilityError> {
        if self.expires_at <= self.issued_at
            || self.expires_at.saturating_sub(self.issued_at) > MAX_CLAIM_LIFETIME_SECONDS
            || self.reporter_membership.certificate.node_id != self.reporter
        {
            return Err(ReachabilityError::InvalidShape);
        }
        match self.source {
            ReachabilitySource::Gateway if self.reporter != self.subject => {
                return Err(ReachabilityError::AuthorityMismatch);
            }
            ReachabilitySource::PeerObserved if self.reporter == self.subject => {
                return Err(ReachabilityError::AuthorityMismatch);
            }
            ReachabilitySource::Gateway | ReachabilitySource::PeerObserved => {}
        }
        self.candidate().map(|_| ())
    }
}

/// Reachability claim validation or canonical encoding failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReachabilityError {
    /// Fields or canonical representation are malformed.
    #[error("reachability claim has an invalid shape")]
    InvalidShape,
    /// The transport address cannot be a valid candidate.
    #[error("reachability claim has an invalid address")]
    InvalidAddress,
    /// Reporter and subject do not match the declared provenance.
    #[error("reachability claim authority does not match its provenance")]
    AuthorityMismatch,
    /// The reporter's root-authorized membership is invalid.
    #[error("reachability claim reporter membership is invalid")]
    Membership,
    /// The claim is expired or issued too far in the future.
    #[error("reachability claim is expired or from the future")]
    Expired,
    /// The reporter signature is invalid.
    #[error("reachability claim signature is invalid")]
    Signature,
    /// Canonical CBOR encoding failed.
    #[error("reachability claim encoding failed")]
    Encoding,
    /// The claim exceeds its protocol size ceiling.
    #[error("reachability claim is oversized")]
    Oversized,
}

/// Canonically encodes one reachability claim.
///
/// # Errors
///
/// Rejects malformed or oversized claims and encoding failures.
pub fn encode_claim(claim: &ReachabilityClaim) -> Result<Vec<u8>, ReachabilityError> {
    let mut output = encode_payload_with_fields(claim, CLAIM_FIELDS)?;
    let signature = claim.signature.clone();
    let mut encoder = Encoder::new(&mut output);
    encoder.bytes(&signature).map_err(|_| ReachabilityError::Encoding)?;
    if output.len() > MAX_REACHABILITY_CLAIM_BYTES {
        return Err(ReachabilityError::Oversized);
    }
    Ok(output)
}

/// Decodes and canonicalizes one reachability claim without trusting it.
///
/// # Errors
///
/// Rejects malformed, non-canonical, or oversized input.
pub fn decode_claim(input: &[u8]) -> Result<ReachabilityClaim, ReachabilityError> {
    if input.is_empty() || input.len() > MAX_REACHABILITY_CLAIM_BYTES {
        return Err(ReachabilityError::Oversized);
    }
    let mut decoder = Decoder::new(input);
    if decoder.array().map_err(map_decode)? != Some(CLAIM_FIELDS) || decoder.u16().map_err(map_decode)? != CLAIM_VERSION
    {
        return Err(ReachabilityError::InvalidShape);
    }
    let source = ReachabilitySource::try_from(decoder.u8().map_err(map_decode)?)?;
    let hive_id = HiveId::from_bytes(read_fixed(&mut decoder)?);
    let subject = NodeId::from_bytes(read_fixed(&mut decoder)?);
    let reporter = NodeId::from_bytes(read_fixed(&mut decoder)?);
    let reporter_membership =
        decode_signed_membership(decoder.bytes().map_err(map_decode)?).map_err(|_| ReachabilityError::Membership)?;
    let family = decoder.u8().map_err(map_decode)?;
    let address_bytes = decoder.bytes().map_err(map_decode)?;
    let port = decoder.u16().map_err(map_decode)?;
    let address = decode_address(family, address_bytes, port)?;
    let issued_at = decoder.u64().map_err(map_decode)?;
    let expires_at = decoder.u64().map_err(map_decode)?;
    let signature = decoder.bytes().map_err(map_decode)?.to_vec();
    if decoder.position() != input.len() {
        return Err(ReachabilityError::InvalidShape);
    }
    let claim = ReachabilityClaim {
        hive_id,
        subject,
        reporter,
        reporter_membership,
        address,
        source,
        issued_at,
        expires_at,
        signature,
    };
    claim.validate_shape()?;
    if encode_claim(&claim)?.as_slice() != input {
        return Err(ReachabilityError::InvalidShape);
    }
    Ok(claim)
}

fn encode_payload(claim: &ReachabilityClaim) -> Result<Vec<u8>, ReachabilityError> {
    encode_payload_with_fields(claim, PAYLOAD_FIELDS)
}

fn encode_payload_with_fields(claim: &ReachabilityClaim, fields: u64) -> Result<Vec<u8>, ReachabilityError> {
    let membership = encode_signed_membership(&claim.reporter_membership).map_err(|_| ReachabilityError::Membership)?;
    let (family, address) = encode_address(claim.address.ip());
    let mut output = Vec::with_capacity(membership.len().saturating_add(192));
    let mut encoder = Encoder::new(&mut output);
    encoder.array(fields).map_err(|_| ReachabilityError::Encoding)?;
    encoder.u16(CLAIM_VERSION).map_err(|_| ReachabilityError::Encoding)?;
    encoder
        .u8(claim.source as u8)
        .map_err(|_| ReachabilityError::Encoding)?;
    encoder
        .bytes(claim.hive_id.as_bytes())
        .map_err(|_| ReachabilityError::Encoding)?;
    encoder
        .bytes(claim.subject.as_bytes())
        .map_err(|_| ReachabilityError::Encoding)?;
    encoder
        .bytes(claim.reporter.as_bytes())
        .map_err(|_| ReachabilityError::Encoding)?;
    encoder.bytes(&membership).map_err(|_| ReachabilityError::Encoding)?;
    encoder.u8(family).map_err(|_| ReachabilityError::Encoding)?;
    encoder.bytes(&address).map_err(|_| ReachabilityError::Encoding)?;
    encoder
        .u16(claim.address.port())
        .map_err(|_| ReachabilityError::Encoding)?;
    encoder.u64(claim.issued_at).map_err(|_| ReachabilityError::Encoding)?;
    encoder.u64(claim.expires_at).map_err(|_| ReachabilityError::Encoding)?;
    Ok(output)
}

fn encode_address(address: IpAddr) -> (u8, Vec<u8>) {
    match address {
        IpAddr::V4(address) => (4, address.octets().to_vec()),
        IpAddr::V6(address) => (6, address.octets().to_vec()),
    }
}

fn decode_address(family: u8, bytes: &[u8], port: u16) -> Result<SocketAddr, ReachabilityError> {
    match family {
        4 => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(read_array(bytes)?)), port)),
        6 => Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(read_array(bytes)?)), port)),
        _ => Err(ReachabilityError::InvalidShape),
    }
}

fn read_fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], ReachabilityError> {
    read_array(decoder.bytes().map_err(map_decode)?)
}

fn read_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ReachabilityError> {
    bytes.try_into().map_err(|_| ReachabilityError::InvalidShape)
}

fn map_decode(_: decode::Error) -> ReachabilityError {
    ReachabilityError::InvalidShape
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{ReachabilityClaim, ReachabilityError, ReachabilitySource, decode_claim, encode_claim};
    use crate::{identity::DeviceIdentity, membership::MembershipRoles, state};

    #[test]
    fn peer_observation_round_trips_with_exact_provenance() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let mut founder = state::initialize(temporary.path().join("state"))?;
        let reporter = DeviceIdentity::generate()?;
        let membership =
            founder.issue_membership(&reporter.verifying_key(), MembershipRoles::DEVICE, [41; 32], 10, 1_000)?;
        let claim = ReachabilityClaim::sign(
            membership,
            &reporter,
            founder.identity().device.node_id(),
            SocketAddr::from(([8, 8, 8, 8], 44_330)),
            ReachabilitySource::PeerObserved,
            50,
        )?;
        let encoded = encode_claim(&claim)?;
        let decoded = decode_claim(&encoded)?;
        decoded.verify(&founder.identity().root_verifying_key, 50)?;
        assert_eq!(decoded, claim);
        Ok(())
    }

    #[test]
    fn changing_the_reported_socket_breaks_the_signature() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let mut founder = state::initialize(temporary.path().join("state"))?;
        let reporter = DeviceIdentity::generate()?;
        let membership =
            founder.issue_membership(&reporter.verifying_key(), MembershipRoles::DEVICE, [42; 32], 10, 1_000)?;
        let mut claim = ReachabilityClaim::sign(
            membership,
            &reporter,
            founder.identity().device.node_id(),
            SocketAddr::from(([8, 8, 8, 8], 44_330)),
            ReachabilitySource::PeerObserved,
            50,
        )?;
        claim.address = SocketAddr::from(([9, 9, 9, 9], 44_330));
        assert_eq!(
            claim.verify(&founder.identity().root_verifying_key, 50),
            Err(ReachabilityError::Signature)
        );
        Ok(())
    }

    #[test]
    fn expired_and_self_reported_peer_observations_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let founder = state::initialize(temporary.path().join("state"))?;
        let membership = founder.local_membership().ok_or("local membership missing")?.clone();
        assert_eq!(
            ReachabilityClaim::sign(
                membership.clone(),
                &founder.identity().device,
                founder.identity().device.node_id(),
                SocketAddr::from(([8, 8, 8, 8], 44_330)),
                ReachabilitySource::PeerObserved,
                50,
            ),
            Err(ReachabilityError::AuthorityMismatch)
        );
        let gateway = ReachabilityClaim::sign(
            membership,
            &founder.identity().device,
            founder.identity().device.node_id(),
            SocketAddr::from(([8, 8, 8, 8], 44_330)),
            ReachabilitySource::Gateway,
            50,
        )?;
        assert_eq!(
            gateway.verify(
                &founder.identity().root_verifying_key,
                gateway.expires_at.saturating_add(1)
            ),
            Err(ReachabilityError::Expired)
        );
        Ok(())
    }
}
