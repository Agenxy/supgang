//! Offline owner-action assertion verifier for exact Remap DNS operations.
//!
//! This prototype is not connected to the live service or a privileged helper.
//! It cannot replace target-local enrollment, hardware custody, a status issuer,
//! or the target's durable challenge/nonce ledger.

use minicbor::{Decoder, Encoder};
use sha2::{Digest as _, Sha256};

use crate::{
    device_key::{DevicePublicKey, DeviceSignature},
    ids::{HiveId, NodeId},
    membership::SignedMembership,
    revocation::SignedRevocationList,
    threshold::{
        Digest, Error, array, canonical, fixed,
        status::{Scope as StatusScope, SignedStatus},
        step::{
            Chain, Status as ChainStatus,
            grant::{Grant, Presence, SignerRole, TargetScope},
        },
    },
};

const ACTION_DOMAIN: &[u8] = b"supgang/owner-action/v1\0";
const REQUEST_DOMAIN: &[u8] = b"supgang/action-request/v1\0";
const CHALLENGE_DOMAIN: &[u8] = b"supgang/owner-action-challenge/v1\0";
const REMAP_CONSUMER: &str = "org.agenxy.remap";
const MAX_REMAP_ASSERTION_AGE: u64 = 5 * 60;
const MAX_REQUEST_BYTES: usize = 4 * 1024;

/// Exact challenge produced and retained by the target's consumer helper.
#[derive(Clone, Eq, PartialEq)]
pub struct Challenge {
    /// Target identity, established locally.
    pub target: NodeId,
    /// Exact consumer identity.
    pub consumer: String,
    /// Exact operation identifier.
    pub operation: String,
    /// Grant selected by the target.
    pub grant_id: [u8; 16],
    /// Consumer-defined canonical arguments and target-observed preconditions.
    pub request: Vec<u8>,
    /// Random, one-use target nonce.
    pub nonce: [u8; 16],
    /// Last UNIX second for redemption.
    pub expires_at: u64,
}

impl Challenge {
    /// Encode the exact target-issued challenge.
    ///
    /// # Errors
    /// Refuses empty/oversized requests or malformed operation identifiers.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.request.is_empty()
            || self.request.len() > MAX_REQUEST_BYTES
            || self.consumer.len() > 96
            || self.operation.len() > 64
            || self.consumer.is_empty()
            || self.operation.is_empty()
            || self.nonce == [0; 16]
        {
            return Err(Error::Bound);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(8)?
            .u8(1)?
            .bytes(self.target.as_bytes())?
            .str(&self.consumer)?
            .str(&self.operation)?
            .bytes(&self.grant_id)?
            .bytes(&self.request)?
            .bytes(&self.nonce)?
            .u64(self.expires_at)?;
        Ok(e.into_writer())
    }

    /// Decode a bounded canonical challenge; target issuance still needs checking.
    ///
    /// # Errors
    /// Refuses malformed, trailing or noncanonical data.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_REQUEST_BYTES + 256 {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 8)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let value = Self {
            target: NodeId::from_bytes(fixed(&mut d)?),
            consumer: d.str()?.to_owned(),
            operation: d.str()?.to_owned(),
            grant_id: fixed(&mut d)?,
            request: d.bytes()?.to_vec(),
            nonce: fixed(&mut d)?,
            expires_at: d.u64()?,
        };
        canonical(bytes, &value.encode()?)?;
        Ok(value)
    }

    /// Domain-separated digest carried in an owner assertion.
    ///
    /// # Errors
    /// Refuses malformed challenge fields.
    pub fn digest(&self) -> Result<Digest, Error> {
        Ok(hash(CHALLENGE_DOMAIN, &self.encode()?))
    }
}

/// One P-256 owner assertion over an arbitrary canonical consumer request.
#[derive(Clone, Eq, PartialEq)]
pub struct Assertion {
    /// Founding hive identity.
    pub hive: HiveId,
    /// Grant-named signer device.
    pub signer_node: NodeId,
    /// Grant-named P-256 public key.
    pub signer_key: DevicePublicKey,
    /// Grant identity.
    pub grant_id: [u8; 16],
    /// Target identity.
    pub target: NodeId,
    /// Exact consumer identity.
    pub consumer: String,
    /// Exact action identifier.
    pub operation: String,
    /// Digest of canonical consumer request bytes.
    pub request_digest: Digest,
    /// Digest of the target-issued challenge.
    pub challenge_digest: Digest,
    /// Target-issued one-use nonce.
    pub nonce: [u8; 16],
    /// UNIX signing second.
    pub issued_at: u64,
    /// Last UNIX second for execution.
    pub expires_at: u64,
    /// Strict low-S P-256 signature over the payload.
    pub signature: [u8; 64],
}

impl Assertion {
    /// Canonical signed payload, independent of the signature envelope.
    ///
    /// # Errors
    /// Refuses oversized or empty identity fields.
    pub fn payload(&self) -> Result<Vec<u8>, Error> {
        if self.consumer.is_empty()
            || self.consumer.len() > 96
            || self.operation.is_empty()
            || self.operation.len() > 64
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > MAX_REMAP_ASSERTION_AGE
            || self.nonce == [0; 16]
        {
            return Err(Error::Bound);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(13)?.u8(1)?.str("p256")?.bytes(self.hive.as_bytes())?;
        e.array(3)?
            .str("owner-presence")?
            .bytes(self.signer_node.as_bytes())?
            .bytes(&self.signer_key.to_bytes())?;
        e.bytes(&self.grant_id)?
            .bytes(self.target.as_bytes())?
            .str(&self.consumer)?
            .str(&self.operation)?
            .bytes(&self.request_digest)?
            .bytes(&self.challenge_digest)?
            .bytes(&self.nonce)?
            .u64(self.issued_at)?
            .u64(self.expires_at)?;
        Ok(e.into_writer())
    }

    /// Encode canonical `[version, payload, signature]` bytes.
    ///
    /// # Errors
    /// Refuses malformed fields or a high-S signature.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        DeviceSignature::from_bytes(&self.signature).map_err(|_| Error::Proof)?;
        let mut e = Encoder::new(Vec::new());
        e.array(3)?.u8(1)?.bytes(&self.payload()?)?.bytes(&self.signature)?;
        Ok(e.into_writer())
    }

    /// Decode canonical, bounded signed assertion bytes.
    ///
    /// # Errors
    /// Refuses unsupported algorithms, fields, signatures and trailing data.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 1024 {
            return Err(Error::Bound);
        }
        let mut outer = Decoder::new(bytes);
        array(&mut outer, 3)?;
        if outer.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let payload = outer.bytes()?;
        let signature = fixed(&mut outer)?;
        let mut d = Decoder::new(payload);
        array(&mut d, 13)?;
        if d.u8()? != 1 || d.str()? != "p256" {
            return Err(Error::Invalid);
        }
        let hive = HiveId::from_bytes(fixed(&mut d)?);
        array(&mut d, 3)?;
        if d.str()? != "owner-presence" {
            return Err(Error::Invalid);
        }
        let signer_node = NodeId::from_bytes(fixed(&mut d)?);
        let signer_key = DevicePublicKey::from_bytes(d.bytes()?).map_err(|_| Error::Invalid)?;
        let assertion = Self {
            hive,
            signer_node,
            signer_key,
            grant_id: fixed(&mut d)?,
            target: NodeId::from_bytes(fixed(&mut d)?),
            consumer: d.str()?.to_owned(),
            operation: d.str()?.to_owned(),
            request_digest: fixed(&mut d)?,
            challenge_digest: fixed(&mut d)?,
            nonce: fixed(&mut d)?,
            issued_at: d.u64()?,
            expires_at: d.u64()?,
            signature,
        };
        canonical(payload, &assertion.payload()?)?;
        canonical(bytes, &assertion.encode()?)?;
        Ok(assertion)
    }

    /// Verify signer proof and exact grant, challenge and target bindings.
    ///
    /// # Errors
    /// Refuses a wrong signer, target, consumer, operation, request, time or signature.
    pub fn verify_binding(
        &self,
        grant: &Grant,
        challenge: &Challenge,
        current_request: &[u8],
        target: NodeId,
        now: u64,
    ) -> Result<(), Error> {
        if current_request.is_empty() || current_request.len() > MAX_REQUEST_BYTES {
            return Err(Error::Bound);
        }
        let grant_matches = (
            self.hive,
            self.grant_id,
            self.signer_node,
            self.signer_key,
            &self.consumer,
        ) == (grant.hive, grant.id, grant.signer_node, grant.signer, &grant.consumer);
        let challenge_matches = (self.target, &self.consumer, &self.operation, self.nonce)
            == (
                challenge.target,
                &challenge.consumer,
                &challenge.operation,
                challenge.nonce,
            );
        let scope_matches = matches!(grant.target, TargetScope::Node(node) if node == target)
            || matches!(grant.target, TargetScope::HiveNodes(hive) if hive == grant.hive);
        if !grant_matches || !challenge_matches || !scope_matches {
            return Err(Error::Authority);
        }
        if grant.signer_role != SignerRole::OwnerPresence
            || self.target != target
            || challenge.grant_id != grant.id
            || self.challenge_digest != challenge.digest()?
            || self.request_digest != hash(REQUEST_DOMAIN, current_request)
            || challenge.request != current_request
        {
            return Err(Error::Authority);
        }
        if now < self.issued_at
            || now > self.expires_at
            || now > challenge.expires_at
            || self.expires_at > challenge.expires_at
            || now < grant.not_before
            || now > grant.not_after
        {
            return Err(Error::Authority);
        }
        let allowed = grant
            .operations
            .iter()
            .find(|entry| entry.name == self.operation)
            .ok_or(Error::Authority)?;
        if allowed.presence != Presence::Required {
            return Err(Error::Authority);
        }
        let signature = DeviceSignature::from_bytes(&self.signature).map_err(|_| Error::Proof)?;
        self.signer_key
            .verify_domain(ACTION_DOMAIN, &self.payload()?, &signature)
            .map_err(|_| Error::Proof)
    }
}

/// Target-owned storage must atomically confirm issue, mark challenge used and
/// durably spend the assertion nonce before the consumer operation executes.
pub trait SpendLedger {
    /// Redeem once, with a retained spent record through expiry plus clock skew.
    ///
    /// # Errors
    /// Refuses unknown/used challenges, duplicate nonces or an unsafe write.
    fn redeem(&mut self, challenge: &Challenge, signer_node: NodeId, retain_until: u64) -> Result<(), Error>;
}

/// An uninhabited runtime gate. Package 8 custody, a current-head status
/// issuer, target-local enrollment and physical cross-host proof must exist
/// before this type can gain a constructor or variant.
pub enum AvailabilityPermit {}

/// Inputs that the target helper obtains from protected local policy and root proofs.
pub struct RemapVerification<'a> {
    /// Authenticated root chain, pinned locally by Remap.
    pub chain: &'a Chain,
    /// Root-signed shared status at the current head.
    pub status: &'a SignedStatus,
    /// Root-signed signer-device membership.
    pub membership: &'a SignedMembership,
    /// Root-signed member revocation snapshot.
    pub revocations: &'a SignedRevocationList,
    /// Signed owner assertion.
    pub assertion: &'a Assertion,
    /// Challenge issued and retained by this target.
    pub challenge: &'a Challenge,
    /// Recomputed canonical request including current resolver-plan preconditions.
    pub current_request: &'a [u8],
    /// Local target identity, never taken from the network request.
    pub target: NodeId,
    /// Trusted local UNIX time.
    pub now: u64,
    /// Root-authorized maximum age, further narrowed by local Remap policy.
    pub maximum_status_age: u64,
    /// Durable high-water mark of member revocation serial.
    pub member_serial_floor: u64,
}

/// Verify the two closed Remap DNS operations and durably spend a one-use nonce.
///
/// This offline prototype fails closed after root rotation until membership and
/// revocation credentials are issued under the new authority. It is not a live
/// privileged helper and does not establish owner hardware custody.
///
/// # Errors
/// Refuses any missing, mismatched, expired, revoked, replayed or stale proof.
pub fn verify_remap_dns(
    input: &RemapVerification<'_>,
    ledger: &mut impl SpendLedger,
    _permit: &AvailabilityPermit,
) -> Result<(), Error> {
    let chain = input.chain;
    let assertion = input.assertion;
    if chain.status() != ChainStatus::Active
        || assertion.consumer != REMAP_CONSUMER
        || !matches!(
            assertion.operation.as_str(),
            "remap.dns.activate" | "remap.dns.deactivate"
        )
    {
        return Err(Error::Authority);
    }
    let grant = chain.grant(&assertion.grant_id).ok_or(Error::Authority)?;
    if grant.consumer != REMAP_CONSUMER {
        return Err(Error::Authority);
    }
    let root_key = ed25519_dalek::VerifyingKey::from_bytes(&chain.group().public_key).map_err(|_| Error::Proof)?;
    input.membership.verify(&root_key).map_err(|_| Error::Proof)?;
    input
        .membership
        .certificate
        .validate_time(input.now)
        .map_err(|_| Error::Authority)?;
    input.revocations.verify(&root_key).map_err(|_| Error::Proof)?;
    if input.membership.certificate.hive_id != chain.hive()
        || input.membership.certificate.node_id != grant.signer_node
        || input.revocations.list.hive_id != chain.hive()
        || input.revocations.contains(&grant.signer_node)
        || input.revocations.list.serial != input.status.status.member_serial
        || input.revocations.list.issued_at > input.status.status.issued_at
        || input.status.status.grant_serial != chain.grant_revocation_serial()
    {
        return Err(Error::Authority);
    }
    input.status.verify(
        &chain.group().public_key,
        &StatusScope {
            hive: chain.hive(),
            head: chain.tip(),
            member_floor: input.member_serial_floor,
            grant_floor: chain.grant_revocation_serial(),
            now: input.now,
            maximum_age: input.maximum_status_age,
        },
    )?;
    assertion.verify_binding(grant, input.challenge, input.current_request, input.target, input.now)?;
    let retain_until = assertion
        .expires_at
        .checked_add(MAX_REMAP_ASSERTION_AGE)
        .ok_or(Error::Bound)?;
    ledger.redeem(input.challenge, assertion.signer_node, retain_until)
}

fn hash(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
