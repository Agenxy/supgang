//! Typed root grants. This is an offline chain codec, not an enabled remote-admin service.
//!
//! The outer field order is shared with future release and code-signing grants.
//! Those kinds are recognized but refused until their policy decoders exist.

use minicbor::{Decoder, Encoder};

use super::{Operation, RootStep};
use crate::{
    authority::SubjectCustody,
    device_key::{DevicePublicKey, DeviceSignature},
    ids::{HiveId, NodeId},
    threshold::{Digest, Error, array, canonical, count, fixed},
};

const POSSESSION_DOMAIN: &[u8] = b"supgang/role-possession/v1\0";
const MAX_LIFETIME: u64 = 366 * 24 * 60 * 60;
const MAX_OPERATIONS: usize = 8;

/// A closed grant kind. Only owner-action policy is currently implemented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Exact consumer actions.
    OwnerAction,
    /// Reserved for ADR 0007's release policy.
    Release,
    /// Reserved for ADR 0007's signing policy.
    CodeSigning,
}

impl Kind {
    const fn text(self) -> &'static str {
        match self {
            Self::OwnerAction => "owner-action",
            Self::Release => "release",
            Self::CodeSigning => "code-signing",
        }
    }

    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "owner-action" => Ok(Self::OwnerAction),
            "release" => Ok(Self::Release),
            "code-signing" => Ok(Self::CodeSigning),
            _ => Err(Error::Invalid),
        }
    }
}

/// Root-enrolled signer class. The label alone is not hardware attestation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerRole {
    /// A device credential, incapable of satisfying required presence.
    Device,
    /// A root-enrolled owner-presence credential; physical custody is a separate gate.
    OwnerPresence,
}

impl SignerRole {
    const fn text(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::OwnerPresence => "owner-presence",
        }
    }

    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "device" => Ok(Self::Device),
            "owner-presence" => Ok(Self::OwnerPresence),
            _ => Err(Error::Invalid),
        }
    }
}

/// Whether a grant demands a fresh carried-device approval for each action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Presence {
    /// Fresh approval required.
    Required,
    /// Standing root policy permits an assertion without a presence prompt.
    Policy,
}

impl Presence {
    const fn text(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Policy => "policy",
        }
    }

    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "required" => Ok(Self::Required),
            "policy" => Ok(Self::Policy),
            _ => Err(Error::Invalid),
        }
    }
}

/// Exact operation identifier and its fixed presence policy.
#[derive(Clone, Eq, PartialEq)]
pub struct AllowedOperation {
    /// Consumer-defined operation, without wildcard matching.
    pub name: String,
    /// Root-authorized minimum approval mode.
    pub presence: Presence,
}

/// Exact target scope; a hive-wide grant is an explicit, high-impact choice.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum TargetScope {
    /// A single target device.
    Node(NodeId),
    /// All enrolled nodes of this exact hive.
    HiveNodes(HiveId),
}

/// Canonical owner-action grant under a root step.
#[derive(Clone, Eq, PartialEq)]
pub struct Grant {
    /// Stable founding hive.
    pub hive: HiveId,
    /// Random, never-reused grant identity.
    pub id: [u8; 16],
    /// Closed kind; only `OwnerAction` can be encoded today.
    pub kind: Kind,
    /// Exact product identifier.
    pub consumer: String,
    /// P-256 signer key; signer algorithms can extend this tagged field later.
    pub signer: DevicePublicKey,
    /// Device to which this credential was enrolled.
    pub signer_node: NodeId,
    /// Root-enrolled signer class.
    pub signer_role: SignerRole,
    /// Root-enrolled custody label; this is not hardware attestation.
    pub signer_custody: SubjectCustody,
    /// Strict low-S proof over the canonical grant identity and enrolled signer fields.
    pub possession: [u8; 64],
    /// First permitted UNIX second.
    pub not_before: u64,
    /// Last permitted UNIX second.
    pub not_after: u64,
    /// Root-step predecessor bound into the payload.
    pub issuer_head: Digest,
    /// Predecessor's sequence, repeated for consumer rollback checks.
    pub issuer_sequence: u64,
    /// Exact target or explicitly hive-wide target scope.
    pub target: TargetScope,
    /// Sorted, unique operations, at most eight.
    pub operations: Vec<AllowedOperation>,
}

impl Grant {
    /// Canonical bytes to be signed by the grant's signer as possession proof.
    ///
    /// # Errors
    /// Refuses an invalid consumer, ID, or unimplemented grant kind.
    pub fn possession_message(&self) -> Result<Vec<u8>, Error> {
        if self.kind != Kind::OwnerAction || self.id == [0; 16] || !valid_consumer_id(&self.consumer) {
            return Err(Error::Invalid);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(10)?
            .u8(1)?
            .bytes(self.hive.as_bytes())?
            .bytes(&self.id)?
            .str(self.kind.text())?
            .str(&self.consumer)?
            .str("p256")?
            .bytes(&self.signer.to_bytes())?
            .bytes(self.signer_node.as_bytes())?
            .str(self.signer_role.text())?
            .str(custody_text(self.signer_custody))?;
        Ok(e.into_writer())
    }

    fn validate(&self) -> Result<(), Error> {
        if self.not_before >= self.not_after
            || self.not_after - self.not_before > MAX_LIFETIME
            || self.operations.is_empty()
            || self.operations.len() > MAX_OPERATIONS
            || matches!(self.target, TargetScope::HiveNodes(hive) if hive != self.hive)
        {
            return Err(Error::Bound);
        }
        if self.signer_role == SignerRole::OwnerPresence && self.signer_custody != SubjectCustody::Hardware {
            return Err(Error::Authority);
        }
        let mut previous = "";
        for operation in &self.operations {
            if !valid_name(&operation.name, 64)
                || operation.name.as_str() <= previous
                || (operation.presence == Presence::Required && self.signer_role != SignerRole::OwnerPresence)
            {
                return Err(Error::Invalid);
            }
            previous = &operation.name;
        }
        let proof = DeviceSignature::from_bytes(&self.possession).map_err(|_| Error::Proof)?;
        self.signer
            .verify_domain(POSSESSION_DOMAIN, &self.possession_message()?, &proof)
            .map_err(|_| Error::Proof)
    }

    /// Encode a strictly checked grant using the common grant field order.
    ///
    /// # Errors
    /// Refuses malformed policy, missing signer possession or unsupported kind.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut e = Encoder::new(Vec::new());
        e.array(12)?
            .u8(1)?
            .bytes(self.hive.as_bytes())?
            .bytes(&self.id)?
            .str(self.kind.text())?
            .str(&self.consumer)?;
        e.array(1)?
            .array(6)?
            .str("p256")?
            .bytes(&self.signer.to_bytes())?
            .bytes(self.signer_node.as_bytes())?
            .str(self.signer_role.text())?
            .str(custody_text(self.signer_custody))?
            .bytes(&self.possession)?;
        e.u8(1)?
            .u64(self.not_before)?
            .u64(self.not_after)?
            .bytes(&self.issuer_head)?
            .u64(self.issuer_sequence)?;
        e.array(2)?;
        match self.target {
            TargetScope::Node(node) => {
                e.array(2)?.str("node")?.bytes(node.as_bytes())?;
            }
            TargetScope::HiveNodes(hive) => {
                e.array(2)?.str("hive-nodes")?.bytes(hive.as_bytes())?;
            }
        }
        e.array(u64::try_from(self.operations.len()).map_err(|_| Error::Bound)?)?;
        for operation in &self.operations {
            e.array(2)?.str(&operation.name)?.str(operation.presence.text())?;
        }
        Ok(e.into_writer())
    }

    /// Decode a bounded, canonical owner-action grant.
    ///
    /// # Errors
    /// Refuses unsupported kinds, thresholds, signer algorithms and malformed policy.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 12 * 1024 {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 12)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let hive = HiveId::from_bytes(fixed(&mut d)?);
        let id = fixed(&mut d)?;
        let kind = Kind::parse(d.str()?)?;
        let consumer = d.str()?.to_owned();
        array(&mut d, 1)?;
        array(&mut d, 6)?;
        if d.str()? != "p256" {
            return Err(Error::Invalid);
        }
        let signer = DevicePublicKey::from_bytes(d.bytes()?).map_err(|_| Error::Invalid)?;
        let signer_node = NodeId::from_bytes(fixed(&mut d)?);
        let signer_role = SignerRole::parse(d.str()?)?;
        let signer_custody = parse_custody(d.str()?)?;
        let possession = fixed(&mut d)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let not_before = d.u64()?;
        let not_after = d.u64()?;
        let issuer_head = fixed(&mut d)?;
        let issuer_sequence = d.u64()?;
        array(&mut d, 2)?;
        array(&mut d, 2)?;
        let target_tag = d.str()?;
        let target_bytes = fixed(&mut d)?;
        let target = match target_tag {
            "node" => TargetScope::Node(NodeId::from_bytes(target_bytes)),
            "hive-nodes" => TargetScope::HiveNodes(HiveId::from_bytes(target_bytes)),
            _ => return Err(Error::Invalid),
        };
        let length = count(&mut d, MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(length);
        for _ in 0..length {
            array(&mut d, 2)?;
            operations.push(AllowedOperation {
                name: d.str()?.to_owned(),
                presence: Presence::parse(d.str()?)?,
            });
        }
        let result = Self {
            hive,
            id,
            kind,
            consumer,
            signer,
            signer_node,
            signer_role,
            signer_custody,
            possession,
            not_before,
            not_after,
            issuer_head,
            issuer_sequence,
            target,
            operations,
        };
        canonical(bytes, &result.encode()?)?;
        Ok(result)
    }
}

/// Typed, independently sequenced revocation of one grant identity.
#[derive(Clone, Eq, PartialEq)]
pub struct Revocation {
    /// Stable founding hive.
    pub hive: HiveId,
    /// Grant identity.
    pub id: [u8; 16],
    /// Exact grant kind.
    pub kind: Kind,
    /// Monotonic grant-and-role revocation serial.
    pub serial: u64,
    /// Root-step predecessor.
    pub issuer_head: Digest,
    /// Predecessor sequence.
    pub issuer_sequence: u64,
}

impl Revocation {
    /// Encode canonical revocation payload.
    ///
    /// # Errors
    /// Refuses zero ID/serial or unsupported kind.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.id == [0; 16] || self.serial == 0 || self.kind != Kind::OwnerAction {
            return Err(Error::Invalid);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(7)?
            .u8(1)?
            .bytes(self.hive.as_bytes())?
            .bytes(&self.id)?
            .str(self.kind.text())?
            .u64(self.serial)?
            .bytes(&self.issuer_head)?
            .u64(self.issuer_sequence)?;
        Ok(e.into_writer())
    }

    /// Decode a canonical, bounded revocation payload.
    ///
    /// # Errors
    /// Refuses unknown kind or noncanonical fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 256 {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 7)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let result = Self {
            hive: HiveId::from_bytes(fixed(&mut d)?),
            id: fixed(&mut d)?,
            kind: Kind::parse(d.str()?)?,
            serial: d.u64()?,
            issuer_head: fixed(&mut d)?,
            issuer_sequence: d.u64()?,
        };
        canonical(bytes, &result.encode()?)?;
        Ok(result)
    }
}

/// Check a grant payload against the authenticated root-step envelope.
///
/// # Errors
/// Refuses a cross-hive payload, stale issuer head or wrong operation schema.
pub fn validate_step(step: &RootStep) -> Result<(), Error> {
    match step.operation {
        Operation::Grant => {
            let grant = Grant::decode(&step.payload)?;
            if grant.hive != step.hive {
                return Err(Error::Authority);
            }
            if grant.issuer_head != step.predecessor {
                return Err(Error::Authority);
            }
            if grant.issuer_sequence != step.sequence.saturating_sub(1) {
                return Err(Error::Authority);
            }
        }
        Operation::RevokeGrant => {
            let revoke = Revocation::decode(&step.payload)?;
            if revoke.hive != step.hive {
                return Err(Error::Authority);
            }
            if revoke.issuer_head != step.predecessor {
                return Err(Error::Authority);
            }
            if revoke.issuer_sequence != step.sequence.saturating_sub(1) {
                return Err(Error::Authority);
            }
        }
        _ => {}
    }
    Ok(())
}

fn valid_name(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.starts_with(['.', '-'])
        && !value.ends_with(['.', '-'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-')
        && !value.contains("..")
}

fn valid_consumer_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with(['.', '-'])
        && !value.ends_with(['.', '-'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || byte.is_ascii_digit() || byte == b'.' || byte == b'-')
        && !value.contains("..")
}

const fn custody_text(value: SubjectCustody) -> &'static str {
    match value {
        SubjectCustody::Hardware => "hardware",
        SubjectCustody::File => "file",
        SubjectCustody::Synced => "synced",
    }
}

fn parse_custody(value: &str) -> Result<SubjectCustody, Error> {
    match value {
        "hardware" => Ok(SubjectCustody::Hardware),
        "file" => Ok(SubjectCustody::File),
        "synced" => Ok(SubjectCustody::Synced),
        _ => Err(Error::Invalid),
    }
}
