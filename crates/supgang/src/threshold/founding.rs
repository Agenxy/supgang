//! Two-round, dealerless DKG through a bounded, tamperable in-memory channel.

use std::collections::{BTreeMap, BTreeSet};

use frost_ed25519::{self as frost, Identifier, keys::dkg};
use minicbor::{Decoder, Encoder};

use super::{Digest, Error, MAX_PARTICIPANTS, array, canonical, count, fixed, hash, length, rng};
use crate::device_key::DevicePublicKey;

/// Explicit owner choices for a simulated DKG.
#[derive(Clone, Copy, Debug)]
pub struct Parameters {
    /// Quorum size.
    pub k: u16,
    /// Roster size.
    pub n: u16,
    /// Explicit acceptance of inability to survive a single loss.
    pub accept_single_loss_failure: bool,
}

impl Parameters {
    /// Checks the ADR range and loss policy, then the pinned library's limit.
    ///
    /// # Errors
    /// Refuses invalid bounds, unaccepted single-loss failure, or k=1 DKG.
    pub fn validate(self) -> Result<(), Error> {
        if self.k == 0 || self.k > self.n || usize::from(self.n) > MAX_PARTICIPANTS {
            return Err(Error::Invalid);
        }
        if self.n < self.k + 1 && !self.accept_single_loss_failure {
            return Err(Error::SingleLoss);
        }
        if self.k == 1 {
            return Err(Error::ThresholdOne);
        }
        Ok(())
    }
}

/// Public participant identity and verifying share. Custody is always `file`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Participant {
    /// Nonzero FROST participant number, assigned by roster order.
    pub id: u16,
    /// Owner-paired device public key.
    pub device: DevicePublicKey,
    /// Serialized Ed25519 verifying share.
    pub verifying_share: [u8; 32],
}

/// Complete public DKG output, encoded independently of FROST's serializer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupDescriptor {
    /// Hive label, 1..=63 visible ASCII bytes.
    pub label: String,
    /// Quorum size.
    pub k: u16,
    /// Share generation for session and control-channel binding.
    pub generation: u64,
    /// Sorted contiguous participant ids, at most 16 unique device keys.
    pub participants: Vec<Participant>,
    /// Ordinary Ed25519 group verification key.
    pub public_key: [u8; 32],
}

impl GroupDescriptor {
    /// Canonical `[1,label,k,n,generation,[[id,device,share,"file"]...],key]`.
    ///
    /// # Errors
    /// Refuses malformed keys, repeated devices, invalid order or bounds.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut e = Encoder::new(Vec::new());
        e.array(7)?.u8(1)?.str(&self.label)?.u16(self.k)?;
        e.u64(length(self.participants.len())?)?.u64(self.generation)?;
        e.array(length(self.participants.len())?)?;
        for participant in &self.participants {
            e.array(4)?.u16(participant.id)?.bytes(&participant.device.to_bytes())?;
            e.bytes(&participant.verifying_share)?.str("file")?;
        }
        e.bytes(&self.public_key)?;
        Ok(e.into_writer())
    }

    /// Decodes bounded, exact canonical descriptor bytes.
    ///
    /// # Errors
    /// Refuses noncanonical forms, unknown custody or malformed public outputs.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 4096 {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 7)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let label = d.str()?.to_owned();
        let k = d.u16()?;
        let n = d.u16()?;
        let generation = d.u64()?;
        let size = count(&mut d, MAX_PARTICIPANTS)?;
        if usize::from(n) != size {
            return Err(Error::Invalid);
        }
        let mut participants = Vec::with_capacity(size);
        for _ in 0..size {
            array(&mut d, 4)?;
            let id = d.u16()?;
            let device = DevicePublicKey::from_bytes(d.bytes()?)?;
            let verifying_share = fixed(&mut d)?;
            if d.str()? != "file" {
                return Err(Error::Invalid);
            }
            participants.push(Participant {
                id,
                device,
                verifying_share,
            });
        }
        let result = Self {
            label,
            k,
            generation,
            participants,
            public_key: fixed(&mut d)?,
        };
        canonical(bytes, &result.encode()?)?;
        Ok(result)
    }

    /// Content identity covering every public output and custody label.
    ///
    /// # Errors
    /// Refuses invalid descriptor fields.
    pub fn digest(&self) -> Result<Digest, Error> {
        Ok(hash(&self.encode()?))
    }

    /// Reconstructs the library's public verification package.
    ///
    /// # Errors
    /// Refuses malformed shares or group keys.
    pub fn public_package(&self) -> Result<frost::keys::PublicKeyPackage, Error> {
        self.validate()?;
        let shares = self
            .participants
            .iter()
            .map(|p| {
                Ok((
                    Identifier::try_from(p.id)?,
                    frost::keys::VerifyingShare::deserialize(&p.verifying_share)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, Error>>()?;
        Ok(frost::keys::PublicKeyPackage::new(
            shares,
            frost::VerifyingKey::deserialize(&self.public_key)?,
            Some(self.k),
        ))
    }

    fn validate(&self) -> Result<(), Error> {
        if self.label.is_empty()
            || self.label.len() > 63
            || !self.label.bytes().all(|b| b.is_ascii_graphic())
            || self.k < 2
            || usize::from(self.k) > self.participants.len()
            || self.participants.len() > MAX_PARTICIPANTS
        {
            return Err(Error::Invalid);
        }
        let mut devices = BTreeSet::new();
        for (index, p) in self.participants.iter().enumerate() {
            if usize::from(p.id) != index + 1 || !devices.insert(p.device.to_bytes()) {
                return Err(Error::Invalid);
            }
            frost::keys::VerifyingShare::deserialize(&p.verifying_share)?;
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.public_key).map_err(|_| Error::Proof)?;
        if key.is_weak() {
            return Err(Error::Proof);
        }
        frost::VerifyingKey::deserialize(&self.public_key)?;
        Ok(())
    }
}

/// Recovery descriptor's independent monotonic history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryDescriptor {
    /// Initial sequence is zero; changes increment exactly once.
    pub sequence: u64,
    /// Previous recovery descriptor digest, all zero at founding.
    pub predecessor: Digest,
    /// Separate DKG group.
    pub group: GroupDescriptor,
}

impl RecoveryDescriptor {
    /// Canonical independent descriptor history.
    ///
    /// # Errors
    /// Refuses malformed public output.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut e = Encoder::new(Vec::new());
        e.array(4)?
            .u8(1)?
            .u64(self.sequence)?
            .bytes(&self.predecessor)?
            .bytes(&self.group.encode()?)?;
        Ok(e.into_writer())
    }

    /// Strict canonical descriptor decoding.
    ///
    /// # Errors
    /// Refuses invalid versions, trailing bytes or malformed groups.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 4200 {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 4)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let result = Self {
            sequence: d.u64()?,
            predecessor: fixed(&mut d)?,
            group: GroupDescriptor::decode(d.bytes()?)?,
        };
        canonical(bytes, &result.encode()?)?;
        Ok(result)
    }

    /// SHA-256 identity of this recovery descriptor.
    ///
    /// # Errors
    /// Refuses malformed descriptor fields.
    pub fn digest(&self) -> Result<Digest, Error> {
        Ok(hash(&self.encode()?))
    }
}

/// Mutable routed packages. No round-two secret packages are exposed here.
#[derive(Default)]
pub struct Channel {
    /// Round-one broadcast keyed by sender.
    pub round1: BTreeMap<Identifier, dkg::round1::Package>,
    /// Round-two private delivery keyed by (sender, recipient).
    pub round2: BTreeMap<(Identifier, Identifier), dkg::round2::Package>,
}

/// Per-participant DKG output. Secret material is not formatted or serialized.
pub struct Output {
    /// Disposable file-custody share, resident in memory.
    pub key: frost::keys::KeyPackage,
    /// All public verifying shares and group key, computed by this participant.
    pub public: frost::keys::PublicKeyPackage,
    /// Descriptor independently assembled from this participant's outputs.
    pub descriptor: GroupDescriptor,
    /// SHA-256 of canonical `[1,group descriptor bytes,recovery descriptor bytes]`.
    pub founding_digest: Digest,
}

/// The complete simulated group's per-participant outputs.
pub struct Group {
    /// Outputs in contiguous participant-id order.
    pub outputs: Vec<Output>,
}

impl Group {
    /// Agreed descriptor; no output exists on an unsuccessful DKG.
    ///
    /// # Errors
    /// Refuses a missing output or inconsistent participant descriptors.
    pub fn descriptor(&self) -> Result<&GroupDescriptor, Error> {
        let first = &self.outputs.first().ok_or(Error::Invalid)?.descriptor;
        if self.outputs.iter().any(|o| &o.descriptor != first) {
            return Err(Error::Proof);
        }
        Ok(first)
    }
}

/// Runs both exchanges and each participant's final verification.
///
/// `recovery` is absent only when generating the independent recovery group.
/// Hooks represent a hostile transport, not an authenticated founding ceremony.
///
/// # Errors
/// Refuses duplicate identities, bad DKG packages, inconsistent public output,
/// unsupported parameters and channel bounds. No partial group is returned.
pub fn run(
    label: &str,
    parameters: Parameters,
    generation: u64,
    devices: &[DevicePublicKey],
    recovery: Option<&RecoveryDescriptor>,
    mut exchange: impl FnMut(u8, &mut Channel),
) -> Result<Group, Error> {
    parameters.validate()?;
    if devices.len() != usize::from(parameters.n) || label.len() > 63 {
        return Err(Error::Invalid);
    }
    if devices
        .iter()
        .map(DevicePublicKey::to_bytes)
        .collect::<BTreeSet<_>>()
        .len()
        != devices.len()
    {
        return Err(Error::Invalid);
    }
    let mut random = rng()?;
    let mut channel = Channel::default();
    let mut secrets = BTreeMap::new();
    for id in 1..=parameters.n {
        let identifier = Identifier::try_from(id)?;
        let (secret, public) = frost_core::keys::dkg::part1::<frost::Ed25519Sha512, _>(
            identifier,
            parameters.n,
            parameters.k,
            &mut random,
        )?;
        secrets.insert(identifier, secret);
        channel.round1.insert(identifier, public);
    }
    exchange(1, &mut channel);
    if channel.round1.len() != devices.len() || !channel.round2.is_empty() {
        return Err(Error::Invalid);
    }
    let mut rounds = BTreeMap::new();
    for (id, secret) in secrets {
        let received = channel
            .round1
            .iter()
            .filter(|(sender, _)| **sender != id)
            .map(|(sender, package)| (*sender, package.clone()))
            .collect::<BTreeMap<_, _>>();
        let (secret, outgoing) = frost_core::keys::dkg::part2(secret, &received)?;
        for (recipient, package) in outgoing {
            channel.round2.insert((id, recipient), package);
        }
        rounds.insert(id, (secret, received));
    }
    exchange(2, &mut channel);
    if channel.round2.len() != devices.len() * (devices.len() - 1) {
        return Err(Error::Invalid);
    }
    let mut outputs = Vec::with_capacity(devices.len());
    for (id, (secret, round1)) in rounds {
        let received = channel
            .round2
            .iter()
            .filter(|((_, recipient), _)| *recipient == id)
            .map(|((sender, _), package)| (*sender, package.clone()))
            .collect::<BTreeMap<_, _>>();
        let (key, public) = frost_core::keys::dkg::part3(&secret, &round1, &received)?;
        let mut participants = Vec::with_capacity(devices.len());
        for (index, device) in devices.iter().enumerate() {
            let id = u16::try_from(index + 1).map_err(|_| Error::Bound)?;
            let share = public
                .verifying_shares()
                .get(&Identifier::try_from(id)?)
                .ok_or(Error::Invalid)?;
            participants.push(Participant {
                id,
                device: *device,
                verifying_share: share.serialize()?.as_slice().try_into().map_err(|_| Error::Invalid)?,
            });
        }
        let descriptor = GroupDescriptor {
            label: label.to_owned(),
            k: parameters.k,
            generation,
            participants,
            public_key: public
                .verifying_key()
                .serialize()?
                .as_slice()
                .try_into()
                .map_err(|_| Error::Invalid)?,
        };
        let founding_digest = founding_digest(&descriptor, recovery)?;
        outputs.push(Output {
            key,
            public,
            descriptor,
            founding_digest,
        });
    }
    let group = Group { outputs };
    group.descriptor()?;
    Ok(group)
}

/// Binds the root's complete public descriptor and separately founded recovery.
///
/// # Errors
/// Refuses malformed descriptors.
pub fn founding_digest(group: &GroupDescriptor, recovery: Option<&RecoveryDescriptor>) -> Result<Digest, Error> {
    let mut e = Encoder::new(Vec::new());
    e.array(3)?.u8(1)?.bytes(&group.encode()?)?;
    if let Some(recovery) = recovery {
        e.bytes(&recovery.encode()?)?;
    } else {
        e.null()?;
    }
    Ok(hash(&e.into_writer()))
}
