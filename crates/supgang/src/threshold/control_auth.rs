//! Typed device-key proof scoped to one current roster and channel transcript.

use minicbor::Encoder;

use super::{Digest, Error, founding::GroupDescriptor};
use crate::{
    authority::device_node_id,
    device_key::{CONTROL_AUTH_DOMAIN, DevicePublicKey, DeviceSignature, DeviceSigner},
    ids::{HiveId, NodeId},
};

/// Exact fresh transcript expected by the receiving participant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Challenge {
    /// Stable hive id.
    pub hive: HiveId,
    /// Current group's canonical descriptor identity.
    pub descriptor: Digest,
    /// Current share generation.
    pub generation: u64,
    /// Device proving possession.
    pub self_node: NodeId,
    /// Intended receiving device.
    pub peer_node: NodeId,
    /// Fresh 32-byte receiver challenge.
    pub challenge: [u8; 32],
    /// 32-byte TLS exporter value; simulated bytes in this offline prototype.
    pub channel_binding: [u8; 32],
}

impl Challenge {
    /// Canonical typed proof message, excluding its device signing domain.
    ///
    /// # Errors
    /// Returns canonical encoder failures.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut e = Encoder::new(Vec::new());
        e.array(8)?
            .u8(1)?
            .bytes(self.hive.as_bytes())?
            .bytes(&self.descriptor)?
            .u64(self.generation)?;
        e.bytes(self.self_node.as_bytes())?.bytes(self.peer_node.as_bytes())?;
        e.bytes(&self.challenge)?.bytes(&self.channel_binding)?;
        Ok(e.into_writer())
    }
}

/// Device public key plus its typed challenge signature.
pub struct Proof {
    /// Device key, verified against the current roster before admission.
    pub key: DevicePublicKey,
    /// Low-s P-256 signature under the dedicated control-auth domain.
    pub signature: DeviceSignature,
}

impl Proof {
    /// Signs exactly the typed challenge as the named device.
    ///
    /// # Errors
    /// Refuses another self id or device-signing failure.
    pub fn sign(challenge: &Challenge, signer: &(impl DeviceSigner + ?Sized)) -> Result<Self, Error> {
        if challenge.self_node != device_node_id(signer.public_key()) {
            return Err(Error::Authority);
        }
        Ok(Self {
            key: signer.public_key(),
            signature: signer.sign_domain(CONTROL_AUTH_DOMAIN, &challenge.encode()?)?,
        })
    }

    /// Verifies against receiver-supplied fresh context and the current roster.
    ///
    /// # Errors
    /// Refuses foreign devices, changed challenge, peer, generation, descriptor,
    /// hive or channel binding. No application membership is conferred.
    pub fn verify(&self, expected: &Challenge, current: &GroupDescriptor) -> Result<(), Error> {
        if expected.descriptor != current.digest()?
            || expected.generation != current.generation
            || expected.self_node != device_node_id(self.key)
            || !current.participants.iter().any(|p| p.device == self.key)
            || !current
                .participants
                .iter()
                .any(|p| device_node_id(p.device) == expected.peer_node)
        {
            return Err(Error::Authority);
        }
        self.key
            .verify_domain(CONTROL_AUTH_DOMAIN, &expected.encode()?, &self.signature)?;
        Ok(())
    }
}
