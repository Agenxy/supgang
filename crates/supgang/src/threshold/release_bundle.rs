//! Bounded, canonical evidence container for an independently verified release.
//!
//! The root key must be the pinned founding key. Succession is intentionally
//! unsupported until the consumer wire contract includes its proof chain.

use minicbor::{Decoder, Encoder, data::Type};

use crate::{
    ids::HiveId,
    threshold::{
        Error, array, canonical, fixed,
        status::{Scope, SignedStatus},
        step::{
            Operation, SignedStep,
            grant::Grant,
            role_grant::{ReleasePresence, RoleGrant, RolePolicy},
        },
    },
};

/// Maximum release authority file length, including every nested record.
pub const MAX_BYTES: usize = 256 * 1024;

/// Root grants and status needed to check release authority.
pub struct ReleaseBundle {
    /// Raw canonical role step, kept to verify the signature before parsing it.
    pub role_step: Vec<u8>,
    /// Root signature over the raw role step.
    pub role_signature: [u8; 64],
    /// Raw canonical owner grant step for carried-device releases.
    pub owner_step: Option<Vec<u8>>,
    /// Root signature over the owner step; present exactly with it.
    pub owner_signature: Option<[u8; 64]>,
    /// Raw canonical signed status.
    pub status: Vec<u8>,
}

impl ReleaseBundle {
    /// Encode the six-field canonical container.
    ///
    /// # Errors
    /// Refuses a mismatched owner pair or an oversized file.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.owner_step.is_some() != self.owner_signature.is_some() {
            return Err(Error::Invalid);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(6)?.u8(1)?.bytes(&self.role_step)?.bytes(&self.role_signature)?;
        if let Some(step) = &self.owner_step {
            e.bytes(step)?;
        } else {
            e.null()?;
        }
        if let Some(signature) = &self.owner_signature {
            e.bytes(signature)?;
        } else {
            e.null()?;
        }
        e.bytes(&self.status)?;
        let bytes = e.into_writer();
        if bytes.len() > MAX_BYTES {
            return Err(Error::Bound);
        }
        Ok(bytes)
    }

    /// Decode exactly one canonical bounded container.
    ///
    /// # Errors
    /// Refuses unsupported versions, tags, indefinite lengths, extra fields,
    /// trailing bytes, nonminimal integers and mismatched owner nulls.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::Bound);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 6)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let role_step = d.bytes()?.to_vec();
        let role_signature = fixed(&mut d)?;
        let owner_step = if d.datatype()? == Type::Null {
            d.null()?;
            None
        } else {
            Some(d.bytes()?.to_vec())
        };
        let owner_signature = if d.datatype()? == Type::Null {
            d.null()?;
            None
        } else {
            Some(fixed(&mut d)?)
        };
        let status = d.bytes()?.to_vec();
        let result = Self {
            role_step,
            role_signature,
            owner_step,
            owner_signature,
            status,
        };
        canonical(bytes, &result.encode()?)?;
        Ok(result)
    }

    /// Verify a bundle with the pinned founding root and protected status scope.
    ///
    /// The caller still verifies the signed statement, its artifact bytes and
    /// protected version high-water state separately.
    ///
    /// # Errors
    /// Refuses a forged, revoked, stale, wrong-role or incomplete bundle.
    pub fn verify(&self, founding_root: &[u8; 32], scope: &Scope<'_>) -> Result<(RoleGrant, Option<Grant>), Error> {
        if HiveId::from_root_verifying_key(founding_root) != scope.hive {
            return Err(Error::Authority);
        }
        let role_step = SignedStep::decode_verified(&self.role_step, self.role_signature, founding_root)?;
        if role_step.step.operation != Operation::Grant || role_step.step.hive != scope.hive {
            return Err(Error::Authority);
        }
        let role = RoleGrant::decode(&role_step.step.payload)?;
        let status = SignedStatus::decode(&self.status)?;
        status.verify(founding_root, scope)?;
        role.check_active_status(&status.status)?;
        let carried = match &role.policy {
            RolePolicy::Release { presence, .. } => *presence == ReleasePresence::CarriedDevice,
            RolePolicy::CodeSigning { .. } => return Err(Error::Authority),
        };
        let owner = match (&self.owner_step, &self.owner_signature) {
            (Some(bytes), Some(signature)) if carried => {
                let step = SignedStep::decode_verified(bytes, *signature, founding_root)?;
                if step.step.operation != Operation::Grant || step.step.hive != scope.hive {
                    return Err(Error::Authority);
                }
                let grant = Grant::decode(&step.step.payload)?;
                status.status.check_active_grant(&grant.id, &[grant.signer_node])?;
                Some(grant)
            }
            (None, None) if !carried => None,
            _ => return Err(Error::Authority),
        };
        Ok((role, owner))
    }
}
