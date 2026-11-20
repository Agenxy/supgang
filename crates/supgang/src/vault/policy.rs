//! Canonical, bounded policy for one agent-purpose signing key.

use minicbor::{Decoder, Encoder, data::Type};

use super::{VaultError, signing::validate_context};
use crate::ids::NodeId;

/// Maximum contexts bound to one signing key.
pub const MAX_CONTEXTS: usize = 16;
/// Maximum device identities in a narrowed member allowlist.
pub const MAX_ALLOWED_MEMBERS: usize = 64;
/// Maximum encoded policy size, checked before decoding.
pub const MAX_POLICY_BYTES: usize = 4096;

/// Immutable contexts and optional exact member allowlist for one purpose key.
///
/// `None` admits every currently authorized, unrevoked member; membership
/// itself must be checked by the caller for every signing request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentPolicy {
    contexts: Vec<String>,
    members: Option<Vec<NodeId>>,
}

impl AgentPolicy {
    /// Creates a canonical policy from already sorted, unique values.
    ///
    /// # Errors
    /// Refuses empty, duplicate, unsorted or overlong contexts and allowlists.
    pub fn new(contexts: Vec<String>, members: Option<Vec<NodeId>>) -> Result<Self, VaultError> {
        if contexts.is_empty()
            || contexts.len() > MAX_CONTEXTS
            || contexts.iter().any(|context| validate_context(context).is_err())
            || contexts
                .windows(2)
                .any(|pair| pair.first().zip(pair.last()).is_some_and(|(left, right)| left >= right))
            || members.as_ref().is_some_and(|list| {
                list.is_empty()
                    || list.len() > MAX_ALLOWED_MEMBERS
                    || list
                        .windows(2)
                        .any(|pair| pair.first().zip(pair.last()).is_some_and(|(left, right)| left >= right))
            })
        {
            return Err(VaultError::InvalidAgentPolicy);
        }
        Ok(Self { contexts, members })
    }

    /// Returns true only for a context fixed when the key was created.
    #[must_use]
    pub fn admits_context(&self, context: &str) -> bool {
        self.contexts
            .binary_search_by(|candidate| candidate.as_str().cmp(context))
            .is_ok()
    }

    /// Returns true for an allowed member identity. The caller must also
    /// verify current membership and revocation independently.
    #[must_use]
    pub fn admits_member(&self, node: NodeId) -> bool {
        self.members
            .as_ref()
            .is_none_or(|members| members.binary_search(&node).is_ok())
    }

    /// Returns the exact context list.
    #[must_use]
    pub fn contexts(&self) -> &[String] {
        &self.contexts
    }

    /// Returns the narrowed member list, or `None` for all members.
    #[must_use]
    pub fn members(&self) -> Option<&[NodeId]> {
        self.members.as_deref()
    }

    /// Canonical bounded encoding for the immutable vault policy.
    ///
    /// # Errors
    /// Returns an error if the policy cannot be encoded within its bound.
    pub fn encode(&self) -> Result<Vec<u8>, VaultError> {
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(3)
            .and_then(|e| e.u8(1))
            .and_then(|e| {
                e.array(u64::try_from(self.contexts.len()).map_err(|_| minicbor::encode::Error::message("contexts"))?)
            })
            .map_err(|_| VaultError::InvalidAgentPolicy)?;
        for context in &self.contexts {
            encoder.str(context).map_err(|_| VaultError::InvalidAgentPolicy)?;
        }
        if let Some(members) = &self.members {
            encoder
                .array(u64::try_from(members.len()).map_err(|_| VaultError::InvalidAgentPolicy)?)
                .map_err(|_| VaultError::InvalidAgentPolicy)?;
            for member in members {
                encoder
                    .bytes(member.as_bytes())
                    .map_err(|_| VaultError::InvalidAgentPolicy)?;
            }
        } else {
            encoder.null().map_err(|_| VaultError::InvalidAgentPolicy)?;
        }
        let bytes = encoder.into_writer();
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(VaultError::InvalidAgentPolicy);
        }
        Ok(bytes)
    }

    /// Decode only canonical bounded policy bytes.
    ///
    /// # Errors
    /// Returns an error for malformed, noncanonical, or oversized policy bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(VaultError::InvalidAgentPolicy);
        }
        let parse = || -> Result<Self, VaultError> {
            let mut decoder = Decoder::new(bytes);
            if decoder.array().map_err(|_| VaultError::InvalidAgentPolicy)? != Some(3)
                || decoder.u8().map_err(|_| VaultError::InvalidAgentPolicy)? != 1
            {
                return Err(VaultError::InvalidAgentPolicy);
            }
            let count = decoder
                .array()
                .map_err(|_| VaultError::InvalidAgentPolicy)?
                .ok_or(VaultError::InvalidAgentPolicy)?;
            if count == 0 || count > MAX_CONTEXTS as u64 {
                return Err(VaultError::InvalidAgentPolicy);
            }
            let mut contexts = Vec::with_capacity(usize::try_from(count).map_err(|_| VaultError::InvalidAgentPolicy)?);
            for _ in 0..count {
                contexts.push(decoder.str().map_err(|_| VaultError::InvalidAgentPolicy)?.to_owned());
            }
            let members = if decoder.datatype().map_err(|_| VaultError::InvalidAgentPolicy)? == Type::Null {
                decoder.null().map_err(|_| VaultError::InvalidAgentPolicy)?;
                None
            } else {
                let count = decoder
                    .array()
                    .map_err(|_| VaultError::InvalidAgentPolicy)?
                    .ok_or(VaultError::InvalidAgentPolicy)?;
                if count == 0 || count > MAX_ALLOWED_MEMBERS as u64 {
                    return Err(VaultError::InvalidAgentPolicy);
                }
                let mut members =
                    Vec::with_capacity(usize::try_from(count).map_err(|_| VaultError::InvalidAgentPolicy)?);
                for _ in 0..count {
                    let bytes: [u8; 32] = decoder
                        .bytes()
                        .map_err(|_| VaultError::InvalidAgentPolicy)?
                        .try_into()
                        .map_err(|_| VaultError::InvalidAgentPolicy)?;
                    members.push(NodeId::from_bytes(bytes));
                }
                Some(members)
            };
            Self::new(contexts, members)
        }();
        let policy = parse?;
        if policy.encode()?.as_slice() != bytes {
            return Err(VaultError::InvalidAgentPolicy);
        }
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentPolicy, MAX_CONTEXTS};
    use crate::{ids::NodeId, vault::VaultError};

    #[test]
    fn canonical_codec_refuses_extra_unsorted_duplicate_and_oversized_data() -> Result<(), VaultError> {
        let first = NodeId::from_bytes([1; 32]);
        let second = NodeId::from_bytes([2; 32]);
        let policy = AgentPolicy::new(vec!["build.stage".to_owned()], Some(vec![first, second]))?;
        let bytes = policy.encode()?;
        assert_eq!(AgentPolicy::decode(&bytes)?, policy);
        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            AgentPolicy::decode(&trailing),
            Err(VaultError::InvalidAgentPolicy)
        ));
        assert!(matches!(
            AgentPolicy::new(vec!["z".to_owned(), "a".to_owned()], None),
            Err(VaultError::InvalidAgentPolicy)
        ));
        assert!(matches!(
            AgentPolicy::new(vec!["a".to_owned(), "a".to_owned()], None),
            Err(VaultError::InvalidAgentPolicy)
        ));
        assert!(matches!(
            AgentPolicy::new(vec!["a".to_owned(); MAX_CONTEXTS + 1], None),
            Err(VaultError::InvalidAgentPolicy)
        ));
        assert!(matches!(
            AgentPolicy::new(vec!["a".to_owned()], Some(vec![second, first])),
            Err(VaultError::InvalidAgentPolicy)
        ));
        assert!(policy.admits_member(first));
        assert!(!policy.admits_member(NodeId::from_bytes([3; 32])));
        Ok(())
    }
}
