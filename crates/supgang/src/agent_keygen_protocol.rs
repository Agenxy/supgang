//! Canonical, bounded remote agent-purpose key creation messages.

use hmac::{Hmac, KeyInit, Mac};
use minicbor::{Decoder, Encoder};
use sha2::Sha256;

use crate::{
    agent_sign_protocol::{MacBinding, ProtocolError},
    vault::{self, AgentPolicy},
};

/// Maximum canonical creation request, including the immutable policy.
pub const MAX_REQUEST_BYTES: usize = 4608;
/// Maximum canonical creation reply.
pub const MAX_RESPONSE_BYTES: usize = 128;
const REQUEST_DOMAIN: &[u8] = b"supgang/agent-keygen/request-mac/v1\0";
const RESPONSE_DOMAIN: &[u8] = b"supgang/agent-keygen/response-mac/v1\0";

/// One authenticated request to create a fresh, unpinned purpose key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeygenRequest {
    /// One-use caller-generated value.
    pub nonce: [u8; 32],
    /// Exact vault purpose name.
    pub purpose: String,
    /// Owner-visible non-secret description.
    pub note: String,
    /// Immutable contexts and certified-member allowlist.
    pub policy: AgentPolicy,
    /// Absolute Unix-seconds deadline, no more than five minutes ahead.
    pub expires_at: u64,
}

impl KeygenRequest {
    /// Check the request against the target's current clock.
    ///
    /// # Errors
    /// Returns an error for an expired, overlong, or invalid request.
    pub fn validate(&self, now: u64) -> Result<(), ProtocolError> {
        if now == 0 || self.expires_at < now || self.expires_at > now.saturating_add(300) {
            return Err(ProtocolError::Time);
        }
        if vault::validate_name(&self.purpose).is_err()
            || self.note.len() > vault::MAX_NOTE_BYTES
            || self.note.chars().any(char::is_control)
        {
            return Err(ProtocolError::Invalid);
        }
        Ok(())
    }

    /// Canonical bounded encoding of the exact requested effect.
    ///
    /// # Errors
    /// Returns an error for an invalid request or oversized encoding.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate_fields()?;
        let policy = self.policy.encode().map_err(|_| ProtocolError::Invalid)?;
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(6)
            .and_then(|e| e.u8(1))
            .and_then(|e| e.bytes(&self.nonce))
            .and_then(|e| e.str(&self.purpose))
            .and_then(|e| e.str(&self.note))
            .and_then(|e| e.bytes(&policy))
            .and_then(|e| e.u64(self.expires_at))
            .map_err(|_| ProtocolError::Invalid)?;
        let bytes = encoder.into_writer();
        if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
            return Err(ProtocolError::Invalid);
        }
        Ok(bytes)
    }

    /// Decode only canonical, bounded creation requests.
    ///
    /// # Errors
    /// Returns an error for malformed, noncanonical, or oversized input.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
            return Err(ProtocolError::Invalid);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| ProtocolError::Invalid)? != Some(6)
            || decoder.u8().map_err(|_| ProtocolError::Invalid)? != 1
        {
            return Err(ProtocolError::Invalid);
        }
        let nonce: [u8; 32] = decoder
            .bytes()
            .map_err(|_| ProtocolError::Invalid)?
            .try_into()
            .map_err(|_| ProtocolError::Invalid)?;
        let purpose = decoder.str().map_err(|_| ProtocolError::Invalid)?.to_owned();
        let note = decoder.str().map_err(|_| ProtocolError::Invalid)?.to_owned();
        let policy = AgentPolicy::decode(decoder.bytes().map_err(|_| ProtocolError::Invalid)?)
            .map_err(|_| ProtocolError::Invalid)?;
        let expires_at = decoder.u64().map_err(|_| ProtocolError::Invalid)?;
        let result = Self {
            nonce,
            purpose,
            note,
            policy,
            expires_at,
        };
        if result.encode()?.as_slice() != bytes {
            return Err(ProtocolError::Invalid);
        }
        Ok(result)
    }

    fn validate_fields(&self) -> Result<(), ProtocolError> {
        if vault::validate_name(&self.purpose).is_err()
            || self.note.len() > vault::MAX_NOTE_BYTES
            || self.note.chars().any(char::is_control)
        {
            return Err(ProtocolError::Invalid);
        }
        Ok(())
    }
}

/// A bounded response carrying only public key material on success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeygenReply {
    /// A fresh purpose key was sealed in the target vault.
    Created {
        /// Exact nonce from the creation request.
        nonce: [u8; 32],
        /// Raw Ed25519 public key for an independently installed consumer pin.
        public_key: [u8; 32],
    },
    /// No usable new key was created.
    Refused {
        /// Exact nonce from the refused request.
        nonce: [u8; 32],
    },
}

impl KeygenReply {
    /// Canonical bounded reply encoding.
    ///
    /// # Errors
    /// Returns an error if the reply cannot be encoded within its bound.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut encoder = Encoder::new(Vec::new());
        match self {
            Self::Created { nonce, public_key } => {
                encoder
                    .array(4)
                    .and_then(|e| e.u8(1))
                    .and_then(|e| e.u8(1))
                    .and_then(|e| e.bytes(nonce))
                    .and_then(|e| e.bytes(public_key))
                    .map_err(|_| ProtocolError::Invalid)?;
            }
            Self::Refused { nonce } => {
                encoder
                    .array(3)
                    .and_then(|e| e.u8(1))
                    .and_then(|e| e.u8(2))
                    .and_then(|e| e.bytes(nonce))
                    .map_err(|_| ProtocolError::Invalid)?;
            }
        }
        let bytes = encoder.into_writer();
        if bytes.is_empty() || bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ProtocolError::Invalid);
        }
        Ok(bytes)
    }

    /// Decode only canonical, bounded replies.
    ///
    /// # Errors
    /// Returns an error for malformed, noncanonical, or oversized input.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.is_empty() || bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ProtocolError::Invalid);
        }
        let mut decoder = Decoder::new(bytes);
        let count = decoder.array().map_err(|_| ProtocolError::Invalid)?;
        if decoder.u8().map_err(|_| ProtocolError::Invalid)? != 1 {
            return Err(ProtocolError::Invalid);
        }
        let kind = decoder.u8().map_err(|_| ProtocolError::Invalid)?;
        let result = match (count, kind) {
            (Some(4), 1) => Self::Created {
                nonce: fixed(&mut decoder)?,
                public_key: fixed(&mut decoder)?,
            },
            (Some(3), 2) => Self::Refused {
                nonce: fixed(&mut decoder)?,
            },
            _ => return Err(ProtocolError::Invalid),
        };
        if result.encode()?.as_slice() != bytes {
            return Err(ProtocolError::Invalid);
        }
        Ok(result)
    }

    /// Nonce that the response answers.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        match self {
            Self::Created { nonce, .. } | Self::Refused { nonce } => nonce,
        }
    }
}

fn fixed(decoder: &mut Decoder<'_>) -> Result<[u8; 32], ProtocolError> {
    decoder
        .bytes()
        .map_err(|_| ProtocolError::Invalid)?
        .try_into()
        .map_err(|_| ProtocolError::Invalid)
}

fn tag(
    domain: &[u8],
    exporter: &[u8; 32],
    binding: &MacBinding,
    payload: &[u8],
    max: usize,
) -> Result<[u8; 32], ProtocolError> {
    if payload.is_empty() || payload.len() > max {
        return Err(ProtocolError::Invalid);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(exporter).map_err(|_| ProtocolError::Authentication)?;
    mac.update(domain);
    mac.update(binding.hive.as_bytes());
    mac.update(binding.requester.as_bytes());
    mac.update(binding.signer.as_bytes());
    mac.update(&binding.stream.to_be_bytes());
    mac.update(&(u16::try_from(payload.len()).map_err(|_| ProtocolError::Invalid)?).to_be_bytes());
    mac.update(payload);
    Ok(mac.finalize().into_bytes().into())
}

/// Tag a key-creation request to one authenticated session and stream.
///
/// # Errors
/// Returns an error for an invalid payload or MAC key.
pub fn request_tag(exporter: &[u8; 32], binding: &MacBinding, bytes: &[u8]) -> Result<[u8; 32], ProtocolError> {
    tag(REQUEST_DOMAIN, exporter, binding, bytes, MAX_REQUEST_BYTES)
}

/// Verify a request's session-bound tag.
///
/// # Errors
/// Returns an error for an invalid payload or mismatched tag.
pub fn verify_request_tag(
    exporter: &[u8; 32],
    binding: &MacBinding,
    bytes: &[u8],
    expected: &[u8; 32],
) -> Result<(), ProtocolError> {
    verify(REQUEST_DOMAIN, exporter, binding, bytes, expected, MAX_REQUEST_BYTES)
}

/// Tag a key-creation response to one authenticated session and stream.
///
/// # Errors
/// Returns an error for an invalid payload or MAC key.
pub fn response_tag(exporter: &[u8; 32], binding: &MacBinding, bytes: &[u8]) -> Result<[u8; 32], ProtocolError> {
    tag(RESPONSE_DOMAIN, exporter, binding, bytes, MAX_RESPONSE_BYTES)
}

/// Verify a response's session-bound tag.
///
/// # Errors
/// Returns an error for an invalid payload or mismatched tag.
pub fn verify_response_tag(
    exporter: &[u8; 32],
    binding: &MacBinding,
    bytes: &[u8],
    expected: &[u8; 32],
) -> Result<(), ProtocolError> {
    verify(RESPONSE_DOMAIN, exporter, binding, bytes, expected, MAX_RESPONSE_BYTES)
}

fn verify(
    domain: &[u8],
    exporter: &[u8; 32],
    binding: &MacBinding,
    bytes: &[u8],
    expected: &[u8; 32],
    max: usize,
) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > max {
        return Err(ProtocolError::Invalid);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(exporter).map_err(|_| ProtocolError::Authentication)?;
    mac.update(domain);
    mac.update(binding.hive.as_bytes());
    mac.update(binding.requester.as_bytes());
    mac.update(binding.signer.as_bytes());
    mac.update(&binding.stream.to_be_bytes());
    mac.update(&(u16::try_from(bytes.len()).map_err(|_| ProtocolError::Invalid)?).to_be_bytes());
    mac.update(bytes);
    mac.verify_slice(expected).map_err(|_| ProtocolError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::{KeygenReply, KeygenRequest, request_tag, verify_request_tag};
    use crate::{
        agent_sign_protocol::{MacBinding, ProtocolError},
        ids::{HiveId, NodeId},
        vault::AgentPolicy,
    };

    #[test]
    fn creation_messages_are_canonical_bounded_and_session_bound() -> Result<(), Box<dyn std::error::Error>> {
        let request = KeygenRequest {
            nonce: [1; 32],
            purpose: "build".to_owned(),
            note: "stage".to_owned(),
            policy: AgentPolicy::new(vec!["build.stage".to_owned()], None)?,
            expires_at: 100,
        };
        let bytes = request.encode()?;
        assert_eq!(KeygenRequest::decode(&bytes)?, request);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(KeygenRequest::decode(&trailing), Err(ProtocolError::Invalid));
        let binding = MacBinding {
            hive: HiveId::from_bytes([2; 32]),
            requester: NodeId::from_bytes([3; 32]),
            signer: NodeId::from_bytes([4; 32]),
            stream: 7,
        };
        let exporter = [5; 32];
        let tag = request_tag(&exporter, &binding, &bytes)?;
        verify_request_tag(&exporter, &binding, &bytes, &tag)?;
        assert_eq!(
            verify_request_tag(&exporter, &MacBinding { stream: 8, ..binding }, &bytes, &tag),
            Err(ProtocolError::Authentication),
        );
        let reply = KeygenReply::Created {
            nonce: request.nonce,
            public_key: [6; 32],
        };
        assert_eq!(KeygenReply::decode(&reply.encode()?)?, reply);
        Ok(())
    }
}
