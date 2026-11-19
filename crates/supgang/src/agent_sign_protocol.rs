//! Bounded, canonical member signing messages independent of the QUIC runtime.

use hmac::{Hmac, KeyInit, Mac};
use minicbor::{Decoder, Encoder};
use sha2::Sha256;
use thiserror::Error;

use crate::{
    ids::{HiveId, NodeId},
    vault,
};

/// Maximum canonical request bytes before the session-bound authentication tag.
pub const MAX_REQUEST_BYTES: usize = 256;
/// Maximum canonical response bytes before the session-bound authentication tag.
pub const MAX_RESPONSE_BYTES: usize = 256;
/// A signing request may expire at most five minutes after it is admitted.
pub const MAX_REQUEST_LIFETIME_SECONDS: u64 = 5 * 60;
/// A received request has no implicit grace period after its stated expiry.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 2 * 60;

const REQUEST_DOMAIN: &[u8] = b"supgang/agent-sign/request-mac/v1\0";
const RESPONSE_DOMAIN: &[u8] = b"supgang/agent-sign/response-mac/v1\0";

/// A malformed, expired, or unauthenticated member signing message.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProtocolError {
    /// The message was malformed, noncanonical or outside its fixed bound.
    #[error("member signing message is invalid")]
    Invalid,
    /// The platform clock or request expiry does not permit this request.
    #[error("member signing request has expired or its clock is invalid")]
    Time,
    /// The session-bound authentication tag did not verify.
    #[error("member signing request authentication failed")]
    Authentication,
}

/// The exact effect a certified member requests from the signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignRequest {
    /// Globally unique caller-generated value, spent before signing.
    pub nonce: [u8; 32],
    /// Exact vault purpose name.
    pub purpose: String,
    /// Exact immutable context selected from that purpose's policy.
    pub context: String,
    /// SHA-256 of the caller's artifact or message.
    pub digest: [u8; 32],
    /// Absolute Unix-seconds deadline.
    pub expires_at: u64,
}

impl SignRequest {
    /// Validates this request against the signer's current clock.
    ///
    /// # Errors
    /// Refuses invalid names, contexts, expiry or clocks.
    pub fn validate(&self, now: u64) -> Result<(), ProtocolError> {
        if now == 0 || self.expires_at < now || self.expires_at > now.saturating_add(MAX_REQUEST_LIFETIME_SECONDS) {
            return Err(ProtocolError::Time);
        }
        if vault::validate_name(&self.purpose).is_err() || vault::validate_context(&self.context).is_err() {
            return Err(ProtocolError::Invalid);
        }
        Ok(())
    }

    /// Canonical CBOR encoding of the authenticated effect, excluding its tag.
    ///
    /// # Errors
    /// Refuses invalid fields or a message outside the fixed bound.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if vault::validate_name(&self.purpose).is_err() || vault::validate_context(&self.context).is_err() {
            return Err(ProtocolError::Invalid);
        }
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(6)
            .and_then(|e| e.u8(1))
            .and_then(|e| e.bytes(&self.nonce))
            .and_then(|e| e.str(&self.purpose))
            .and_then(|e| e.str(&self.context))
            .and_then(|e| e.bytes(&self.digest))
            .and_then(|e| e.u64(self.expires_at))
            .map_err(|_| ProtocolError::Invalid)?;
        let bytes = encoder.into_writer();
        if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
            return Err(ProtocolError::Invalid);
        }
        Ok(bytes)
    }

    /// Decodes and checks one canonical bounded request.
    ///
    /// # Errors
    /// Refuses malformed, noncanonical or oversized bytes.
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
        let nonce = fixed(&mut decoder)?;
        let purpose = decoder.str().map_err(|_| ProtocolError::Invalid)?.to_owned();
        let context = decoder.str().map_err(|_| ProtocolError::Invalid)?.to_owned();
        let digest = fixed(&mut decoder)?;
        let expires_at = decoder.u64().map_err(|_| ProtocolError::Invalid)?;
        let request = Self {
            nonce,
            purpose,
            context,
            digest,
            expires_at,
        };
        if request.encode()?.as_slice() != bytes {
            return Err(ProtocolError::Invalid);
        }
        Ok(request)
    }
}

/// One reply bound to the caller's nonce. Refusal carries no key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignReply {
    /// The exact context/digest has been signed under this public key.
    Signed {
        /// Request nonce that this reply answers.
        nonce: [u8; 32],
        /// Raw Ed25519 public key, pinned independently by the consumer.
        public_key: [u8; 32],
        /// Raw Ed25519 signature.
        signature: [u8; 64],
    },
    /// The signer refused without releasing a signature.
    Refused {
        /// Request nonce that this reply answers.
        nonce: [u8; 32],
    },
}

impl SignReply {
    /// Canonical CBOR encoding of a bounded reply, excluding its tag.
    ///
    /// # Errors
    /// Refuses an impossible encoded bound.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut encoder = Encoder::new(Vec::new());
        match self {
            Self::Signed {
                nonce,
                public_key,
                signature,
            } => {
                encoder
                    .array(5)
                    .and_then(|e| e.u8(1))
                    .and_then(|e| e.u8(1))
                    .and_then(|e| e.bytes(nonce))
                    .and_then(|e| e.bytes(public_key))
                    .and_then(|e| e.bytes(signature))
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

    /// Decodes and checks one canonical bounded reply.
    ///
    /// # Errors
    /// Refuses malformed, noncanonical or oversized bytes.
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
        let reply = match (count, kind) {
            (Some(5), 1) => Self::Signed {
                nonce: fixed(&mut decoder)?,
                public_key: fixed(&mut decoder)?,
                signature: decoder
                    .bytes()
                    .map_err(|_| ProtocolError::Invalid)?
                    .try_into()
                    .map_err(|_| ProtocolError::Invalid)?,
            },
            (Some(3), 2) => Self::Refused {
                nonce: fixed(&mut decoder)?,
            },
            _ => return Err(ProtocolError::Invalid),
        };
        if reply.encode()?.as_slice() != bytes {
            return Err(ProtocolError::Invalid);
        }
        Ok(reply)
    }

    /// The nonce identifying the request this reply answers.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        match self {
            Self::Signed { nonce, .. } | Self::Refused { nonce } => nonce,
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

/// Exact authenticated session and stream identifiers for one MAC direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacBinding {
    /// Stable hive identity.
    pub hive: HiveId,
    /// Certified member that opened the stream.
    pub requester: NodeId,
    /// Certified signer that receives the request.
    pub signer: NodeId,
    /// QUIC stream identifier within this exporter-bound session.
    pub stream: u64,
}

/// Computes a session-bound request tag from the connection's TLS exporter.
///
/// # Errors
/// Refuses an invalid HMAC key or unbounded payload.
pub fn request_tag(exporter: &[u8; 32], binding: &MacBinding, request: &[u8]) -> Result<[u8; 32], ProtocolError> {
    tag(REQUEST_DOMAIN, exporter, binding, request, MAX_REQUEST_BYTES)
}

/// Verifies a request tag in constant time.
///
/// # Errors
/// Refuses an invalid binding, payload or tag.
pub fn verify_request_tag(
    exporter: &[u8; 32],
    binding: &MacBinding,
    request: &[u8],
    expected: &[u8; 32],
) -> Result<(), ProtocolError> {
    verify_tag(REQUEST_DOMAIN, exporter, binding, request, expected, MAX_REQUEST_BYTES)
}

/// Computes a session-bound response tag from the same exporter.
///
/// # Errors
/// Refuses an invalid HMAC key or unbounded payload.
pub fn response_tag(exporter: &[u8; 32], binding: &MacBinding, reply: &[u8]) -> Result<[u8; 32], ProtocolError> {
    tag(RESPONSE_DOMAIN, exporter, binding, reply, MAX_RESPONSE_BYTES)
}

/// Verifies a response tag in constant time.
///
/// # Errors
/// Refuses an invalid binding, payload or tag.
pub fn verify_response_tag(
    exporter: &[u8; 32],
    binding: &MacBinding,
    reply: &[u8],
    expected: &[u8; 32],
) -> Result<(), ProtocolError> {
    verify_tag(RESPONSE_DOMAIN, exporter, binding, reply, expected, MAX_RESPONSE_BYTES)
}

fn mac(
    domain: &[u8],
    exporter: &[u8; 32],
    binding: &MacBinding,
    payload: &[u8],
) -> Result<Hmac<Sha256>, ProtocolError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(exporter).map_err(|_| ProtocolError::Authentication)?;
    mac.update(domain);
    mac.update(binding.hive.as_bytes());
    mac.update(binding.requester.as_bytes());
    mac.update(binding.signer.as_bytes());
    mac.update(&binding.stream.to_be_bytes());
    mac.update(&(u16::try_from(payload.len()).map_err(|_| ProtocolError::Invalid)?).to_be_bytes());
    mac.update(payload);
    Ok(mac)
}

fn tag(
    domain: &[u8],
    exporter: &[u8; 32],
    binding: &MacBinding,
    payload: &[u8],
    maximum: usize,
) -> Result<[u8; 32], ProtocolError> {
    if payload.is_empty() || payload.len() > maximum {
        return Err(ProtocolError::Invalid);
    }
    Ok(mac(domain, exporter, binding, payload)?.finalize().into_bytes().into())
}

fn verify_tag(
    domain: &[u8],
    exporter: &[u8; 32],
    binding: &MacBinding,
    payload: &[u8],
    expected: &[u8; 32],
    maximum: usize,
) -> Result<(), ProtocolError> {
    if payload.is_empty() || payload.len() > maximum {
        return Err(ProtocolError::Invalid);
    }
    mac(domain, exporter, binding, payload)?
        .verify_slice(expected)
        .map_err(|_| ProtocolError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::{
        MacBinding, ProtocolError, SignReply, SignRequest, request_tag, response_tag, verify_request_tag,
        verify_response_tag,
    };
    use crate::ids::{HiveId, NodeId};

    #[test]
    fn request_and_reply_are_canonical_and_bounded() -> Result<(), ProtocolError> {
        let request = SignRequest {
            nonce: [1; 32],
            purpose: "build.stage".to_owned(),
            context: "build.stage".to_owned(),
            digest: [2; 32],
            expires_at: 120,
        };
        request.validate(100)?;
        let encoded = request.encode()?;
        assert_eq!(SignRequest::decode(&encoded)?, request);
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(SignRequest::decode(&trailing), Err(ProtocolError::Invalid));
        assert_eq!(request.validate(121), Err(ProtocolError::Time));
        assert_eq!(request.validate(0), Err(ProtocolError::Time));
        let reply = SignReply::Signed {
            nonce: request.nonce,
            public_key: [3; 32],
            signature: [4; 64],
        };
        let encoded = reply.encode()?;
        assert_eq!(SignReply::decode(&encoded)?, reply);
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(SignReply::decode(&trailing), Err(ProtocolError::Invalid));
        Ok(())
    }

    #[test]
    fn mac_binds_hive_identities_stream_payload_and_direction() -> Result<(), ProtocolError> {
        let exporter = [5; 32];
        let binding = MacBinding {
            hive: HiveId::from_bytes([1; 32]),
            requester: NodeId::from_bytes([2; 32]),
            signer: NodeId::from_bytes([3; 32]),
            stream: 4,
        };
        let bytes = b"canonical request";
        let tag = request_tag(&exporter, &binding, bytes)?;
        verify_request_tag(&exporter, &binding, bytes, &tag)?;
        assert_eq!(
            verify_response_tag(&exporter, &binding, bytes, &tag),
            Err(ProtocolError::Authentication)
        );
        assert_eq!(
            verify_request_tag(&[6; 32], &binding, bytes, &tag),
            Err(ProtocolError::Authentication)
        );
        assert_eq!(
            verify_request_tag(&exporter, &MacBinding { stream: 5, ..binding }, bytes, &tag),
            Err(ProtocolError::Authentication)
        );
        assert_eq!(
            verify_request_tag(
                &exporter,
                &MacBinding {
                    requester: NodeId::from_bytes([9; 32]),
                    ..binding
                },
                bytes,
                &tag
            ),
            Err(ProtocolError::Authentication)
        );
        assert_eq!(
            verify_request_tag(&exporter, &binding, b"changed", &tag),
            Err(ProtocolError::Authentication)
        );
        let reply_tag = response_tag(&exporter, &binding, bytes)?;
        verify_response_tag(&exporter, &binding, bytes, &reply_tag)?;
        Ok(())
    }
}
