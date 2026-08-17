//! Fixed-size, non-secret identifiers used by the protocol.

use core::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};
use thiserror::Error;

const ID_BYTES: usize = 32;
const ID_HEX_CHARS: usize = ID_BYTES * 2;

/// An error returned when a textual identifier is malformed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdError {
    /// The identifier did not contain exactly 64 hexadecimal characters.
    #[error("identifier must contain exactly 64 hexadecimal characters")]
    WrongLength,
    /// The identifier contained a non-hexadecimal character.
    #[error("identifier contains a non-hexadecimal character")]
    InvalidHex,
}

macro_rules! define_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; ID_BYTES]);

        impl $name {
            /// Builds an identifier from its canonical 32-byte representation.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; ID_BYTES]) -> Self {
                Self(bytes)
            }

            /// Returns the canonical 32-byte representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; ID_BYTES] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}({self})", stringify!($name))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&hex::encode(self.0))
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                if value.len() != ID_HEX_CHARS {
                    return Err(IdError::WrongLength);
                }
                let mut bytes = [0_u8; ID_BYTES];
                hex::decode_to_slice(value, &mut bytes).map_err(|_| IdError::InvalidHex)?;
                Ok(Self(bytes))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(D::Error::custom)
            }
        }
    };
}

define_id!(HiveId, "The stable identifier of one private Supgang hive.");
define_id!(NodeId, "The stable identifier derived from a device verification key.");
define_id!(
    TransportKeyId,
    "The identifier of the short-lived key or certificate authenticating a transport endpoint."
);

impl HiveId {
    /// Generates a new hive identifier from the operating system's cryptographic random source.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating system cannot provide secure random bytes.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0_u8; ID_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Derives a self-certifying hive identifier from its root verification key.
    #[must_use]
    pub fn from_root_verifying_key(key: &[u8; ID_BYTES]) -> Self {
        Self(domain_hash(b"supgang/hive-id/v1\0", key))
    }
}

impl NodeId {
    /// Derives a node identifier from an Ed25519 verification key.
    #[must_use]
    pub fn from_verifying_key(key: &[u8; ID_BYTES]) -> Self {
        Self(domain_hash(b"supgang/node-id/v1\0", key))
    }
}

impl TransportKeyId {
    /// Derives a transport key identifier from a public key or certificate.
    #[must_use]
    pub fn from_public_material(material: &[u8]) -> Self {
        Self(domain_hash(b"supgang/transport-key-id/v1\0", material))
    }
}

fn domain_hash(domain: &[u8], material: &[u8]) -> [u8; ID_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(material);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{HiveId, IdError, NodeId};

    #[test]
    fn identifiers_round_trip_as_lowercase_hex() -> Result<(), Box<dyn std::error::Error>> {
        let id = HiveId::from_bytes([0xab; 32]);
        let text = id.to_string();
        assert_eq!(text.len(), 64);
        assert_eq!(text.parse::<HiveId>()?, id);
        assert_eq!(serde_json::from_str::<HiveId>(&serde_json::to_string(&id)?)?, id);
        Ok(())
    }

    #[test]
    fn identifiers_reject_wrong_length_and_invalid_hex() {
        assert_eq!("ab".parse::<NodeId>(), Err(IdError::WrongLength));
        assert_eq!("z".repeat(64).parse::<NodeId>(), Err(IdError::InvalidHex));
    }
}
