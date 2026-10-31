//! Versioned canonical CBOR restore records, stored beside the identity.

use super::custody::{CustodyError, CustodyKind};
use minicbor::{Decoder, Encoder};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// Maximum provider payload, independent of any vendor's current blob size.
pub const MAX_SEALED_BYTES: usize = 4096;
const MAX_RECORD_BYTES: usize = MAX_SEALED_BYTES + 16;
const FILE_NAME: &str = "device-custody.cbor";

/// An opaque restore record. For `File`, bytes are an extractable scalar.
/// Debug output never includes the bytes; dropping the record clears them.
#[derive(Clone, Eq, PartialEq)]
pub struct SealedKey {
    /// Provider that alone may interpret these bytes.
    pub kind: CustodyKind,
    /// Wrapped key material, or an explicitly chosen file scalar; at most 4096 bytes.
    pub bytes: Vec<u8>,
}

impl core::fmt::Debug for SealedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealedKey")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Drop for SealedKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl SealedKey {
    /// Checks provider identity before interpreting the payload.
    ///
    /// # Errors
    /// Refuses a different kind, empty bytes or bytes over the portable bound.
    pub fn require_kind(&self, kind: CustodyKind) -> Result<(), CustodyError> {
        if self.kind != kind {
            return Err(CustodyError::KindMismatch);
        }
        if self.bytes.is_empty() || self.bytes.len() > MAX_SEALED_BYTES {
            return Err(CustodyError::InvalidSealedKey);
        }
        Ok(())
    }

    /// Canonical CBOR `[1, kind, bytes]`; kind codes 0..=3 follow capability order.
    /// The caller must clear the returned buffer after writing it.
    ///
    /// # Errors
    /// Refuses empty or oversized bytes and encoding failures.
    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        self.require_kind(self.kind)?;
        let kind = match self.kind {
            CustodyKind::SecureEnclave => 0,
            CustodyKind::Tpm2 => 1,
            CustodyKind::SecurityKey => 2,
            CustodyKind::File => 3,
        };
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .and_then(|e| e.u8(1))
            .and_then(|e| e.u8(kind))
            .and_then(|e| e.bytes(&self.bytes))
            .map_err(|_| CustodyError::InvalidSealedKey)?;
        Ok(e.into_writer())
    }

    /// Decodes only the exact canonical record, with no trailing bytes.
    ///
    /// # Errors
    /// Refuses unsupported versions or kinds, truncation, noncanonical CBOR and bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, CustodyError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(CustodyError::InvalidSealedKey);
        }
        let parse = || -> Result<Self, minicbor::decode::Error> {
            let mut d = Decoder::new(bytes);
            if d.array()? != Some(3) || d.u8()? != 1 {
                return Err(minicbor::decode::Error::message("sealed key version"));
            }
            let kind = match d.u8()? {
                0 => CustodyKind::SecureEnclave,
                1 => CustodyKind::Tpm2,
                2 => CustodyKind::SecurityKey,
                3 => CustodyKind::File,
                _ => return Err(minicbor::decode::Error::message("sealed key kind")),
            };
            Ok(Self {
                kind,
                bytes: d.bytes()?.to_vec(),
            })
        };
        let key = parse().map_err(|_| CustodyError::InvalidSealedKey)?;
        if Zeroizing::new(key.encode()?).as_slice() != bytes {
            return Err(CustodyError::InvalidSealedKey);
        }
        Ok(key)
    }

    /// Creates `device-custody.cbor` beside the identity, mode 0600, without replacement.
    /// The caller chooses and enrols the key; storing it does not migrate a live identity.
    ///
    /// # Errors
    /// Refuses unsafe directories, existing paths, invalid records and filesystem failures.
    pub fn write_new(&self, identity_directory: &Path) -> Result<(), CustodyError> {
        let directory = crate::storage::validate_directory(identity_directory)?;
        crate::artifact::write_new(
            directory.join(FILE_NAME),
            &Zeroizing::new(self.encode()?),
            MAX_RECORD_BYTES,
        )?;
        Ok(())
    }

    /// Reads the bounded, owner-only restore record beside the identity.
    ///
    /// # Errors
    /// Refuses unsafe directories or files, invalid CBOR and filesystem failures.
    pub fn read(identity_directory: &Path) -> Result<Self, CustodyError> {
        let directory = crate::storage::validate_directory(identity_directory)?;
        Self::decode(&Zeroizing::new(crate::artifact::read(
            directory.join(FILE_NAME),
            MAX_RECORD_BYTES,
        )?))
    }
}
