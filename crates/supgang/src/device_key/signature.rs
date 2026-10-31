//! Provider signature conversion, available on every platform without hardware.
//!
//! The Swift helper sends hexadecimal raw `r || s`. Low-s normalization happens
//! here in Rust, before `DeviceSignature::from_bytes`, never in the helper.

use super::{DeviceKeyError, DeviceSignature};
use p256::ecdsa::Signature;

/// Normalizes a provider's fixed-width 64-byte raw signature.
///
/// # Errors
/// Refuses wrong lengths and zero or out-of-range integers.
pub fn from_raw(bytes: &[u8]) -> Result<DeviceSignature, DeviceKeyError> {
    let signature = Signature::from_slice(bytes).map_err(|_| DeviceKeyError::InvalidSignature)?;
    normalized(signature)
}

/// Converts strict ASN.1 DER integers, including short integers, to padded raw form.
/// This is a portable conversion utility; the enclave wire protocol uses raw form.
///
/// # Errors
/// Refuses malformed, noncanonical or out-of-range DER signatures.
pub fn from_der(bytes: &[u8]) -> Result<DeviceSignature, DeviceKeyError> {
    let signature = Signature::from_der(bytes).map_err(|_| DeviceKeyError::InvalidSignature)?;
    normalized(signature)
}

fn normalized(signature: Signature) -> Result<DeviceSignature, DeviceKeyError> {
    DeviceSignature::from_bytes(&signature.normalize_s().to_bytes())
}
