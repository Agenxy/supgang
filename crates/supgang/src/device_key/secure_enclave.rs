//! `CryptoKit`'s sealed-blob Secure Enclave provider; no keychain or entitlement.
//!
//! The sibling `supgang-secure-enclave` executable speaks `supgang/custody/v1`.
//! Sealed blobs, public keys, digests and raw signatures are lowercase hex on
//! stdin/stdout, never arguments. Rust normalizes signatures to low-s.

use super::{
    Custody, DeviceKeyError, DevicePublicKey, DeviceSignature, DeviceSigner,
    custody::{Availability, CustodyError, CustodyKind, CustodyProvider, PresencePolicy, SealedKey, UnavailableReason},
    domain_digest, helper, signature,
};
use std::time::Duration;
use zeroize::Zeroizing;

/// The owner enrolled this key as hardware-held. That label is not an
/// attestation: a device cannot prove to anyone else where its key lives.
#[derive(Clone, Copy, Debug)]
pub struct SecureEnclaveProvider;

impl CustodyProvider for SecureEnclaveProvider {
    fn kind(&self) -> CustodyKind {
        CustodyKind::SecureEnclave
    }
    fn availability(&self) -> Availability {
        match helper::invoke("probe", Duration::from_secs(2)) {
            Ok(response) if response.as_str() == "probe supgang-secure-enclave ready" => Availability::Ready,
            Ok(response) if response.as_str() == "probe supgang-secure-enclave no-hardware" => {
                Availability::Unavailable(UnavailableReason::NoHardware)
            }
            Ok(_) => Availability::Unavailable(UnavailableReason::HelperProtocol),
            Err(reason) => Availability::Unavailable(reason),
        }
    }
    fn generate(&self, presence: PresencePolicy) -> Result<Box<dyn DeviceSigner>, CustodyError> {
        let flag = match presence {
            PresencePolicy::Required => "--presence",
            PresencePolicy::Unattended => "--no-presence",
        };
        let response = helper::invoke(&format!("generate {flag}"), Duration::from_mins(1))?;
        let fields: Vec<_> = response.split(' ').collect();
        let ["generate", blob, public] = fields.as_slice() else {
            return Err(UnavailableReason::HelperProtocol.into());
        };
        let sealed = SealedKey {
            kind: self.kind(),
            bytes: decode_hex(blob)?,
        };
        sealed.require_kind(self.kind())?;
        let public = DevicePublicKey::from_bytes(&decode_hex(public)?)?;
        Ok(Box::new(EnclaveSigner { sealed, public }))
    }
    fn load(&self, sealed: &SealedKey) -> Result<Box<dyn DeviceSigner>, CustodyError> {
        sealed.require_kind(self.kind())?;
        let request = Zeroizing::new(format!("public --sealed {}", hex::encode(&sealed.bytes)));
        let response = helper::invoke(&request, Duration::from_secs(5))?;
        let public = response
            .strip_prefix("public ")
            .ok_or(UnavailableReason::HelperProtocol)?;
        let public = DevicePublicKey::from_bytes(&decode_hex(public)?)?;
        Ok(Box::new(EnclaveSigner {
            sealed: sealed.clone(),
            public,
        }))
    }
}

struct EnclaveSigner {
    sealed: SealedKey,
    public: DevicePublicKey,
}

impl DeviceSigner for EnclaveSigner {
    fn sealed_key(&self) -> Result<SealedKey, CustodyError> {
        Ok(self.sealed.clone())
    }
    fn public_key(&self) -> DevicePublicKey {
        self.public
    }
    fn custody(&self) -> Custody {
        Custody::Hardware
    }
    fn sign_domain(&self, domain: &'static [u8], message: &[u8]) -> Result<DeviceSignature, DeviceKeyError> {
        let digest = domain_digest(domain, message);
        let request = Zeroizing::new(format!(
            "sign --sealed {} {}",
            hex::encode(&self.sealed.bytes),
            hex::encode(digest)
        ));
        let response = helper::invoke(&request, Duration::from_mins(1)).map_err(DeviceKeyError::CustodyRefused)?;
        let raw = response
            .strip_prefix("sign ")
            .ok_or(DeviceKeyError::CustodyRefused(UnavailableReason::HelperProtocol))?;
        let bytes = decode_hex(raw).map_err(DeviceKeyError::CustodyRefused)?;
        let signature = signature::from_raw(&bytes)?;
        self.public.verify_domain(domain, message, &signature)?;
        Ok(signature)
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, UnavailableReason> {
    if !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(UnavailableReason::HelperProtocol);
    }
    hex::decode(value).map_err(|_| UnavailableReason::HelperProtocol)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(presence: PresencePolicy) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(SecureEnclaveProvider.availability(), Availability::Ready);
        let key = SecureEnclaveProvider.generate(presence)?;
        assert_eq!(key.custody(), Custody::Hardware);
        let sealed = key.sealed_key()?;
        let restored = SecureEnclaveProvider.load(&SealedKey::decode(&sealed.encode()?)?)?;
        assert_eq!(key.public_key(), restored.public_key());
        let domain = b"supgang/custody-test/v1\0";
        let signature = restored.sign_domain(domain, b"restored")?;
        key.public_key().verify_domain(domain, b"restored", &signature)?;
        let truncated = SealedKey {
            kind: CustodyKind::SecureEnclave,
            bytes: sealed.bytes.get(..16).ok_or(CustodyError::InvalidSealedKey)?.to_vec(),
        };
        assert!(SecureEnclaveProvider.load(&truncated).is_err());
        Ok(())
    }

    #[test]
    // Requires a built helper next to this test executable and a real Secure Enclave.
    #[ignore = "requires the sibling Swift helper and real Secure Enclave"]
    fn real_helper_restores_and_signs() -> Result<(), Box<dyn std::error::Error>> {
        round_trip(PresencePolicy::Unattended)
    }

    #[test]
    // Requires the helper built and the owner present to approve Touch ID.
    #[ignore = "requires the sibling Swift helper, Secure Enclave and owner present"]
    fn real_helper_requires_presence() -> Result<(), Box<dyn std::error::Error>> {
        round_trip(PresencePolicy::Required)
    }
}
