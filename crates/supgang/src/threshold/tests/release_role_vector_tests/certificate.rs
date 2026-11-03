//! Pinned public certificates for the code-signing role.
//!
//! ECDSA certificate signatures can vary on reissuance. Reuse the reviewed DER
//! in the committed bundle so regeneration does not silently change every hash.

use std::{fs, path::Path};

use crate::threshold::step::role_grant::{RoleGrant, RolePolicy};

pub(super) fn cert_der(output: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let der = fs::read(output.join("code-signing-cert.der"))?;
    if der.is_empty() || der.len() >= 4096 {
        return Err(std::io::Error::other("missing normal-sized pinned certificate").into());
    }
    Ok(der)
}

pub(super) fn max_cert_der(output: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let role = RoleGrant::decode(&fs::read(output.join("edge-certificate-bytes-max.cbor"))?)?;
    let RolePolicy::CodeSigning { certificate, .. } = role.policy else {
        return Err(std::io::Error::other("missing pinned edge certificate").into());
    };
    if certificate.len() != 4096 {
        return Err(std::io::Error::other("wrong pinned edge certificate length").into());
    }
    Ok(certificate)
}
