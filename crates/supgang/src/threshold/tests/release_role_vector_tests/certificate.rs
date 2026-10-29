//! Pinned public certificate fixture for the code-signing role.

use std::{fs, path::Path};

use p256::pkcs8::EncodePrivateKey as _;

pub(super) fn cert_der(output: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = output.join("code-signing-cert.der");
    if path.exists() {
        let existing = fs::read(&path)?;
        if existing.len() == 4096 {
            return Ok(existing);
        }
    }
    let secret = p256::SecretKey::from_slice(&[9; 32])?;
    let private_der = secret.to_pkcs8_der()?;
    let pair = rcgen::KeyPair::try_from(private_der.as_bytes())?;
    let mut params = rcgen::CertificateParams::default();
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2026, 12, 31);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "org.agenxy.Remap code signing test");
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
    let mut padding = 3700_usize;
    for _ in 0..32 {
        params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 55_555, 1],
            vec![0; padding],
        )];
        let der = params.self_signed(&pair)?.der().to_vec();
        if der.len() == 4096 {
            fs::write(path, &der)?;
            return Ok(der);
        }
        let delta = 4096_isize - isize::try_from(der.len())?;
        padding = padding
            .checked_add_signed(delta)
            .filter(|value| *value <= 4096)
            .ok_or_else(|| std::io::Error::other("cannot size test certificate"))?;
    }
    Err(std::io::Error::other("could not generate a 4096-byte test certificate").into())
}
