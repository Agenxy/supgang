//! Pinned public certificate fixture for the code-signing role.

use p256::pkcs8::EncodePrivateKey as _;

fn parameters() -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::default();
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2026, 12, 31);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "org.agenxy.Remap code signing 06060606");
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
    params
}

fn pair() -> Result<rcgen::KeyPair, Box<dyn std::error::Error>> {
    let secret = p256::SecretKey::from_slice(&[14; 32])?;
    let private_der = secret.to_pkcs8_der()?;
    Ok(rcgen::KeyPair::try_from(private_der.as_bytes())?)
}

pub(super) fn cert_der() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(parameters().self_signed(&pair()?)?.der().to_vec())
}

pub(super) fn max_cert_der() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = pair()?;
    let mut params = parameters();
    let mut padding = 3700_usize;
    for _ in 0..32 {
        params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 55_555, 1],
            vec![0; padding],
        )];
        let der = params.clone().self_signed(&key)?.der().to_vec();
        if der.len() == 4096 {
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
