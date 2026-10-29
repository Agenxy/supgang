//! Isolated malformed grant and certificate fixtures.

use super::*;

pub(super) fn write(
    output: &Path,
    records: &mut Vec<serde_json::Value>,
    release: &RoleGrant,
    release_bytes: &[u8],
    code_bytes: &[u8],
    certificate: &[u8],
    release_key: &FileDeviceKey,
) -> TestResult {
    let mut bad_grant = release_bytes.to_vec();
    let proof = release
        .signers
        .first()
        .ok_or_else(|| std::io::Error::other("missing role signer"))?
        .possession;
    let offset = bad_grant
        .windows(proof.len())
        .position(|part| part == proof)
        .ok_or_else(|| std::io::Error::other("missing possession bytes"))?;
    *bad_grant
        .get_mut(offset)
        .ok_or_else(|| std::io::Error::other("missing possession byte"))? ^= 1;
    save(
        output,
        records,
        "release-grant-bad-possession.cbor",
        &bad_grant,
        "reject: signer possession proof changed",
    )?;
    let mut bad_class = release_bytes.to_vec();
    let class = b"role-key";
    let offset = bad_class
        .windows(class.len())
        .position(|part| part == class)
        .ok_or_else(|| std::io::Error::other("missing signer class"))?;
    *bad_class
        .get_mut(offset)
        .ok_or_else(|| std::io::Error::other("missing class byte"))? = b'R';
    let mut wrong_class_message = release
        .signers
        .first()
        .ok_or_else(|| std::io::Error::other("missing role signer"))?
        .possession_message(release)?;
    let class_offset = wrong_class_message
        .windows(class.len())
        .position(|part| part == class)
        .ok_or_else(|| std::io::Error::other("missing signed class"))?;
    *wrong_class_message
        .get_mut(class_offset)
        .ok_or_else(|| std::io::Error::other("missing class byte"))? = b'R';
    let wrong_class_proof = release_key
        .sign_domain(b"supgang/role-possession/v1\0", &wrong_class_message)?
        .to_bytes();
    let proof_offset = bad_class
        .windows(proof.len())
        .position(|part| part == proof)
        .ok_or_else(|| std::io::Error::other("missing class proof"))?;
    bad_class
        .get_mut(proof_offset..proof_offset + proof.len())
        .ok_or_else(|| std::io::Error::other("missing class proof bytes"))?
        .copy_from_slice(&wrong_class_proof);
    save(
        output,
        records,
        "release-grant-wrong-class.cbor",
        &bad_class,
        "reject: signer class not allowed for release kind",
    )?;
    let mut bad_cert = code_bytes.to_vec();
    let offset = bad_cert
        .windows(certificate.len())
        .position(|part| part == certificate)
        .ok_or_else(|| std::io::Error::other("missing cert bytes"))?;
    *bad_cert
        .get_mut(offset)
        .ok_or_else(|| std::io::Error::other("missing cert byte"))? ^= 1;
    save(
        output,
        records,
        "code-signing-grant-bad-cert.cbor",
        &bad_cert,
        "reject: malformed role certificate",
    )?;

    Ok(())
}
