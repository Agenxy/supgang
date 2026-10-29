//! Extra signed statement bound and signer-order fixtures.

use super::*;

pub(super) struct Context<'a> {
    pub release: &'a RoleGrant,
    pub carried: &'a SignedStatement,
    pub release_content_bytes: &'a [u8],
    pub assertion: &'a Assertion,
    pub release_key: &'a FileDeviceKey,
    pub presence_key: &'a FileDeviceKey,
}

pub(super) fn write(output: &Path, records: &mut Vec<serde_json::Value>, context: &Context<'_>) -> TestResult {
    let Context {
        release,
        carried,
        release_content_bytes,
        assertion,
        release_key,
        presence_key,
    } = context;
    let mut multi_role = bounds::three_signers(release)?;
    multi_role.threshold = 1;
    let mut multi_statement = (*carried).clone();
    multi_statement.signatures.clear();
    for (index, signer) in multi_role.signers.iter().take(2).enumerate() {
        let key = [9_u8, 10, 12]
            .into_iter()
            .map(|secret| FileDeviceKey::from_secret_bytes(&[secret; 32]))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|key| signer.key == SubjectKey::P256(key.public_key()))
            .ok_or_else(|| std::io::Error::other("missing signer key"))?;
        multi_statement.signatures.push(RoleSignature {
            signer: u8::try_from(index)?,
            bytes: key.sign_domain(RELEASE_DOMAIN, release_content_bytes)?.to_bytes(),
        });
    }
    let multi_keys = multi_role
        .signers
        .iter()
        .map(|signer| signer.key.clone())
        .collect::<Vec<_>>();
    multi_statement.verify_role_signatures(&multi_keys, 1)?;
    save(
        output,
        records,
        "multi-signer-role.cbor",
        &multi_role.encode()?,
        "accept: role with three valid enrolled signer proofs",
    )?;
    save(
        output,
        records,
        "multi-signer-statement.cbor",
        &multi_statement.encode()?,
        "accept: valid two-signature ordered envelope",
    )?;
    let mut unsorted = multi_statement.signatures.clone();
    unsorted.reverse();
    save(
        output,
        records,
        "refuse-unsorted-signers.cbor",
        &raw_statement_signatures(release_content_bytes, assertion, &unsorted)?,
        "reject: two valid signatures have descending signer indexes",
    )?;
    let mut duplicate = multi_statement.signatures.clone();
    let first_signature = *duplicate
        .first()
        .ok_or_else(|| std::io::Error::other("missing signer"))?;
    *duplicate
        .get_mut(1)
        .ok_or_else(|| std::io::Error::other("missing second signer"))? = first_signature;
    save(
        output,
        records,
        "refuse-duplicate-signers.cbor",
        &raw_statement_signatures(release_content_bytes, assertion, &duplicate)?,
        "reject: same valid signature repeats one signer index",
    )?;
    let mut long_window = release_content_bytes.to_vec();
    let old_expiry = (NOW + 24 * 60 * 60).to_be_bytes();
    let new_expiry = (NOW - 10 + 30 * 24 * 60 * 60 + 1).to_be_bytes();
    let old_wire = [&[0x1a][..], &old_expiry[4..]].concat();
    let new_wire = [&[0x1a][..], &new_expiry[4..]].concat();
    let expiry_offset = long_window
        .windows(old_wire.len())
        .position(|part| part == old_wire)
        .ok_or_else(|| std::io::Error::other("missing content expiry"))?;
    long_window
        .get_mut(expiry_offset..expiry_offset + old_wire.len())
        .ok_or_else(|| std::io::Error::other("missing expiry bytes"))?
        .copy_from_slice(&new_wire);
    let mut long_assertion = (*assertion).clone();
    let mut request_hash = Sha256::new();
    request_hash.update(REQUEST_DOMAIN);
    request_hash.update(&long_window);
    long_assertion.request_digest = request_hash.finalize().into();
    long_assertion.signature = presence_key
        .sign_domain(ACTION_DOMAIN, &long_assertion.payload()?)?
        .to_bytes();
    let long_signature = release_key.sign_domain(RELEASE_DOMAIN, &long_window)?.to_bytes();
    save(
        output,
        records,
        "refuse-statement-over-thirty-days.cbor",
        &raw_statement(&long_window, &long_assertion, &long_signature)?,
        "reject: canonical content has a thirty-day-plus-one-second window with valid signatures",
    )?;
    Ok(())
}
