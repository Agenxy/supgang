//! Extra signed statement bound and signer-order fixtures.

use super::*;

pub(super) struct Context<'a> {
    pub carried: &'a SignedStatement,
    pub release_content_bytes: &'a [u8],
    pub assertion: &'a Assertion,
    pub multi_role: &'a RoleGrant,
    pub release_key: &'a FileDeviceKey,
    pub presence_key: &'a FileDeviceKey,
}

pub(super) fn write(output: &Path, records: &mut Vec<serde_json::Value>, context: &Context<'_>) -> TestResult {
    let Context {
        carried,
        release_content_bytes,
        assertion,
        multi_role,
        release_key,
        presence_key,
    } = context;
    let multi_content = content(carried.content.hive, multi_role.id, 4);
    let multi_request = multi_content.encode()?;
    let multi_challenge = Challenge {
        target: assertion.target,
        consumer: assertion.consumer.clone(),
        operation: assertion.operation.clone(),
        grant_id: assertion.grant_id,
        request: multi_request.clone(),
        nonce: assertion.nonce,
        expires_at: NOW + 90,
    };
    let mut request_hash = Sha256::new();
    request_hash.update(REQUEST_DOMAIN);
    request_hash.update(&multi_request);
    let mut multi_assertion = (*assertion).clone();
    multi_assertion.request_digest = request_hash.finalize().into();
    multi_assertion.challenge_digest = multi_challenge.digest()?;
    multi_assertion.signature = presence_key
        .sign_domain(ACTION_DOMAIN, &multi_assertion.payload()?)?
        .to_bytes();
    let mut multi_statement = SignedStatement {
        content: multi_content,
        assertion: Some(multi_assertion.clone()),
        signatures: Vec::new(),
    };
    for (index, signer) in multi_role.signers.iter().enumerate() {
        let key = [9_u8, 10, 12]
            .into_iter()
            .map(|secret| FileDeviceKey::from_secret_bytes(&[secret; 32]))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|key| signer.key == SubjectKey::P256(key.public_key()))
            .ok_or_else(|| std::io::Error::other("missing signer key"))?;
        multi_statement.signatures.push(RoleSignature {
            signer: u8::try_from(index)?,
            bytes: key.sign_domain(RELEASE_DOMAIN, &multi_request)?.to_bytes(),
        });
    }
    let multi_keys = multi_role
        .signers
        .iter()
        .map(|signer| signer.key.clone())
        .collect::<Vec<_>>();
    multi_statement.verify_role_signatures(&multi_keys, 3)?;
    multi_statement.check_role_policy(multi_role, &["stable"], NOW, None)?;
    save(
        output,
        records,
        "multi-signer-request.bin",
        &multi_request,
        "accept: canonical content bytes bound to multi-signer assertion",
    )?;
    save(
        output,
        records,
        "multi-signer-challenge.cbor",
        &multi_challenge.encode()?,
        "accept: owner challenge for threshold-three release statement",
    )?;
    save(
        output,
        records,
        "multi-signer-statement.cbor",
        &multi_statement.encode()?,
        "accept: valid three-signature ordered envelope at active role",
    )?;
    let mut fewer = multi_statement.clone();
    fewer.signatures.truncate(1);
    save(
        output,
        records,
        "refuse-fewer-than-threshold-statement.cbor",
        &fewer.encode()?,
        "reject: pair with multi-signer-role.cbor; one valid signature is below threshold three",
    )?;
    let mut unsorted = multi_statement.signatures.clone();
    unsorted.reverse();
    save(
        output,
        records,
        "refuse-unsorted-signers.cbor",
        &raw_statement_signatures(&multi_request, &multi_assertion, &unsorted)?,
        "reject: three valid signatures have descending signer indexes",
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
        &raw_statement_signatures(&multi_request, &multi_assertion, &duplicate)?,
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
