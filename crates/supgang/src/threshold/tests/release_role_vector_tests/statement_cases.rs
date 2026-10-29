//! Independent one-fault statement refusal fixtures.

use super::*;

pub(super) fn write(
    output: &Path,
    records: &mut Vec<serde_json::Value>,
    carried: &SignedStatement,
    unattended_statement: &SignedStatement,
    assertion: &Assertion,
    owner_expiry: &Grant,
    release_key: &FileDeviceKey,
    presence_key: &FileDeviceKey,
) -> TestResult {
    let mut bad_signature = carried.clone();
    bad_signature
        .signatures
        .first_mut()
        .ok_or_else(|| std::io::Error::other("missing signature"))?
        .bytes[0] ^= 1;
    save(
        output,
        records,
        "release-statement-bad-signature.cbor",
        &bad_signature.encode()?,
        "reject: role signature bit changed",
    )?;
    let mut wrong_assertion = carried.clone();
    let assertion_mut = wrong_assertion
        .assertion
        .as_mut()
        .ok_or_else(|| std::io::Error::other("missing assertion"))?;
    assertion_mut.request_digest[0] ^= 1;
    assertion_mut.signature = presence_key
        .sign_domain(ACTION_DOMAIN, &assertion_mut.payload()?)?
        .to_bytes();
    save(
        output,
        records,
        "release-statement-wrong-assertion.cbor",
        &wrong_assertion.encode()?,
        "reject: valid presence signature bound to a different request digest",
    )?;
    let mut expired = carried.clone();
    expired.content.expires_at = NOW - 1;
    resign_carried(&mut expired, release_key, presence_key)?;
    save(
        output,
        records,
        "release-statement-expired.cbor",
        &expired.encode()?,
        "reject: statement expired before verification time",
    )?;
    let mut wrong_channel = carried.clone();
    wrong_channel.content.channel = "stable".into();
    resign_carried(&mut wrong_channel, release_key, presence_key)?;
    save(
        output,
        records,
        "release-statement-wrong-channel.cbor",
        &wrong_channel.encode()?,
        "reject: channel outside root grant",
    )?;
    let mut below_minimum = carried.clone();
    below_minimum
        .content
        .version
        .pre
        .as_mut()
        .ok_or_else(|| std::io::Error::other("missing prerelease"))?
        .number = 3;
    resign_carried(&mut below_minimum, release_key, presence_key)?;
    save(
        output,
        records,
        "refuse-version-below-minimum.cbor",
        &below_minimum.encode()?,
        "reject: signed preview.3 is below granted preview.4 minimum",
    )?;
    let mut mixed_artifact = carried.clone();
    mixed_artifact
        .content
        .artifacts
        .first_mut()
        .ok_or_else(|| std::io::Error::other("missing artifact"))?
        .sha256 = [9; 32];
    resign_carried(&mut mixed_artifact, release_key, presence_key)?;
    save(
        output,
        records,
        "refuse-mixed-artifact-statement.cbor",
        &mixed_artifact.encode()?,
        "reject: valid statement names a digest different from artifact.bin",
    )?;
    let mut missing_assertion = carried.clone();
    missing_assertion.assertion = None;
    save(
        output,
        records,
        "refuse-carried-missing-assertion.cbor",
        &missing_assertion.encode()?,
        "reject: carried-device statement omits owner assertion",
    )?;
    let mut excess_assertion = unattended_statement.clone();
    let unattended_request = excess_assertion.content.encode()?;
    let unattended_challenge = Challenge {
        target: assertion.target,
        consumer: assertion.consumer.clone(),
        operation: assertion.operation.clone(),
        grant_id: assertion.grant_id,
        request: unattended_request.clone(),
        nonce: assertion.nonce,
        expires_at: NOW + 90,
    };
    let mut request_hash = Sha256::new();
    request_hash.update(REQUEST_DOMAIN);
    request_hash.update(&unattended_request);
    let mut bound_assertion = assertion.clone();
    bound_assertion.request_digest = request_hash.finalize().into();
    bound_assertion.challenge_digest = unattended_challenge.digest()?;
    bound_assertion.signature = presence_key
        .sign_domain(ACTION_DOMAIN, &bound_assertion.payload()?)?
        .to_bytes();
    excess_assertion.assertion = Some(bound_assertion);
    save(
        output,
        records,
        "refuse-unattended-extra-request.bin",
        &unattended_request,
        "accept: request bytes bound to the otherwise valid forbidden assertion",
    )?;
    save(
        output,
        records,
        "refuse-unattended-extra-challenge.cbor",
        &unattended_challenge.encode()?,
        "accept: challenge bound to the unattended statement content",
    )?;
    save(
        output,
        records,
        "refuse-unattended-with-assertion.cbor",
        &excess_assertion.encode()?,
        "reject: unattended statement carries an owner assertion",
    )?;
    let mut before_statement = carried.clone();
    before_statement
        .assertion
        .as_mut()
        .ok_or_else(|| std::io::Error::other("missing assertion"))?
        .issued_at = before_statement.content.issued_at - 1;
    resign_carried(&mut before_statement, release_key, presence_key)?;
    save(
        output,
        records,
        "refuse-assertion-before-statement.cbor",
        &before_statement.encode()?,
        "reject: valid signature but assertion precedes statement issuance",
    )?;
    let mut at_statement_expiry = carried.clone();
    at_statement_expiry.content.expires_at = VERIFY_AT + 30;
    let expiry_request = at_statement_expiry.content.encode()?;
    let expiry_challenge = Challenge {
        target: assertion.target,
        consumer: assertion.consumer.clone(),
        operation: assertion.operation.clone(),
        grant_id: owner_expiry.id,
        request: expiry_request.clone(),
        nonce: assertion.nonce,
        expires_at: VERIFY_AT + 90,
    };
    let assertion_at_expiry = at_statement_expiry
        .assertion
        .as_mut()
        .ok_or_else(|| std::io::Error::other("missing assertion"))?;
    assertion_at_expiry.grant_id = owner_expiry.id;
    assertion_at_expiry.challenge_digest = expiry_challenge.digest()?;
    assertion_at_expiry.issued_at = VERIFY_AT + 30;
    assertion_at_expiry.expires_at = VERIFY_AT + 60;
    resign_carried(&mut at_statement_expiry, release_key, presence_key)?;
    at_statement_expiry
        .assertion
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing assertion"))?
        .verify_binding(
            owner_expiry,
            &expiry_challenge,
            &expiry_request,
            expiry_challenge.target,
            VERIFY_AT + 30,
        )?;
    save(
        output,
        records,
        "refuse-assertion-at-statement-expiry-request.bin",
        &expiry_request,
        "accept: canonical request for expiry-bound assertion",
    )?;
    save(
        output,
        records,
        "refuse-assertion-at-statement-expiry-challenge.cbor",
        &expiry_challenge.encode()?,
        "accept: owner challenge valid at manifest verification time",
    )?;
    save(
        output,
        records,
        "refuse-assertion-at-statement-expiry.cbor",
        &at_statement_expiry.encode()?,
        "reject: at manifest verification time, valid owner assertion equals statement expiry",
    )?;
    Ok(())
}
