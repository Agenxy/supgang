//! Refusals that require consumer context rather than a malformed CBOR item.

use std::path::Path;

use ed25519_dalek::Signer as _;
use minicbor::Encoder;

use super::{NOW, TestResult, bounds, release_policy, role_grant, root_step, save};
use crate::{
    authority::{SubjectCustody, device_node_id},
    device_key::{DeviceSigner as _, FileDeviceKey},
    ids::HiveId,
    threshold::{
        release_statement::SignedStatement,
        status::{DOMAIN as STATUS_DOMAIN, SignedStatus},
        step::{
            DOMAIN as STEP_DOMAIN,
            grant::Kind,
            role_grant::{ReleasePresence, RoleGrant, RolePolicy},
        },
    },
};

pub(super) struct Base<'a> {
    pub root: &'a ed25519_dalek::SigningKey,
    pub hive: HiveId,
    pub head: [u8; 32],
    pub release: &'a RoleGrant,
    pub unattended: &'a RoleGrant,
    pub status: &'a SignedStatus,
    pub statement: &'a SignedStatement,
}

pub(super) fn write(output: &Path, records: &mut Vec<serde_json::Value>, base: &Base<'_>) -> TestResult {
    let other_hive = role_grant(
        HiveId::from_bytes([99; 32]),
        20,
        (base.head, 4),
        (9, SubjectCustody::File),
        release_policy(ReleasePresence::CarriedDevice, 4),
        (NOW - 1000, NOW + 1000),
    )?;
    save(
        output,
        records,
        "refuse-cross-hive-grant.cbor",
        &other_hive.encode()?,
        "reject: grant hive differs from pinned hive",
    )?;

    let file_unattended = role_grant(
        base.hive,
        21,
        (base.head, 4),
        (10, SubjectCustody::File),
        release_policy(ReleasePresence::Unattended, 5),
        (NOW - 1000, NOW + 1000),
    )?;
    save(
        output,
        records,
        "refuse-unattended-file-signer.cbor",
        &bounds::raw_role(&file_unattended)?,
        "reject: unattended role with file custody",
    )?;

    let mut default_channel = base.unattended.clone();
    if let RolePolicy::Release { channels, .. } = &mut default_channel.policy {
        *channels = vec!["stable".into()];
    }
    save(
        output,
        records,
        "refuse-unattended-default-channel.cbor",
        &default_channel.encode()?,
        "reject: independently protected stable default channel intersects unattended role",
    )?;

    let threshold_three = bounds::three_signers(base.release)?;
    save(
        output,
        records,
        "refuse-fewer-than-threshold-grant.cbor",
        &threshold_three.encode()?,
        "reject: pair with release-statement.cbor, which has one signature and this grant requires three",
    )?;

    let mut wrong_consumer = base.statement.clone();
    wrong_consumer.content.consumer_id = "org.agenxy.Other".into();
    save(
        output,
        records,
        "refuse-wrong-consumer-statement.cbor",
        &wrong_consumer.encode()?,
        "reject: signed statement consumer differs from exact root grant consumer",
    )?;

    let mut stale_status = *base.status;
    stale_status.status.issued_at = NOW - 601;
    stale_status.status.expires_at = NOW + 1;
    let mut message = STATUS_DOMAIN.to_vec();
    message.extend_from_slice(&stale_status.status.encode()?);
    stale_status.signature = base.root.sign(&message).to_bytes();
    save(
        output,
        records,
        "refuse-stale-status.cbor",
        &stale_status.encode()?,
        "reject: valid root signature but status older than consumer 600-second maximum",
    )?;

    let duplicate = role_grant(
        base.hive,
        base.release.id[0],
        (base.head, 4),
        (9, SubjectCustody::File),
        release_policy(ReleasePresence::CarriedDevice, 4),
        (NOW - 1000, NOW + 1000),
    )?;
    let proposer = device_node_id(FileDeviceKey::from_secret_bytes(&[9; 32])?.public_key());
    let (duplicate_step, duplicate_signature) = root_step(base.root, base.head, 5, duplicate.encode()?, proposer)?;
    save(
        output,
        records,
        "refuse-reused-role-id-step.cbor",
        &duplicate_step.encode()?,
        "reject: pair with accepted four-step chain, role id is already spent",
    )?;
    save(
        output,
        records,
        "refuse-reused-role-id-step.sig",
        &duplicate_signature,
        "reject: valid root signature does not permit a spent role id",
    )?;

    let stale_issuer = role_grant(
        base.hive,
        23,
        ([42; 32], 4),
        (9, SubjectCustody::File),
        release_policy(ReleasePresence::CarriedDevice, 4),
        (NOW - 1000, NOW + 1000),
    )?;
    let mut raw = Encoder::new(Vec::new());
    raw.array(10)?
        .u8(1)?
        .bytes(base.hive.as_bytes())?
        .bytes(&base.head)?
        .u64(5)?
        .u64(0)?
        .u64(0)?
        .str("grant")?
        .bytes(&stale_issuer.encode()?)?
        .u64(NOW - 100)?
        .bytes(proposer.as_bytes())?;
    let raw = raw.into_writer();
    let mut message = STEP_DOMAIN.to_vec();
    message.extend_from_slice(&raw);
    let stale_signature = base.root.sign(&message).to_bytes();
    save(
        output,
        records,
        "refuse-stale-issuer-head-step.cbor",
        &raw,
        "reject: signed step predecessor differs from grant issuer head",
    )?;
    save(
        output,
        records,
        "refuse-stale-issuer-head-step.sig",
        &stale_signature,
        "reject: root signature cannot repair a stale issuer head",
    )?;

    // Both available grant kinds are deliberately in the bundle: consumers
    // refuse release as code-signing and code-signing as release by kind.
    assert_eq!(base.release.kind(), Kind::Release);
    Ok(())
}
