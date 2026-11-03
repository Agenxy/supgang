//! Additional root-issued roles used to isolate consumer refusal cases.

use super::*;

pub(super) struct Issued {
    pub multi_role: RoleGrant,
    pub owner_expiry: Grant,
    pub head: [u8; 32],
}

pub(super) fn write(
    output: &Path,
    records: &mut Vec<serde_json::Value>,
    root: &ed25519_dalek::SigningKey,
    hive: HiveId,
    owner_head: [u8; 32],
    target: NodeId,
    proposer: NodeId,
) -> Result<Issued, Box<dyn std::error::Error>> {
    let multi_base = role_grant(
        hive,
        24,
        (owner_head, 4),
        (9, SubjectCustody::File),
        release_policy(ReleasePresence::CarriedDevice, 4),
        (NOW - 1000, NOW + 90 * 24 * 60 * 60 - 1000),
    )?;
    let multi_role = bounds::three_signers(&multi_base)?;
    let multi_bytes = multi_role.encode()?;
    let (multi_step, multi_signature) = root_step(root, owner_head, 5, multi_bytes.clone(), proposer)?;
    let multi_head = multi_step.digest()?;
    save(
        output,
        records,
        "multi-signer-role.cbor",
        &multi_bytes,
        "accept: root-issued threshold-three release role",
    )?;
    save(
        output,
        records,
        "multi-signer-role-step.cbor",
        &multi_step.encode()?,
        "accept: root step enrolling all three release signers",
    )?;
    save(
        output,
        records,
        "multi-signer-role-step.sig",
        &multi_signature,
        "accept: root signature over multi-signer role step",
    )?;

    let owner_expiry = owner_grant(hive, 13, multi_head, 5, target, VERIFY_AT + 3600)?;
    let owner_expiry_bytes = owner_expiry.encode()?;
    let (owner_expiry_step, owner_expiry_signature) =
        root_step(root, multi_head, 6, owner_expiry_bytes.clone(), proposer)?;
    let head = owner_expiry_step.digest()?;
    save(
        output,
        records,
        "owner-expiry-grant.cbor",
        &owner_expiry_bytes,
        "accept: second owner-action grant valid at verification time",
    )?;
    save(
        output,
        records,
        "owner-expiry-grant-step.cbor",
        &owner_expiry_step.encode()?,
        "accept: root-issued second owner-action grant step",
    )?;
    save(
        output,
        records,
        "owner-expiry-grant-step.sig",
        &owner_expiry_signature,
        "accept: root signature over second owner-action grant step",
    )?;

    Ok(Issued {
        multi_role,
        owner_expiry,
        head,
    })
}
