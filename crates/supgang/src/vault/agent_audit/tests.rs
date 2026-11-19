//! Agent audit durability and resource-bound tests.
use super::{Action, Event, Record, create_reserved, reserve_nonce, scan, segment_name, write_head};
use crate::{agent_sign_protocol::SignRequest, artifact, ids::NodeId, vault::VaultError};

#[test]
fn nonce_replay_and_purpose_budget_refuse_before_signing() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let requester = NodeId::from_bytes([1; 32]);
    create_reserved(directory.path(), requester, "build", b"policy", &[3; 32], false)?;
    let mut request = SignRequest {
        nonce: [0; 32],
        purpose: "build".to_owned(),
        context: "build.stage".to_owned(),
        digest: [4; 32],
        expires_at: super::unix_now() + 60,
    };
    for index in 0_u8..64 {
        request.nonce = [index; 32];
        reserve_nonce(directory.path(), requester, &request, &[3; 32])?;
    }
    assert!(matches!(
        reserve_nonce(directory.path(), requester, &request, &[3; 32]),
        Err(VaultError::AgentNonceReplay)
    ));
    request.nonce = [64; 32];
    assert!(matches!(
        reserve_nonce(directory.path(), requester, &request, &[3; 32]),
        Err(VaultError::AgentSignLimit)
    ));
    request.purpose = "other".to_owned();
    reserve_nonce(directory.path(), requester, &request, &[3; 32])?;
    Ok(())
}

#[test]
fn linked_segments_verify_and_tampering_refuses() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let requester = NodeId::from_bytes([1; 32]);
    let first = Record::new(
        1,
        [0; 32],
        Event {
            requester,
            action: Action::CreateReserved,
            purpose: "build",
            context: None,
            digest: &[2; 32],
            public_key: &[3; 32],
        },
    )?;
    let first_bytes = first.encode()?;
    artifact::write_new(directory.path().join(segment_name(0)), &first_bytes, 256 * 1024)?;
    let second = Record::new(
        2,
        first.compute_hash()?,
        Event {
            requester,
            action: Action::Sign,
            purpose: "build",
            context: Some("build.stage"),
            digest: &[4; 32],
            public_key: &[3; 32],
        },
    )?;
    let second_bytes = second.encode()?;
    artifact::write_new(directory.path().join(segment_name(1)), &second_bytes, 256 * 1024)?;
    write_head(directory.path(), 2, second.compute_hash()?, second.at)?;
    let verified = scan(directory.path())?;
    assert_eq!(verified.sequence, 2);
    assert_eq!(verified.hash, second.compute_hash()?);

    std::fs::remove_file(directory.path().join(segment_name(1)))?;
    assert!(matches!(scan(directory.path()), Err(VaultError::AgentAudit)));
    artifact::write_new(directory.path().join(segment_name(1)), &second_bytes, 256 * 1024)?;

    let mut changed = first_bytes;
    let offset = changed.iter().position(|byte| *byte == b'b').ok_or("missing purpose")?;
    *changed.get_mut(offset).ok_or("missing purpose")? = b'c';
    std::fs::write(directory.path().join(segment_name(0)), &changed)?;
    assert!(matches!(scan(directory.path()), Err(VaultError::AgentAudit)));
    Ok(())
}

#[test]
fn creation_limits_count_each_member_and_the_hive() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    for member in 1..=4 {
        let requester = NodeId::from_bytes([member; 32]);
        for index in 0..8 {
            create_reserved(
                directory.path(),
                requester,
                &format!("key{member}_{index}"),
                b"policy",
                &[3; 32],
                false,
            )?;
        }
        assert!(matches!(
            create_reserved(directory.path(), requester, "extra", b"policy", &[3; 32], true),
            Err(VaultError::AgentKeyCreationLimit)
        ));
    }
    assert!(matches!(
        create_reserved(
            directory.path(),
            NodeId::from_bytes([5; 32]),
            "extra",
            b"policy",
            &[3; 32],
            true
        ),
        Err(VaultError::AgentKeyCreationLimit)
    ));
    Ok(())
}

#[test]
fn future_audit_time_refuses_further_effects() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let requester = NodeId::from_bytes([1; 32]);
    let mut record = Record::new(
        1,
        [0; 32],
        Event {
            requester,
            action: Action::CreateReserved,
            purpose: "build",
            context: None,
            digest: &[2; 32],
            public_key: &[3; 32],
        },
    )?;
    record.at = record.at.saturating_add(60);
    record.hash = hex::encode(record.compute_hash()?);
    artifact::write_new(directory.path().join(segment_name(0)), &record.encode()?, 256 * 1024)?;
    write_head(directory.path(), 1, record.compute_hash()?, record.at)?;
    assert!(matches!(scan(directory.path()), Err(VaultError::AgentAudit)));
    Ok(())
}
