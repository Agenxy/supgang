use super::event::signed_checkpoint;
use super::{
    AUTHORITATIVE_COMPACTION_THRESHOLD_BYTES, StateError, StateEvent, create_join_request, encode_event, initialize,
    install_join_bundle, open, unix_time,
};
use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
    identity::DeviceIdentity,
    ids::{HiveId, NodeId, TransportKeyId},
    invitation::JoinBundle,
    journal::MAX_JOURNAL_BYTES,
    membership::{MAX_MEMBERSHIP_LIFETIME_SECONDS, MembershipRoles},
    record::{Capabilities, EndpointClaims},
    revocation::{REVOCATION_VERSION, RevocationList, SignedRevocationList},
    storage,
};

#[test]
fn founder_and_sequences_replay_after_restart() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state");
    let mut state = initialize(&path)?;
    assert_eq!(state.event_count(), 1);
    assert_eq!(state.reserve_next_sequence()?, 1);
    assert_eq!(state.reserve_next_sequence()?, 2);
    drop(state);

    let reopened = open(&path)?;
    assert_eq!(reopened.sequence(), 2);
    assert_eq!(reopened.event_count(), 3);
    assert_eq!(reopened.member_count(), 1);
    Ok(())
}

#[test]
fn initialization_recovers_the_identity_before_genesis_crash_window() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state");
    let incomplete = storage::initialize(&path)?;
    let expected_node = incomplete.identity.device.node_id();
    drop(incomplete);

    let recovered = initialize(&path)?;
    assert_eq!(recovered.identity().device.node_id(), expected_node);
    assert_eq!(recovered.event_count(), 1);
    drop(recovered);
    assert_eq!(open(&path)?.event_count(), 1);
    Ok(())
}

#[test]
fn issued_membership_is_durable_and_root_verified() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state");
    let mut state = initialize(&path)?;
    let peer = DeviceIdentity::generate()?;
    let signed = state.issue_membership(&peer.verifying_key(), MembershipRoles::DEVICE, [7; 32], 100, 200)?;
    signed.verify(&state.identity().root_verifying_key)?;
    drop(state);
    assert_eq!(open(&path)?.member_count(), 2);
    Ok(())
}

#[test]
fn sequence_gap_fails_closed_during_replay() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state");
    drop(initialize(&path)?);
    let (mut journal, _) = storage::open_journal(&path)?;
    journal.append(&encode_event(&StateEvent::Sequence {
        generation: 0,
        sequence: 2,
    })?)?;
    drop(journal);
    assert!(matches!(open(&path), Err(StateError::InvalidSequence)));
    Ok(())
}

#[test]
fn offline_join_never_exports_the_recipient_private_key() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let founder_path = directory.path().join("founder");
    let joiner_path = directory.path().join("joiner");
    let mut founder = initialize(&founder_path)?;
    let request = create_join_request(&joiner_path)?;
    let expected_node = NodeId::from_verifying_key(&request.device_verifying_key);
    let now = unix_time()?;
    let membership = founder.authorize_join_request(
        &request,
        expected_node,
        MembershipRoles::DEVICE,
        now,
        now.saturating_add(MAX_MEMBERSHIP_LIFETIME_SECONDS),
    )?;
    let bundle = JoinBundle::new(
        founder.identity().root.as_ref().ok_or("founder root missing")?,
        membership,
        founder.revocations().clone(),
        now,
    )?;
    let expected_hive = HiveId::from_root_verifying_key(&bundle.root_verifying_key);
    let joined = install_join_bundle(&joiner_path, &bundle, expected_hive)?;
    assert_eq!(
        joined.identity().device.verifying_key().to_bytes(),
        request.device_verifying_key
    );
    assert!(joined.identity().root.is_none());
    assert_eq!(joined.member_count(), 1);
    assert_eq!(founder.member_count(), 2);
    Ok(())
}

#[test]
fn join_authorization_rejects_an_unexpected_proved_node_before_mutation() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let founder_path = directory.path().join("founder");
    let joiner_path = directory.path().join("joiner");
    let mut founder = initialize(&founder_path)?;
    let request = create_join_request(&joiner_path)?;
    let actual_node = NodeId::from_verifying_key(&request.device_verifying_key);
    let expected_node = if actual_node == NodeId::from_bytes([42; 32]) {
        NodeId::from_bytes([43; 32])
    } else {
        NodeId::from_bytes([42; 32])
    };
    let before_events = founder.event_count();
    let before_members = founder.member_count();
    let now = unix_time()?;

    assert!(matches!(
        founder.authorize_join_request(
            &request,
            expected_node,
            MembershipRoles::DEVICE,
            now,
            now.saturating_add(MAX_MEMBERSHIP_LIFETIME_SECONDS),
        ),
        Err(StateError::UnexpectedJoinNode)
    ));
    assert_eq!(founder.event_count(), before_events);
    assert_eq!(founder.member_count(), before_members);
    drop(founder);
    let reopened = open(&founder_path)?;
    assert_eq!(reopened.event_count(), before_events);
    assert_eq!(reopened.member_count(), before_members);
    Ok(())
}

#[test]
fn join_install_rejects_an_unexpected_hive_before_filesystem_mutation() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let founder_path = directory.path().join("founder");
    let joiner_path = directory.path().join("joiner");
    let mut founder = initialize(&founder_path)?;
    let request = create_join_request(&joiner_path)?;
    let expected_node = NodeId::from_verifying_key(&request.device_verifying_key);
    let now = unix_time()?;
    let membership = founder.authorize_join_request(
        &request,
        expected_node,
        MembershipRoles::DEVICE,
        now,
        now.saturating_add(MAX_MEMBERSHIP_LIFETIME_SECONDS),
    )?;
    let bundle = JoinBundle::new(
        founder.identity().root.as_ref().ok_or("founder root missing")?,
        membership,
        founder.revocations().clone(),
        now,
    )?;
    let actual_hive = HiveId::from_root_verifying_key(&bundle.root_verifying_key);
    let unexpected_hive = if actual_hive == HiveId::from_bytes([42; 32]) {
        HiveId::from_bytes([43; 32])
    } else {
        HiveId::from_bytes([42; 32])
    };

    assert!(matches!(
        install_join_bundle(&joiner_path, &bundle, unexpected_hive),
        Err(StateError::UnexpectedJoinHive)
    ));
    assert!(!joiner_path.join(storage::JOURNAL_FILE_NAME).exists());
    assert!(!joiner_path.join(storage::IDENTITY_FILE_NAME).exists());
    assert!(joiner_path.join(storage::PENDING_FILE_NAME).exists());

    let joined = install_join_bundle(&joiner_path, &bundle, actual_hive)?;
    assert_eq!(joined.identity().hive_id, actual_hive);
    Ok(())
}

#[test]
fn endpoint_signature_is_returned_only_after_sequence_persistence() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state");
    let mut state = initialize(&path)?;
    let now = unix_time()?;
    let signed = state.sign_endpoint_record(
        crate::profile::PeerName::new("Test Computer")?,
        TransportKeyId::from_public_material(b"ephemeral transport key"),
        EndpointClaims {
            candidates: vec![EndpointCandidate::new(
                CandidateKind::Local,
                CandidateTransport::QuicV1,
                std::net::SocketAddr::from(([127, 0, 0, 1], 4_433)),
            )?],
            capabilities: Capabilities::NONE,
            services: Vec::new(),
        },
        now,
        now.saturating_add(3_600),
    )?;
    assert_eq!(
        signed.record.protocol_version,
        crate::record::ENDPOINT_RECORD_VERSION_V2,
        "a record that advertises nothing stays readable by members that have not upgraded"
    );
    signed.verify_authorized(
        state.local_membership().ok_or("missing local membership")?,
        &state.identity().root_verifying_key,
        now,
    )?;
    assert_eq!(signed.record.sequence, 1);
    drop(state);
    assert_eq!(open(&path)?.sequence(), 1);
    Ok(())
}

#[test]
fn revocation_is_durable_idempotent_and_permanent() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state");
    let mut state = initialize(&path)?;
    let peer = DeviceIdentity::generate()?;
    let now = unix_time()?;
    state.issue_membership(
        &peer.verifying_key(),
        MembershipRoles::DEVICE,
        [9; 32],
        now,
        now.saturating_add(MAX_MEMBERSHIP_LIFETIME_SECONDS),
    )?;
    let before = state.event_count();

    let first = state.revoke(peer.node_id(), now)?;
    assert_eq!(first.list.serial, 1);
    assert!(first.contains(&peer.node_id()));
    assert_eq!(state.event_count(), before + 1);
    assert_eq!(state.revoke(peer.node_id(), now)?, first);
    assert_eq!(state.event_count(), before + 1);
    assert!(matches!(
        state.issue_membership(
            &peer.verifying_key(),
            MembershipRoles::DEVICE,
            [10; 32],
            now,
            now.saturating_add(MAX_MEMBERSHIP_LIFETIME_SECONDS),
        ),
        Err(StateError::RevokedMember)
    ));
    drop(state);

    let reopened = open(&path)?;
    assert_eq!(reopened.revocations(), &first);
    Ok(())
}

#[test]
fn revocation_merge_rejects_equivocation_and_set_rollback() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state");
    let mut state = initialize(&path)?;
    let first_peer = DeviceIdentity::generate()?;
    let second_peer = DeviceIdentity::generate()?;
    let now = unix_time()?;
    let expires_at = now.saturating_add(MAX_MEMBERSHIP_LIFETIME_SECONDS);
    state.issue_membership(
        &first_peer.verifying_key(),
        MembershipRoles::DEVICE,
        [11; 32],
        now,
        expires_at,
    )?;
    state.issue_membership(
        &second_peer.verifying_key(),
        MembershipRoles::DEVICE,
        [12; 32],
        now,
        expires_at,
    )?;
    let first = state.revoke(first_peer.node_id(), now)?;
    let (equivocation, rollback) = {
        let root = state.identity.root.as_ref().ok_or("missing root")?;
        let hive_id = state.identity.hive_id;
        let equivocation = SignedRevocationList::sign(
            RevocationList {
                version: REVOCATION_VERSION,
                hive_id,
                serial: first.list.serial,
                issued_at: now,
                revoked_nodes: vec![second_peer.node_id()],
            },
            root,
        )?;
        let rollback = SignedRevocationList::sign(
            RevocationList {
                version: REVOCATION_VERSION,
                hive_id,
                serial: first.list.serial + 1,
                issued_at: now,
                revoked_nodes: vec![second_peer.node_id()],
            },
            root,
        )?;
        (equivocation, rollback)
    };
    assert!(matches!(
        state.merge_revocations(equivocation),
        Err(StateError::RevocationEquivocation)
    ));

    assert!(matches!(
        state.merge_revocations(rollback),
        Err(StateError::RevocationRollback)
    ));
    assert_eq!(state.revocations(), &first);
    Ok(())
}

#[test]
fn signed_checkpoint_preserves_authority_and_sequence_across_restart() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state");
    let mut state = initialize(&path)?;
    let peer = DeviceIdentity::generate()?;
    let now = unix_time()?;
    state.issue_membership(
        &peer.verifying_key(),
        MembershipRoles::DEVICE,
        [31; 32],
        now,
        now.saturating_add(MAX_MEMBERSHIP_LIFETIME_SECONDS),
    )?;
    let revocations = state.revoke(peer.node_id(), now)?;
    assert_eq!(state.reserve_next_sequence()?, 1);
    assert_eq!(state.reserve_next_sequence()?, 2);
    state.compact()?;
    assert_eq!(state.event_count(), 3);
    drop(state);

    let mut reopened = open(&path)?;
    assert_eq!(reopened.member_count(), 2);
    assert_eq!(reopened.revocations(), &revocations);
    assert_eq!(reopened.sequence(), 2);
    assert_eq!(reopened.event_count(), 3);
    assert_eq!(reopened.reserve_next_sequence()?, 3);
    drop(reopened);
    assert_eq!(open(&path)?.sequence(), 3);
    Ok(())
}

#[test]
fn near_full_authoritative_history_compacts_before_append_and_restarts() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state");
    let mut state = initialize(&path)?;
    let final_sequence = 370_000_u64;
    let mut frames = Vec::with_capacity(usize::try_from(final_sequence)?);
    for sequence in 1..=final_sequence {
        frames.push(encode_event(&StateEvent::Sequence {
            generation: 0,
            sequence,
        })?);
    }
    state.journal_mut()?.append_batch(&frames)?;
    drop(state);

    let mut reopened = open(&path)?;
    assert_eq!(reopened.sequence(), final_sequence);
    assert!(reopened.journal_mut()?.byte_len()? >= MAX_JOURNAL_BYTES.saturating_sub(512_u64.saturating_mul(1024)));
    assert_eq!(reopened.reserve_next_sequence()?, final_sequence + 1);
    assert!(reopened.journal_mut()?.byte_len()? < AUTHORITATIVE_COMPACTION_THRESHOLD_BYTES);
    drop(reopened);

    let reopened = open(&path)?;
    assert_eq!(reopened.sequence(), final_sequence + 1);
    assert_eq!(reopened.member_count(), 1);
    Ok(())
}

#[test]
fn checkpoint_signature_tampering_and_post_checkpoint_rollback_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let tampered_path = directory.path().join("tampered");
    let mut tampered = initialize(&tampered_path)?;
    assert_eq!(tampered.reserve_next_sequence()?, 1);
    let mut snapshot = tampered.compaction_frames()?;
    snapshot.pop().ok_or("checkpoint frame missing")?;
    let mut checkpoint = signed_checkpoint(
        tampered.identity(),
        tampered.generation(),
        tampered.sequence(),
        &snapshot,
    )?;
    let StateEvent::Checkpoint { signature, .. } = &mut checkpoint else {
        return Err("signed checkpoint had the wrong event type".into());
    };
    signature[0] ^= 1;
    snapshot.push(encode_event(&checkpoint)?);
    tampered.journal_mut()?.compact(&snapshot)?;
    drop(tampered);
    assert!(matches!(open(&tampered_path), Err(StateError::InvalidCheckpoint)));

    let rollback_path = directory.path().join("rollback");
    let mut rollback = initialize(&rollback_path)?;
    assert_eq!(rollback.reserve_next_sequence()?, 1);
    rollback.compact()?;
    let rollback_generation = rollback.generation();
    let rollback_sequence = rollback.sequence();
    rollback.journal_mut()?.append(&encode_event(&StateEvent::Sequence {
        generation: rollback_generation,
        sequence: rollback_sequence,
    })?)?;
    drop(rollback);
    assert!(matches!(open(&rollback_path), Err(StateError::InvalidSequence)));
    Ok(())
}

#[test]
fn ambiguous_compaction_failure_poisoned_state_until_reopen() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state");
    let mut state = initialize(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))?;
    let compact = state.compact();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    assert!(matches!(compact, Err(StateError::Journal(_))));
    assert!(matches!(
        state.reserve_next_sequence(),
        Err(StateError::ReadOnlySnapshot)
    ));
    drop(state);
    let reopened = open(&path)?;
    assert_eq!(reopened.sequence(), 0);
    Ok(())
}
