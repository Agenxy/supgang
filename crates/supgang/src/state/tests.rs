use super::{
    StateError, StateEvent, create_join_request, encode_event, initialize, install_join_bundle, open, unix_time,
};
use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
    identity::DeviceIdentity,
    ids::TransportKeyId,
    invitation::JoinBundle,
    membership::{MAX_MEMBERSHIP_LIFETIME_SECONDS, MembershipRoles},
    record::Capabilities,
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
    let now = unix_time()?;
    let membership = founder.authorize_join_request(
        &request,
        MembershipRoles::DEVICE,
        now,
        now.saturating_add(MAX_MEMBERSHIP_LIFETIME_SECONDS),
    )?;
    let bundle = JoinBundle::new(
        &founder.identity().root_verifying_key,
        membership,
        founder.revocations().clone(),
    );
    let joined = install_join_bundle(&joiner_path, &bundle)?;
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
fn endpoint_signature_is_returned_only_after_sequence_persistence() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state");
    let mut state = initialize(&path)?;
    let now = unix_time()?;
    let signed = state.sign_endpoint_record(
        TransportKeyId::from_public_material(b"ephemeral transport key"),
        vec![EndpointCandidate::new(
            CandidateKind::Local,
            CandidateTransport::QuicV1,
            std::net::SocketAddr::from(([127, 0, 0, 1], 4_433)),
        )?],
        Capabilities::NONE,
        now,
        now.saturating_add(3_600),
    )?;
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
