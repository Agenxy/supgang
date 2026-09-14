use std::{fs, net::SocketAddr};

use super::{
    ImportDecision, PEER_COMPACTION_THRESHOLD_BYTES, PEER_DIRECTORY_FILE_NAME, PeerDialHint, PeerDirectory,
    PeerDirectoryError,
};
use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
    contact::{PeerContact, encode_contact},
    identity::DeviceIdentity,
    reachability::{ReachabilityClaim, ReachabilitySource},
    record::Capabilities,
    state,
};

fn contact(
    founder: &mut state::LocalState,
    device: &DeviceIdentity,
    sequence: u64,
    port: u16,
) -> Result<PeerContact, Box<dyn std::error::Error>> {
    contact_with_ports(founder, device, sequence, &[port])
}

fn contact_with_ports(
    founder: &mut state::LocalState,
    device: &DeviceIdentity,
    sequence: u64,
    ports: &[u16],
) -> Result<PeerContact, Box<dyn std::error::Error>> {
    let membership = if let Some(existing) = founder.membership(&device.node_id()) {
        existing.clone()
    } else {
        founder.issue_membership(
            &device.verifying_key(),
            crate::membership::MembershipRoles::DEVICE,
            [u8::try_from(sequence)?; 32],
            10,
            1_000,
        )?
    };
    let endpoint = crate::record::SignedEndpointRecord::sign(
        crate::record::EndpointRecord {
            protocol_version: crate::record::ENDPOINT_RECORD_VERSION,
            hive_id: founder.identity().hive_id,
            node_id: device.node_id(),
            display_name: Some(crate::profile::PeerName::new("Test Peer")?),
            transport_key_id: crate::ids::TransportKeyId::from_public_material(b"transport"),
            generation: 0,
            sequence,
            issued_at: 20,
            expires_at: 100,
            candidates: ports
                .iter()
                .map(|port| {
                    EndpointCandidate::new(
                        CandidateKind::Local,
                        CandidateTransport::QuicV1,
                        SocketAddr::from(([127, 0, 0, 1], *port)),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
            capabilities: Capabilities::NONE,
            services: Vec::new(),
        },
        device,
    )?;
    Ok(PeerContact { membership, endpoint })
}

fn public_contact_with_ports(
    founder: &mut state::LocalState,
    device: &DeviceIdentity,
    sequence: u64,
    ports: &[u16],
) -> Result<PeerContact, Box<dyn std::error::Error>> {
    let membership = if let Some(existing) = founder.membership(&device.node_id()) {
        existing.clone()
    } else {
        founder.issue_membership(
            &device.verifying_key(),
            crate::membership::MembershipRoles::DEVICE,
            [u8::try_from(sequence)?; 32],
            10,
            1_000,
        )?
    };
    let candidates = ports
        .iter()
        .map(|port| {
            EndpointCandidate::new(
                CandidateKind::Direct,
                CandidateTransport::QuicV1,
                SocketAddr::from(([8, 8, 8, 8], *port)),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let endpoint = crate::record::SignedEndpointRecord::sign(
        crate::record::EndpointRecord {
            protocol_version: crate::record::ENDPOINT_RECORD_VERSION,
            hive_id: founder.identity().hive_id,
            node_id: device.node_id(),
            display_name: Some(crate::profile::PeerName::new("Test Peer")?),
            transport_key_id: crate::ids::TransportKeyId::from_public_material(b"transport"),
            generation: 0,
            sequence,
            issued_at: 20,
            expires_at: 100,
            candidates,
            capabilities: Capabilities::NONE,
            services: Vec::new(),
        },
        device,
    )?;
    Ok(PeerContact { membership, endpoint })
}

fn conflicting_contact(
    original: &PeerContact,
    device: &DeviceIdentity,
    port: u16,
) -> Result<PeerContact, Box<dyn std::error::Error>> {
    let mut conflict = original.clone();
    conflict.endpoint = crate::record::SignedEndpointRecord::sign(
        crate::record::EndpointRecord {
            candidates: vec![EndpointCandidate::new(
                CandidateKind::Local,
                CandidateTransport::QuicV1,
                SocketAddr::from(([127, 0, 0, 1], port)),
            )?],
            ..original.endpoint.record.clone()
        },
        device,
    )?;
    Ok(conflict)
}

#[test]
fn imports_replays_and_stops_on_equivocation() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state_path = temporary.path().join("state");
    let mut founder = state::initialize(&state_path)?;
    let peer = DeviceIdentity::generate()?;
    let first = contact(&mut founder, &peer, 1, 4_433)?;
    let mut directory = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    assert_eq!(directory.import(first.clone(), 50)?, ImportDecision::AcceptedFirst);
    assert_eq!(directory.import(first.clone(), 50)?, ImportDecision::Duplicate);

    let conflict = conflicting_contact(&first, &peer, 4_434)?;
    assert!(matches!(
        directory.import(conflict, 50),
        Err(PeerDirectoryError::Equivocation)
    ));
    drop(directory);

    let reopened = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    let entry = reopened.entries().get(&peer.node_id()).ok_or("peer missing")?;
    assert!(entry.is_conflicted());
    assert!(reopened.usable(&peer.node_id(), 50).is_none());
    drop(reopened);
    let mut compacted = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    compacted.compact()?;
    drop(compacted);
    let reopened = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    assert!(
        reopened
            .entries()
            .get(&peer.node_id())
            .ok_or("peer missing after compaction")?
            .is_conflicted()
    );
    Ok(())
}

#[test]
fn one_sync_page_coalesces_repeated_node_updates_to_one_durable_frame() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state_path = temporary.path().join("state");
    let mut founder = state::initialize(&state_path)?;
    let peer = DeviceIdentity::generate()?;
    let contacts = (1_u64..=8)
        .map(|sequence| {
            contact(
                &mut founder,
                &peer,
                sequence,
                4_400 + u16::try_from(sequence).unwrap_or(0),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut directory = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    assert!(directory.import_page(contacts, 50)?);
    assert_eq!(
        directory
            .entries()
            .get(&peer.node_id())
            .ok_or("peer missing")?
            .current()
            .endpoint
            .record
            .sequence,
        8
    );
    assert_eq!(
        crate::journal::Journal::read(state_path.join(PEER_DIRECTORY_FILE_NAME))?.len(),
        1
    );
    Ok(())
}

#[test]
fn equivocation_churn_persists_only_the_first_conflict_and_survives_restart() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = tempfile::tempdir()?;
    let state_path = temporary.path().join("state");
    let mut founder = state::initialize(&state_path)?;
    let peer = DeviceIdentity::generate()?;
    let first = contact(&mut founder, &peer, 1, 4_433)?;
    let first_conflict = conflicting_contact(&first, &peer, 4_434)?;
    let journal_path = state_path.join(PEER_DIRECTORY_FILE_NAME);
    let mut directory = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    assert_eq!(directory.import(first.clone(), 50)?, ImportDecision::AcceptedFirst);
    assert!(matches!(
        directory.import(first_conflict.clone(), 50),
        Err(PeerDirectoryError::Equivocation)
    ));
    let bounded_length = fs::metadata(&journal_path)?.len();

    for port in 4_435_u16..4_535 {
        assert!(matches!(
            directory.import(conflicting_contact(&first, &peer, port)?, 50),
            Err(PeerDirectoryError::Equivocation)
        ));
        assert_eq!(fs::metadata(&journal_path)?.len(), bounded_length);
    }
    let entry = directory.entries().get(&peer.node_id()).ok_or("peer missing")?;
    assert_eq!(entry.conflict(), Some(&first_conflict));
    drop(directory);

    let reopened = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    let entry = reopened
        .entries()
        .get(&peer.node_id())
        .ok_or("peer missing after restart")?;
    assert!(entry.is_conflicted());
    assert_eq!(entry.conflict(), Some(&first_conflict));
    assert!(reopened.usable(&peer.node_id(), 50).is_none());
    assert_eq!(crate::journal::Journal::read(&journal_path)?.len(), 2);
    Ok(())
}

#[test]
fn terminal_equivocation_compacts_a_bloated_legacy_journal() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state_path = temporary.path().join("state");
    let mut founder = state::initialize(&state_path)?;
    let peer = DeviceIdentity::generate()?;
    let first = contact(&mut founder, &peer, 1, 4_433)?;
    let first_conflict = conflicting_contact(&first, &peer, 4_434)?;
    let mut directory = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    assert_eq!(directory.import(first.clone(), 50)?, ImportDecision::AcceptedFirst);
    assert!(matches!(
        directory.import(first_conflict, 50),
        Err(PeerDirectoryError::Equivocation)
    ));

    let encoded = encode_contact(&first)?;
    let journal = directory.journal.as_mut().ok_or("writable peer journal missing")?;
    assert!(
        journal.append_repeated_until_len_for_test(&encoded, PEER_COMPACTION_THRESHOLD_BYTES.saturating_add(1),)? > 0
    );
    assert!(journal.byte_len()? >= PEER_COMPACTION_THRESHOLD_BYTES);

    assert!(matches!(
        directory.import(conflicting_contact(&first, &peer, 4_435)?, 50),
        Err(PeerDirectoryError::Equivocation)
    ));
    let journal = directory.journal.as_ref().ok_or("writable peer journal missing")?;
    assert!(journal.byte_len()? < PEER_COMPACTION_THRESHOLD_BYTES);
    assert_eq!(crate::journal::Journal::read(journal.path())?.len(), 2);
    drop(directory);

    let reopened = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    assert!(
        reopened
            .entries()
            .get(&peer.node_id())
            .ok_or("peer missing after compacted restart")?
            .is_conflicted()
    );
    Ok(())
}

#[test]
fn revocation_view_rejects_rollback_equivocation_and_restoration() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state_path = temporary.path().join("state");
    let mut founder = state::initialize(&state_path)?;
    let first = DeviceIdentity::generate()?;
    let second = DeviceIdentity::generate()?;
    for (device, nonce) in [(&first, [1; 32]), (&second, [2; 32])] {
        founder.issue_membership(
            &device.verifying_key(),
            crate::membership::MembershipRoles::DEVICE,
            nonce,
            10,
            1_000,
        )?;
    }
    let initial = founder.revocations().clone();
    let first_revocation = founder.revoke(first.node_id(), initial.list.issued_at.saturating_add(1))?;
    let second_revocation = founder.revoke(second.node_id(), initial.list.issued_at.saturating_add(2))?;
    let mut directory = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        &initial,
    )?;

    directory.set_revocations(&first_revocation)?;
    directory.set_revocations(&first_revocation)?;
    assert!(matches!(
        directory.set_revocations(&initial),
        Err(PeerDirectoryError::RevocationRollback)
    ));

    let root = founder.identity().root.as_ref().ok_or("founder root missing")?;
    let equivocation = crate::revocation::SignedRevocationList::sign(
        crate::revocation::RevocationList {
            version: crate::revocation::REVOCATION_VERSION,
            hive_id: founder.identity().hive_id,
            serial: first_revocation.list.serial,
            issued_at: first_revocation.list.issued_at,
            revoked_nodes: vec![second.node_id()],
        },
        root,
    )?;
    assert!(matches!(
        directory.set_revocations(&equivocation),
        Err(PeerDirectoryError::RevocationEquivocation)
    ));

    let removed_revocation = crate::revocation::SignedRevocationList::sign(
        crate::revocation::RevocationList {
            version: crate::revocation::REVOCATION_VERSION,
            hive_id: founder.identity().hive_id,
            serial: second_revocation.list.serial.saturating_add(1),
            issued_at: second_revocation.list.issued_at,
            revoked_nodes: vec![second.node_id()],
        },
        root,
    )?;
    assert!(matches!(
        directory.set_revocations(&removed_revocation),
        Err(PeerDirectoryError::RevocationRollback)
    ));
    directory.set_revocations(&second_revocation)?;
    assert!(directory.is_revoked(&first.node_id()));
    assert!(directory.is_revoked(&second.node_id()));
    Ok(())
}

#[test]
fn expired_contact_remains_pin_authority_only_for_authenticated_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state_path = temporary.path().join("state");
    let mut founder = state::initialize(&state_path)?;
    let peer = DeviceIdentity::generate()?;
    let signed = contact(&mut founder, &peer, 1, 4_433)?;
    let mut directory = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    directory.import(signed, 50)?;

    assert!(directory.usable(&peer.node_id(), 101).is_none());
    assert_eq!(
        directory
            .recovery_authority(&peer.node_id())
            .map(|contact| contact.endpoint.record.node_id),
        Some(peer.node_id())
    );
    Ok(())
}

#[test]
fn revocation_immediately_removes_every_automatic_use() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state_path = temporary.path().join("state");
    let mut founder = state::initialize(&state_path)?;
    let peer = DeviceIdentity::generate()?;
    let signed_contact = contact(&mut founder, &peer, 1, 4_433)?;
    let mut directory = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    assert_eq!(
        directory.import(signed_contact.clone(), 50)?,
        ImportDecision::AcceptedFirst
    );

    let revocation_time = founder.revocations().list.issued_at;
    let revocations = founder.revoke(peer.node_id(), revocation_time)?;
    directory.set_revocations(&revocations)?;
    assert!(directory.is_revoked(&peer.node_id()));
    assert!(directory.usable(&peer.node_id(), 50).is_none());
    assert!(directory.usable_contacts(50).is_empty());
    assert!(directory.dial_hints(50).is_empty());
    assert!(matches!(
        directory.import(signed_contact, 50),
        Err(PeerDirectoryError::Revoked)
    ));
    Ok(())
}

#[test]
fn historical_dial_hints_are_newest_first_deduplicated_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state_path = temporary.path().join("state");
    let mut founder = state::initialize(&state_path)?;
    let peer = DeviceIdentity::generate()?;
    let mut directory = PeerDirectory::open_with_history_limit(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
        8,
    )?;
    for sequence in 1_u64..=12 {
        let port = 4_400_u16.saturating_add(u16::try_from(sequence)?);
        directory.import(public_contact_with_ports(&mut founder, &peer, sequence, &[port])?, 50)?;
    }

    let hints = directory.dial_hints(50);
    assert_eq!(hints.len(), 9);
    let ports = hints
        .iter()
        .flat_map(super::PeerDialHint::addresses)
        .map(SocketAddr::port)
        .collect::<Vec<_>>();
    assert_eq!(ports, [4_412, 4_411, 4_410, 4_409, 4_408, 4_407, 4_406, 4_405, 4_404]);

    directory.compact()?;
    drop(directory);
    let reopened = PeerDirectory::open_with_history_limit(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
        8,
    )?;
    assert_eq!(reopened.dial_hints(50).len(), 9);
    Ok(())
}

#[test]
fn historical_records_retry_only_addresses_missing_from_newer_records() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state_path = temporary.path().join("state");
    let mut founder = state::initialize(&state_path)?;
    let peer = DeviceIdentity::generate()?;
    let mut directory = PeerDirectory::open_with_history_limit(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
        8,
    )?;
    directory.import(
        public_contact_with_ports(&mut founder, &peer, 1, &[4_401, 4_402, 4_403, 4_404, 4_405])?,
        50,
    )?;
    directory.import(
        public_contact_with_ports(&mut founder, &peer, 2, &[4_401, 4_402, 4_403, 4_404, 4_406])?,
        50,
    )?;

    let hints = directory.dial_hints(50);
    assert_eq!(hints.len(), 2);
    let [current, previous] = hints.as_slice() else {
        return Err("expected one current and one historical hint".into());
    };
    assert_eq!(current.addresses().len(), 5);
    assert_eq!(previous.addresses(), [SocketAddr::from(([8, 8, 8, 8], 4_405))]);
    Ok(())
}

#[test]
fn reporter_bound_reachability_is_ephemeral_and_revocation_aware() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state_path = temporary.path().join("state");
    let mut founder = state::initialize(&state_path)?;
    let subject = DeviceIdentity::generate()?;
    let reporter = DeviceIdentity::generate()?;
    let subject_contact = contact(&mut founder, &subject, 1, 4_433)?;
    let reporter_membership = founder.issue_membership(
        &reporter.verifying_key(),
        crate::membership::MembershipRoles::DEVICE,
        [70; 32],
        10,
        1_000,
    )?;
    let claim = ReachabilityClaim::sign(
        reporter_membership,
        &reporter,
        subject.node_id(),
        SocketAddr::from(([8, 8, 8, 8], 44_330)),
        ReachabilitySource::PeerObserved,
        50,
    )?;
    let mut directory = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    directory.import(subject_contact, 50)?;
    assert!(directory.import_reachability(claim.clone(), 50)?);
    assert!(!directory.import_reachability(claim.clone(), 50)?);
    assert_eq!(
        directory.dial_hints(50).first().map(PeerDialHint::addresses),
        Some([claim.address].as_slice())
    );
    assert!(directory.dial_hints(claim.expires_at.saturating_add(1)).is_empty());

    drop(directory);
    let mut reopened = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    assert!(reopened.dial_hints(50).is_empty());
    assert!(reopened.import_reachability(claim, 50)?);
    let revocations = founder.revoke(reporter.node_id(), founder.revocations().list.issued_at)?;
    reopened.set_revocations(&revocations)?;
    assert!(reopened.dial_hints(50).is_empty());
    Ok(())
}

#[test]
fn gateway_report_replaces_only_ephemeral_local_provenance() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state_path = temporary.path().join("state");
    let founder = state::initialize(&state_path)?;
    let membership = founder.local_membership().ok_or("local membership missing")?.clone();
    let first = ReachabilityClaim::sign(
        membership.clone(),
        &founder.identity().device,
        founder.identity().device.node_id(),
        SocketAddr::from(([8, 8, 8, 8], 44_330)),
        ReachabilitySource::Gateway,
        50,
    )?;
    let second = ReachabilityClaim::sign(
        membership,
        &founder.identity().device,
        founder.identity().device.node_id(),
        SocketAddr::from(([9, 9, 9, 9], 44_330)),
        ReachabilitySource::Gateway,
        51,
    )?;
    let mut directory = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    assert!(directory.replace_local_gateway_reachability(Some(first), 50)?);
    assert!(directory.replace_local_gateway_reachability(Some(second.clone()), 51)?);
    assert_eq!(directory.reachability_claims(51), [second]);
    assert!(directory.replace_local_gateway_reachability(None, 51)?);
    assert!(directory.reachability_claims(51).is_empty());
    Ok(())
}
