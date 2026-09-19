use super::*;

#[test]
fn a_full_cache_keeps_its_bound_when_the_local_gateway_arrives() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("state");
    let mut founder = state::initialize(&path)?;
    let local = founder.identity().device.node_id();
    let subject = DeviceIdentity::generate()?.node_id();
    let mut directory = PeerDirectory::open(
        &path,
        founder.identity().root_verifying_key,
        local,
        founder.revocations(),
    )?;
    for serial in 1..=8 {
        let reporter = DeviceIdentity::generate()?;
        let membership = founder.issue_membership(
            &reporter.verifying_key(),
            crate::membership::MembershipRoles::DEVICE,
            [serial; 32],
            10,
            1_000,
        )?;
        for port in 1..=4 {
            directory.import_reachability(
                ReachabilityClaim::sign(
                    membership.clone(),
                    &reporter,
                    subject,
                    SocketAddr::from(([9, 9, 9, 9], port)),
                    ReachabilitySource::PeerObserved,
                    50,
                )?,
                50,
            )?;
        }
    }
    assert_eq!(directory.reachability.len(), 16);
    let gateway = ReachabilityClaim::sign(
        founder.local_membership().ok_or("membership")?.clone(),
        &founder.identity().device,
        local,
        "8.8.8.8:44330".parse()?,
        ReachabilitySource::Gateway,
        50,
    )?;
    directory.replace_local_gateway_reachability(Some(gateway.clone()), 50)?;
    assert_eq!(directory.reachability.len(), 16);
    assert!(directory.reachability_claims(50).contains(&gateway));
    let reporters = directory
        .reachability_claims(50)
        .iter()
        .map(|claim| claim.reporter)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(reporters.len(), 9);
    Ok(())
}

#[test]
fn one_reporter_cannot_displace_another_or_the_local_gateway() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("state");
    let mut founder = state::initialize(&path)?;
    let local = founder.identity().device.node_id();
    let subject = DeviceIdentity::generate()?.node_id();
    let mut directory = PeerDirectory::open(
        &path,
        founder.identity().root_verifying_key,
        local,
        founder.revocations(),
    )?;
    let gateway = ReachabilityClaim::sign(
        founder.local_membership().ok_or("membership")?.clone(),
        &founder.identity().device,
        local,
        "8.8.8.8:44330".parse()?,
        ReachabilitySource::Gateway,
        50,
    )?;
    assert!(directory.replace_local_gateway_reachability(Some(gateway.clone()), 50)?);
    let trusted = DeviceIdentity::generate()?;
    let noisy = DeviceIdentity::generate()?;
    for reporter in [&trusted, &noisy] {
        let membership = founder.issue_membership(
            &reporter.verifying_key(),
            crate::membership::MembershipRoles::DEVICE,
            [1; 32],
            10,
            1_000,
        )?;
        let attempts = if reporter.node_id() == trusted.node_id() { 1 } else { 32 };
        for port in 1..=attempts {
            let claim = ReachabilityClaim::sign(
                membership.clone(),
                reporter,
                subject,
                SocketAddr::from(([9, 9, 9, 9], port)),
                ReachabilitySource::PeerObserved,
                50,
            )?;
            assert!(directory.import_reachability(claim, 50)?);
        }
    }
    let retained = directory.reachability_claims(50);
    assert_eq!(retained.len(), 6);
    assert!(retained.contains(&gateway));
    assert!(retained.iter().any(|claim| claim.reporter == trusted.node_id()));
    directory.replace_local_gateway_reachability(None, 50)?;
    assert!(!directory.import_reachability(gateway, 50)?);
    assert!(
        !directory
            .reachability_claims(50)
            .iter()
            .any(|claim| claim.reporter == local)
    );
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
        Some([claim.address, "127.0.0.1:4433".parse()?].as_slice())
    );
    assert_eq!(
        directory
            .dial_hints(claim.expires_at.saturating_add(1))
            .first()
            .map(PeerDialHint::addresses),
        Some(["127.0.0.1:4433".parse()?].as_slice())
    );

    drop(directory);
    let mut reopened = PeerDirectory::open(
        &state_path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    assert_eq!(
        reopened.dial_hints(50).first().map(PeerDialHint::addresses),
        Some(["127.0.0.1:4433".parse()?].as_slice())
    );
    assert!(reopened.import_reachability(claim, 50)?);
    let revocations = founder.revoke(reporter.node_id(), founder.revocations().list.issued_at)?;
    reopened.set_revocations(&revocations)?;
    assert_eq!(
        reopened.dial_hints(50).first().map(PeerDialHint::addresses),
        Some(["127.0.0.1:4433".parse()?].as_slice())
    );
    Ok(())
}

#[test]
fn mapped_ipv4_observations_share_one_hint_and_cannot_hide_loopback() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("state");
    let mut founder = state::initialize(&path)?;
    let subject = DeviceIdentity::generate()?;
    let reporter = DeviceIdentity::generate()?;
    let signed_contact = contact(&mut founder, &subject, 1, 44330)?;
    let membership = founder.issue_membership(
        &reporter.verifying_key(),
        crate::membership::MembershipRoles::DEVICE,
        [71; 32],
        10,
        1_000,
    )?;
    let mut directory = PeerDirectory::open(
        &path,
        founder.identity().root_verifying_key,
        founder.identity().device.node_id(),
        founder.revocations(),
    )?;
    directory.import(signed_contact, 50)?;
    let sign = |address| {
        ReachabilityClaim::sign(
            membership.clone(),
            &reporter,
            subject.node_id(),
            address,
            ReachabilitySource::PeerObserved,
            50,
        )
    };
    let original = sign("[::ffff:8.8.8.8]:44330".parse()?)?;
    assert!(directory.import_reachability(original.clone(), 50)?);
    assert!(!directory.import_reachability(sign("8.8.8.8:44330".parse()?)?, 50)?);
    // Lookup uses canonical sockets without rewriting authenticated payload bytes.
    assert_eq!(directory.reachability_claims(50), [original]);
    assert_eq!(
        directory.dial_hints(50).first().map(PeerDialHint::addresses),
        Some(["8.8.8.8:44330".parse()?, "127.0.0.1:44330".parse()?].as_slice())
    );
    for address in ["127.0.0.1:44330", "[::ffff:127.0.0.1]:44330"] {
        assert!(directory.import_reachability(sign(address.parse()?)?, 50).is_err());
    }
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
