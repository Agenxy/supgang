use super::{ServiceConfig, eligible_hints, make_local_contact, recovery_candidates, unix_time};
use crate::{
    ids::NodeId, network::InterfaceNetwork, peer_directory::PeerDirectory, profile::PeerName, state,
    transport::TransportIdentity,
};

#[test]
fn unreachable_current_records_do_not_delay_the_only_usable_historical_family() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = tempfile::tempdir()?;
    let state_path = temporary.path().join("state");
    let mut publisher = state::initialize(&state_path)?;
    let transport = TransportIdentity::generate()?;
    let listen = "0.0.0.0:44330".parse()?;
    let config = ServiceConfig::new(PeerName::new("Test Peer")?, listen, &[], &["8.8.8.8:44330".parse()?])?;
    let original = make_local_contact(&mut publisher, &transport, &config)?;
    let mut directory = PeerDirectory::open(
        &state_path,
        publisher.identity().root_verifying_key,
        NodeId::from_bytes([5; 32]),
        publisher.revocations(),
    )?;
    directory.import(original.clone(), unix_time()?)?;
    for index in 1..=6 {
        let config = ServiceConfig::new(
            PeerName::new("Test Peer")?,
            listen,
            &[],
            &[format!("[2600::{index}]:44330").parse()?],
        )?;
        directory.import(make_local_contact(&mut publisher, &transport, &config)?, unix_time()?)?;
    }
    let hints = directory.dial_hints(unix_time()?);
    assert_eq!(hints.len(), 7);
    let ipv4 = InterfaceNetwork::new("10.0.0.2".parse()?, "255.255.255.0".parse()?);
    let ipv6 = InterfaceNetwork::new("2600::ffff".parse()?, "ffff:ffff:ffff:ffff::".parse()?);
    let eligible = eligible_hints(&hints, &[ipv4]);
    assert_eq!(eligible.len(), 1);
    let (hint, addresses) = eligible.first().ok_or("historical IPv4 hint was lost")?;
    assert_eq!(hint.contact(), &original);
    assert_eq!(addresses, &["8.8.8.8:44330".parse()?]);
    assert_eq!(eligible_hints(&hints, &[ipv6]).len(), 6);
    assert_eq!(eligible_hints(&hints, &[ipv4, ipv6]).len(), 7);
    assert!(eligible_hints(&hints, &[]).is_empty());
    let mut seen = std::collections::BTreeSet::new();
    for cycle in 0..16 {
        let candidates = recovery_candidates(&hints, &[ipv4, ipv6], cycle);
        assert!(candidates.len() <= crate::network::MAX_DIAL_CANDIDATES_PER_ROUND);
        // The preferred current path is present in every round, stronger than
        // the former three-current-rounds-to-one-historical-record policy.
        assert_eq!(
            candidates.first().map(|(contact, _)| contact),
            hints.first().map(crate::peer_directory::PeerDialHint::contact)
        );
        assert!(
            candidates
                .iter()
                .any(|(contact, address)| contact == &original && address.is_ipv4())
        );
        for (contact, address) in candidates {
            assert!(
                contact
                    .endpoint
                    .record
                    .candidates
                    .iter()
                    .any(|candidate| candidate.address() == address)
            );
            seen.insert(address);
        }
        let ipv4_only = recovery_candidates(&hints, &[ipv4], cycle);
        assert_eq!(ipv4_only, vec![(original.clone(), "8.8.8.8:44330".parse()?)]);
    }
    assert_eq!(
        seen.len(),
        7,
        "every eligible historical address must receive an attempt"
    );
    assert!(recovery_candidates(&hints, &[], 0).is_empty());
    Ok(())
}
