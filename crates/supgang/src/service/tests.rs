use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

use super::live_session::dial_hint_index;
use super::local_control::connection_event_is_current;
use super::{
    CANDIDATE_RACE_DELAY_MILLIS, MAX_PENDING_INBOUND_SESSIONS, MAX_PENDING_OUTBOUND_SESSIONS,
    MAX_PENDING_PRIORITY_INBOUND_SESSIONS, MAX_PENDING_SESSIONS, SECONDARY_RECOVERY_CADENCE, ServiceConfig,
    ServiceError, candidate_race_delay, replace_interface_candidates, should_attempt_peer,
};
use crate::{candidate::CandidateKind, ids::NodeId};

const _: () = {
    assert!(MAX_PENDING_INBOUND_SESSIONS > 0);
    assert!(MAX_PENDING_OUTBOUND_SESSIONS > 0);
    assert!(
        MAX_PENDING_INBOUND_SESSIONS + MAX_PENDING_PRIORITY_INBOUND_SESSIONS + MAX_PENDING_OUTBOUND_SESSIONS
            == MAX_PENDING_SESSIONS
    );
};

fn name() -> crate::profile::PeerName {
    crate::profile::PeerName::new("Test Computer").unwrap_or_else(|_| unreachable!())
}

#[test]
fn strict_configuration_rejects_missing_or_unsafe_advertisements() {
    let listen = SocketAddr::from(([0, 0, 0, 0], 4_433));
    assert!(matches!(
        ServiceConfig::new(name(), listen, &[], &[]),
        Err(ServiceError::InvalidConfiguration)
    ));
    assert!(ServiceConfig::new(name(), listen, &[SocketAddr::from(([127, 0, 0, 1], 4_433))], &[]).is_ok());
    let configured = ServiceConfig::new(name(), listen, &[SocketAddr::from(([127, 0, 0, 1], 4_433))], &[])
        .and_then(|value| value.with_intervals(Duration::from_millis(1), Duration::from_hours(1)));
    assert!(matches!(configured, Err(ServiceError::InvalidConfiguration)));
}

#[test]
fn anchor_mode_raises_the_neighbor_budget_to_a_fixed_ceiling() -> Result<(), Box<dyn std::error::Error>> {
    let listen = SocketAddr::from(([0, 0, 0, 0], 4_433));
    let config =
        ServiceConfig::new(name(), listen, &[SocketAddr::from(([127, 0, 0, 1], 4_433))], &[])?.with_anchor_mode(true);
    assert_eq!(config.max_active_peers, super::MAX_ANCHOR_PEERS);
    Ok(())
}

#[test]
fn explicit_router_mappings_preserve_provenance_and_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let listen = SocketAddr::from(([0, 0, 0, 0], 4_433));
    let local = SocketAddr::from(([192, 168, 1, 20], 4_433));
    let mapped = SocketAddr::from(([8, 8, 8, 8], 4_433));
    let config = ServiceConfig::new(name(), listen, &[local], &[])?.with_mapped_addresses(&[mapped])?;
    assert!(
        config
            .candidates
            .iter()
            .any(|candidate| candidate.kind() == CandidateKind::Mapped && candidate.address() == mapped)
    );
    assert!(
        ServiceConfig::new(name(), listen, &[local], &[])?
            .with_mapped_addresses(&[local])
            .is_err()
    );
    assert!(
        ServiceConfig::new(name(), SocketAddr::from(([127, 0, 0, 1], 4_433)), &[local], &[])?
            .with_mapped_addresses(&[mapped])
            .is_err()
    );
    assert!(
        ServiceConfig::new(name(), listen, &[local], &[])?
            .with_mapped_addresses(&[SocketAddr::from(([192, 168, 1, 1], 4_433))])
            .is_err()
    );
    Ok(())
}

#[test]
fn interface_refresh_preserves_owner_declared_router_mapping() -> Result<(), Box<dyn std::error::Error>> {
    let listen = SocketAddr::from(([0, 0, 0, 0], 4_433));
    let old_local = SocketAddr::from(([192, 168, 1, 20], 4_433));
    let new_local = SocketAddr::from(([10, 0, 0, 20], 4_433));
    let mapped = SocketAddr::from(([8, 8, 8, 8], 4_433));
    let mut config = ServiceConfig::new(name(), listen, &[old_local], &[])?
        .with_mapped_addresses(&[mapped])?
        .with_automatic_interface_refresh(true);
    assert!(
        config
            .candidates
            .iter()
            .any(|candidate| candidate.kind() == CandidateKind::Mapped && candidate.address() == mapped)
    );

    assert!(replace_interface_candidates(&mut config, &[new_local], &[]));
    assert!(
        config
            .candidates
            .iter()
            .any(|candidate| { candidate.kind() == CandidateKind::Mapped && candidate.address() == mapped }),
        "candidates after refresh: {:?}",
        config.candidates
    );
    assert!(
        config
            .candidates
            .iter()
            .any(|candidate| candidate.address() == new_local)
    );
    assert!(
        !config
            .candidates
            .iter()
            .any(|candidate| candidate.address() == old_local)
    );
    assert!(config.candidates.len() <= super::MAX_CANDIDATES);
    Ok(())
}

#[test]
fn automatic_mode_keeps_a_fixed_interface_candidate_ceiling() -> Result<(), Box<dyn std::error::Error>> {
    let listen = SocketAddr::from(([0, 0, 0, 0], 4_433));
    let local = (1_u8..=8)
        .map(|host| SocketAddr::from(([10, 0, 0, host], 4_433)))
        .collect::<Vec<_>>();
    let config = ServiceConfig::new(name(), listen, &local, &[])?.with_automatic_interface_refresh(true);
    assert_eq!(config.candidates.len(), super::MAX_CANDIDATES);
    Ok(())
}

#[test]
fn either_node_order_may_make_a_bounded_recovery_attempt() {
    let active = BTreeMap::new();
    let lower = NodeId::from_bytes([1; 32]);
    let higher = NodeId::from_bytes([255; 32]);
    assert!(should_attempt_peer(&active, lower, higher, 0));
    assert!(!should_attempt_peer(&active, higher, lower, 0));
    assert!(should_attempt_peer(
        &active,
        higher,
        lower,
        SECONDARY_RECOVERY_CADENCE - 1
    ));
}

#[test]
fn current_contact_is_retried_three_times_before_each_historical_hint() {
    assert_eq!(dial_hint_index(0, 4), 0);
    assert_eq!(dial_hint_index(1, 4), 0);
    assert_eq!(dial_hint_index(2, 4), 0);
    assert_eq!(dial_hint_index(3, 4), 1);
    assert_eq!(dial_hint_index(7, 4), 2);
    assert_eq!(dial_hint_index(11, 4), 3);
    assert_eq!(dial_hint_index(15, 4), 1);
    assert_eq!(dial_hint_index(3, 1), 0);
}

#[test]
fn stale_connection_events_cannot_remove_a_replacement_session() {
    assert!(connection_event_is_current(Some(41), 41));
    assert!(!connection_event_is_current(Some(42), 41));
    assert!(!connection_event_is_current(None, 41));
}

#[test]
fn candidate_racing_is_immediate_then_tightly_staggered() {
    assert_eq!(candidate_race_delay(0), Duration::ZERO);
    assert_eq!(
        candidate_race_delay(3),
        Duration::from_millis(CANDIDATE_RACE_DELAY_MILLIS * 3)
    );
}
