use std::{net::SocketAddr, time::Duration};

use super::{ServiceConfig, ServiceError, apply_reflexive_observation};

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
fn only_global_authenticated_observations_become_reflexive_candidates() -> Result<(), Box<dyn std::error::Error>> {
    let listen = SocketAddr::from(([0, 0, 0, 0], 4_433));
    let mut config = ServiceConfig::new(name(), listen, &[SocketAddr::from(([127, 0, 0, 1], 4_433))], &[])?;
    assert!(!apply_reflexive_observation(
        &mut config,
        SocketAddr::from(([127, 0, 0, 1], 50_000))
    ));
    assert!(apply_reflexive_observation(
        &mut config,
        SocketAddr::from(([8, 8, 8, 8], 50_000))
    ));
    assert!(!apply_reflexive_observation(
        &mut config,
        SocketAddr::from(([8, 8, 8, 8], 50_000))
    ));
    assert_eq!(config.candidates.len(), 2);
    Ok(())
}
