use std::{
    cell::Cell,
    process::ExitCode,
    time::{Duration, Instant},
};

use super::{LimitChanges, connect_failure_code, limits, wait_for_peer};
use crate::{control, state, tunnel_policy};

const SHORT: Duration = Duration::from_millis(1);

#[test]
fn connect_waits_through_a_reconnect_and_announces_once() {
    let attempts = Cell::new(0);
    let announcements = Cell::new(0);
    let result = wait_for_peer(
        Instant::now() + Duration::from_secs(5),
        SHORT,
        || {
            attempts.set(attempts.get() + 1);
            match attempts.get() {
                1 => Err(control::PEER_NOT_CONNECTED.to_owned()),
                2 => Err(control::PEER_AUTHORIZATION_LAPSED.to_owned()),
                3 => Err(control::PEER_SESSION_FAILED.to_owned()),
                4 => Err(control::LEGACY_SETUP_FAILED.to_owned()),
                _ => Ok("stream"),
            }
        },
        || announcements.set(announcements.get() + 1),
    );
    assert_eq!(result, Ok("stream"));
    assert_eq!((attempts.get(), announcements.get()), (5, 1));
}

#[test]
fn legacy_setup_reply_is_transient_even_when_the_old_service_cannot_disambiguate_it() {
    assert_eq!(connect_failure_code(control::LEGACY_SETUP_FAILED), ExitCode::from(75));
    assert_ne!(connect_failure_code(control::LEGACY_SETUP_FAILED), ExitCode::from(3));
}

#[test]
fn connect_exit_codes_distinguish_transient_failure_from_refusal() {
    for message in [
        control::PEER_NOT_CONNECTED,
        control::PEER_AUTHORIZATION_LAPSED,
        control::PEER_SESSION_FAILED,
        control::LEGACY_SETUP_FAILED,
        "local Supgang service is unavailable",
        "start the local Supgang service before connecting",
    ] {
        assert_eq!(connect_failure_code(message), ExitCode::from(75), "{message}");
    }
    let unresponsive = control::ControlError::Unresponsive { seconds: 10 }.to_string();
    assert_eq!(connect_failure_code(&unresponsive), ExitCode::from(75));
    for message in [
        "the peer refused the service; check its exposure and runtime version",
        "the peer is revoked; tunnels to it are refused",
        "every tunnel allowed to this peer is in use",
        "no known peer with that name",
        "service name is invalid",
    ] {
        assert_eq!(connect_failure_code(message), ExitCode::from(3), "{message}");
    }
}

#[test]
fn connect_returns_any_other_refusal_at_once() {
    let attempts = Cell::new(0);
    let result: Result<(), _> = wait_for_peer(
        Instant::now() + Duration::from_secs(5),
        SHORT,
        || {
            attempts.set(attempts.get() + 1);
            Err("the peer is revoked; tunnels to it are refused".to_owned())
        },
        || {},
    );
    assert!(result.is_err());
    assert_eq!(attempts.get(), 1);
}

#[test]
fn connect_stops_waiting_at_its_bound() {
    let attempts = Cell::new(0_u32);
    let result: Result<(), _> = wait_for_peer(
        Instant::now() + Duration::from_millis(30),
        Duration::from_millis(5),
        || {
            attempts.set(attempts.get() + 1);
            Err(control::PEER_NOT_CONNECTED.to_owned())
        },
        || {},
    );
    assert_eq!(result, Err(control::PEER_NOT_CONNECTED.to_owned()));
    assert!((2..=8).contains(&attempts.get()), "{}", attempts.get());
}

#[test]
fn tunnel_limits_without_changes_keeps_the_saved_limits() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    drop(state::initialize(&directory)?);
    let mut sink = Vec::new();
    let set = |changes, sink: &mut Vec<u8>| limits(&directory, changes, true, &mut Vec::new(), sink);
    let raised = LimitChanges {
        per_peer: Some(40),
        total: Some(64),
        idle_seconds: Some(86_400),
    };
    assert_eq!(set(raised, &mut sink), ExitCode::SUCCESS);
    assert_eq!(set(LimitChanges::default(), &mut sink), ExitCode::SUCCESS);
    let policy = tunnel_policy::load(&directory)?;
    assert_eq!((policy.per_peer, policy.total, policy.idle_seconds), (40, 64, 86_400));
    let total_only = LimitChanges {
        total: Some(32),
        ..LimitChanges::default()
    };
    assert_eq!(set(total_only, &mut sink), ExitCode::SUCCESS);
    let policy = tunnel_policy::load(&directory)?;
    assert_eq!((policy.per_peer, policy.total, policy.idle_seconds), (40, 32, 86_400));
    Ok(())
}
