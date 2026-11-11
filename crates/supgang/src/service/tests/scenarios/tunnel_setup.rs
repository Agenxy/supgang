//! Tunnel setup outcomes over the simulated network.

use super::{Error, HomeGateway, Ipv6Policy, LAPTOP, SOLIS, connection, paired_at_home};
use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

#[test]
fn a_stale_session_never_looks_like_a_peer_refusal() -> Result<(), Error> {
    let world = paired_at_home(
        HomeGateway {
            ipv4_forward: false,
            ipv6: Ipv6Policy::DefaultDeny,
        },
        101,
    )?;
    let solis = world.fleet.computer(SOLIS)?;
    let laptop = world.fleet.computer(LAPTOP)?;
    assert!(connection(laptop, solis.node)?.is_some());
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let name = crate::tunnel_policy::encoded_name(&crate::record::ServiceName::new("ssh")?);
    assert!(matches!(
        crate::control::request(&solis.path, crate::control::ControlRequest::Expose { name, port })?,
        Some(crate::control::ControlReply::ExposureChanged)
    ));
    // Cut every packet while the laptop still reports its old session. The
    // service must retire that path or the client's whole deadline must end.
    world.network.move_host(solis.host, None)?;
    assert!(connection(laptop, solis.node)?.is_some());
    let start = Instant::now();
    let mut message = Vec::new();
    let result = crate::cli_tunnel::wait_for_tunnel(
        &laptop.path,
        solis.node,
        "solis",
        name,
        start + Duration::from_secs(45),
        &mut message,
    );
    let (code, detail) = match result {
        Ok(_stream) => (std::process::ExitCode::SUCCESS, String::new()),
        Err(refusal) => (crate::cli_tunnel::connect_failure_code(&refusal), refusal),
    };
    assert_eq!(
        code,
        std::process::ExitCode::from(75),
        "stale session did not return transient exit 75: {detail}; {}",
        String::from_utf8_lossy(&message)
    );
    assert!(
        start.elapsed() <= Duration::from_secs(48),
        "setup exceeded the 45 s deadline with slack"
    );
    Ok(())
}

#[test]
fn an_unexposed_service_is_refused_without_a_retry() -> Result<(), Error> {
    let world = paired_at_home(
        HomeGateway {
            ipv4_forward: false,
            ipv6: Ipv6Policy::DefaultDeny,
        },
        102,
    )?;
    let solis = world.fleet.computer(SOLIS)?;
    let laptop = world.fleet.computer(LAPTOP)?;
    let name = crate::tunnel_policy::encoded_name(&crate::record::ServiceName::new("ssh")?);
    let start = Instant::now();
    let mut message = Vec::new();
    let result = crate::cli_tunnel::wait_for_tunnel(
        &laptop.path,
        solis.node,
        "solis",
        name,
        start + Duration::from_secs(45),
        &mut message,
    );
    let refusal = result.err().ok_or("unexposed service was accepted")?;
    assert!(refusal.contains("peer refused the service"), "{refusal}");
    assert_eq!(
        crate::cli_tunnel::connect_failure_code(&refusal),
        std::process::ExitCode::from(3)
    );
    assert!(start.elapsed() < Duration::from_secs(2), "peer refusal was retried");
    assert!(message.is_empty(), "peer refusal announced a reconnect");
    Ok(())
}
