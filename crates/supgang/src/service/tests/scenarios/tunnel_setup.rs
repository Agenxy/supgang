//! Tunnel setup outcomes over the simulated network.

use super::{
    Error, HomeGateway, Ipv6Policy, LAPTOP, ROAMING, SOLIS, cellular_site, connection, eventually, open_tunnel,
    paired_at_home,
};
use std::{
    io::{Read as _, Write as _},
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use crate::simnet::IpFamily;

#[test]
fn a_missed_setup_probe_preserves_an_existing_tunnel() -> Result<(), Error> {
    let world = paired_at_home(
        HomeGateway {
            ipv4_forward: false,
            ipv6: Ipv6Policy::Pinhole,
        },
        103,
    )?;
    let solis = world.fleet.computer(SOLIS)?;
    let laptop = world.fleet.computer(LAPTOP)?;
    let away = world.network.add_site(cellular_site())?;
    world.network.move_host(laptop.host, Some(away))?;
    eventually(ROAMING, || {
        let local = connection(laptop, solis.node)?;
        let remote = connection(solis, laptop.node)?;
        Ok(local.filter(|address| address.is_ipv6() && remote.is_some_and(|address| address.is_ipv6())))
    })?
    .ok_or("both peers did not establish the off-network IPv6 session")?;
    let echo = super::super::sim_harness::expose_echo_with_timeout(solis, "ssh", Duration::from_mins(1))?;
    let mut held = open_tunnel(laptop, solis.node, "ssh")?;
    held.write_all(b"before")?;

    // The path stops answering long enough for setup and its datagram probe
    // to fail, but recovers before the transport's idle deadline.
    world.network.set_family_loss_permille(away, IpFamily::V6, 1_000)?;
    let failed_setup = open_tunnel(laptop, solis.node, "absent");
    world.network.set_family_loss_permille(away, IpFamily::V6, 0)?;
    let refusal = failed_setup.err().ok_or("the lost setup unexpectedly connected")?;
    assert_eq!(refusal.to_string(), crate::control::PEER_SESSION_FAILED);

    held.write_all(b" and after")?;
    held.shutdown(std::net::Shutdown::Write)?;
    let mut returned = Vec::new();
    held.read_to_end(&mut returned)?;
    assert_eq!(returned, b"before and after", "setup failure cut the held tunnel");
    echo.join().map_err(|_| "echo server panicked")??;
    Ok(())
}

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
