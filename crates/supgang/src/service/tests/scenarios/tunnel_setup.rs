//! Tunnel setup outcomes over the simulated network.

use super::{
    Error, HomeGateway, Ipv6Policy, LAPTOP, PAIRING, ROAMING, SOLIS, cellular_site, connection, eventually,
    open_tunnel, paired_at_home, publish_forward, wait_connected,
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

fn peer_tunnel_counts(
    computer: &super::super::sim_harness::Computer,
    peer: crate::ids::NodeId,
) -> Result<Option<(usize, usize)>, Error> {
    let Some(crate::control::ControlReply::Peers { value }) =
        crate::control::request(&computer.path, crate::control::ControlRequest::Peers)?
    else {
        return Ok(None);
    };
    let peer = peer.to_string();
    Ok(value
        .peers
        .into_iter()
        .find(|row| row.node_id == peer && row.connected == Some(true))
        .and_then(|row| row.connection)
        .and_then(|connection| connection.active_tunnels.zip(connection.tunnel_limit)))
}

#[test]
fn a_peer_at_its_tunnel_limit_refuses_immediately_and_reports_occupancy() -> Result<(), Error> {
    let mut world = paired_at_home(
        HomeGateway {
            ipv4_forward: false,
            ipv6: Ipv6Policy::DefaultDeny,
        },
        104,
    )?;
    // Raise only the caller's per-peer limit so the remote peer's default limit
    // of 4 is the bottleneck, matching an asymmetric fleet configuration.
    world.fleet.set_tunnel_limits(LAPTOP, 16, 32)?;
    world.fleet.stop(LAPTOP)?;
    world.fleet.start(LAPTOP)?;
    wait_connected(&world.fleet, LAPTOP, SOLIS, PAIRING)?.ok_or("peers did not reconnect after limit change")?;
    let solis = world.fleet.computer(SOLIS)?;
    let laptop = world.fleet.computer(LAPTOP)?;
    let echo = super::super::sim_harness::expose_echoes(solis, "ssh", 5)?;

    let mut held = Vec::new();
    for index in 0..4 {
        let mut stream = open_tunnel(laptop, solis.node, "ssh")?;
        stream.write_all(format!("held-{index}").as_bytes())?;
        held.push(stream);
    }

    assert_eq!(peer_tunnel_counts(solis, laptop.node)?, Some((4, 4)));
    assert_eq!(peer_tunnel_counts(laptop, solis.node)?, Some((4, 16)));
    let Some(crate::control::ControlReply::Exposures { value: exposures }) =
        crate::control::request(&solis.path, crate::control::ControlRequest::Exposures)?
    else {
        return Err("exposures reply missing".into());
    };
    assert_eq!(exposures.limits.active_tunnels, Some(4));
    assert_eq!(exposures.limits.active_total, Some(16));

    let Some(crate::control::ControlReply::Status { value: before_status }) =
        crate::control::request(&laptop.path, crate::control::ControlRequest::Status)?
    else {
        return Err("status reply missing".into());
    };
    let name = crate::tunnel_policy::encoded_name(&crate::record::ServiceName::new("ssh")?);
    let start = Instant::now();
    let mut message = Vec::new();
    let fifth = crate::cli_tunnel::wait_for_tunnel(
        &laptop.path,
        solis.node,
        "solis",
        name,
        start + Duration::from_secs(45),
        &mut message,
    );
    let refusal = fifth.err().ok_or("fifth tunnel bypassed remote peer limit")?;
    assert_eq!(refusal, crate::control::PEER_AT_CAPACITY);
    assert_eq!(
        crate::cli_tunnel::connect_failure_code(&refusal),
        std::process::ExitCode::from(3)
    );
    assert!(start.elapsed() < Duration::from_secs(5), "capacity refusal was retried");
    assert!(
        message.is_empty(),
        "capacity refusal falsely announced a reconnect: {}",
        String::from_utf8_lossy(&message)
    );
    let Some(crate::control::ControlReply::Status { value: after_status }) =
        crate::control::request(&laptop.path, crate::control::ControlRequest::Status)?
    else {
        return Err("status reply missing".into());
    };
    assert_eq!(
        before_status.recent_connections, after_status.recent_connections,
        "capacity refusal disturbed the live session"
    );

    // Releasing one held tunnel frees a slot on the same session without reconnecting.
    let mut freed = held.remove(0);
    freed.shutdown(std::net::Shutdown::Write)?;
    let mut echoed = Vec::new();
    freed.read_to_end(&mut echoed)?;
    assert_eq!(echoed, b"held-0");
    drop(freed);
    eventually(Duration::from_secs(5), || {
        Ok((peer_tunnel_counts(solis, laptop.node)? == Some((3, 4))).then_some(()))
    })?
    .ok_or("remote active tunnel count did not drop after closing a tunnel")?;

    let mut message = Vec::new();
    let mut recovered = crate::cli_tunnel::wait_for_tunnel(
        &laptop.path,
        solis.node,
        "solis",
        name,
        Instant::now() + Duration::from_secs(15),
        &mut message,
    )?;
    assert_eq!(String::from_utf8_lossy(&message), "");
    recovered.set_nonblocking(false)?;
    recovered.set_read_timeout(Some(Duration::from_secs(20)))?;
    recovered.write_all(b"recovered")?;
    recovered.shutdown(std::net::Shutdown::Write)?;
    let mut returned = Vec::new();
    recovered.read_to_end(&mut returned)?;
    assert_eq!(returned, b"recovered");
    for (offset, mut stream) in held.into_iter().enumerate() {
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut returned = Vec::new();
        stream.read_to_end(&mut returned)?;
        assert_eq!(returned, format!("held-{}", offset + 1).as_bytes());
    }
    echo.join().map_err(|_| "echo server panicked")??;
    Ok(())
}

#[test]
fn black_holed_ipv6_recovers_to_new_ipv4_for_tunnel() -> Result<(), Error> {
    let world = paired_at_home(
        HomeGateway {
            ipv4_forward: true,
            ipv6: Ipv6Policy::Pinhole,
        },
        105,
    )?;
    let solis = world.fleet.computer(SOLIS)?;
    let laptop = world.fleet.computer(LAPTOP)?;
    let away = world.network.add_site(cellular_site())?;
    world.network.set_family_loss_permille(away, IpFamily::V4, 1_000)?;
    world.network.move_host(laptop.host, Some(away))?;
    eventually(ROAMING, || {
        let local = connection(laptop, solis.node)?;
        let remote = connection(solis, laptop.node)?;
        Ok(local.filter(|address| address.is_ipv6() && remote.is_some_and(|address| address.is_ipv6())))
    })?
    .ok_or("peers did not establish the initial IPv6 session")?;
    let echo = super::super::sim_harness::expose_echo_with_timeout(solis, "ssh", Duration::from_mins(1))?;

    // Solis gains a published IPv4 address while the old IPv6 path black-holes.
    publish_forward(&world)?;
    world.network.set_family_loss_permille(away, IpFamily::V4, 0)?;
    world.network.set_family_loss_permille(away, IpFamily::V6, 1_000)?;

    let name = crate::tunnel_policy::encoded_name(&crate::record::ServiceName::new("ssh")?);
    let mut message = Vec::new();
    let mut stream = crate::cli_tunnel::wait_for_tunnel(
        &laptop.path,
        solis.node,
        "solis",
        name,
        Instant::now() + Duration::from_secs(45),
        &mut message,
    )?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.write_all(b"recovered")?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut returned = Vec::new();
    stream.read_to_end(&mut returned)?;
    assert_eq!(returned, b"recovered");
    assert!(connection(laptop, solis.node)?.is_some_and(|address| address.is_ipv4()));
    echo.join().map_err(|_| "echo server panicked")??;
    Ok(())
}
