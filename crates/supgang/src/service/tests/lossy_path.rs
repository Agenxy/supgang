//! A tunnel across an ocean from a network that drops a few percent of UDP
//! datagrams, as hotel and café networks do. Loss-based congestion control
//! reads every such drop as congestion: in this scenario it moved 1 MiB each
//! way in about 30 s (35 kB/s), matching a tunnel measured from a French
//! hotel on 2026-10-20 while TCP on the same network ran at 13.5 MB/s.
//! Supgang's transport uses model-based congestion control (BBR), which
//! moved the same megabyte in about 2.3 s.

use std::{
    io::{Read as _, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use super::sim_harness::{
    Error, Fleet, PORT, add_mapped, connection, eventually, expose_echo, open_tunnel, wait_connected,
};
use crate::{
    cli_peer_types::PathStatistics,
    control::{ControlReply, ControlRequest},
    ids::NodeId,
    simnet::{IpFamily, Nat44, Network, SiteSpec, V4Access},
};

const SOLIS: usize = 0;
const LAPTOP: usize = 1;
const HOME_PUBLIC: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
/// Two percent of datagrams dropped at the hotel, each way.
const LOSS_PERMILLE: u16 = 20;
/// Far above the 2.3 s measured, far below loss-based control's 30 s.
const BOUND: Duration = Duration::from_secs(10);

fn site(public: Ipv4Addr, lan: Ipv4Addr, nat: Nat44) -> SiteSpec {
    SiteSpec {
        v4: Some(V4Access::Translated { public, lan, nat }),
        v6: None,
    }
}

#[test]
fn a_tunnel_from_a_lossy_hotel_across_an_ocean_keeps_its_throughput() -> Result<(), Error> {
    let network = Network::new(52);
    let home = network.add_site(site(HOME_PUBLIC, Ipv4Addr::new(192, 168, 1, 0), Nat44::home_router()))?;
    let solis = network.add_host(Some(home))?;
    let laptop = network.add_host(Some(home))?;
    network.forward_udp(home, PORT, solis, PORT)?;
    let mut fleet = Fleet::pair(Arc::clone(&network), &[solis, laptop])?;
    fleet.start_all()?;
    wait_connected(&fleet, LAPTOP, SOLIS, Duration::from_secs(30))?.ok_or("no connection at home")?;
    add_mapped(fleet.computer(SOLIS)?, SocketAddrV4::new(HOME_PUBLIC, PORT))?;
    super::sim_harness::wait_mapped(&fleet, LAPTOP, SOLIS, SocketAddrV4::new(HOME_PUBLIC, PORT))?;
    let echo = expose_echo(fleet.computer(SOLIS)?, "ssh")?;
    wait_connected(&fleet, LAPTOP, SOLIS, Duration::from_mins(1))?.ok_or("no connection after exposure")?;

    let hotel = network.add_site(site(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 20, 0, 0),
        Nat44::symmetric(),
    ))?;
    network.set_latency(home, Duration::from_millis(10))?;
    network.set_latency(hotel, Duration::from_millis(65))?;
    network.move_host(laptop, Some(hotel))?;
    let forward = SocketAddr::new(IpAddr::V4(HOME_PUBLIC), PORT);
    eventually(Duration::from_mins(1), || {
        Ok(connection(fleet.computer(LAPTOP)?, fleet.computer(SOLIS)?.node)?.filter(|path| *path == forward))
    })?
    .ok_or("no connection from the hotel")?;
    network.set_loss_permille(hotel, LOSS_PERMILLE)?;

    let payload = (0..1_usize << 20)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect::<Vec<_>>();
    let started = std::time::Instant::now();
    let mut stream = open_tunnel(fleet.computer(LAPTOP)?, fleet.computer(SOLIS)?.node, "ssh")?;
    stream.write_all(&payload)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut returned = Vec::with_capacity(payload.len());
    stream.read_to_end(&mut returned)?;
    let elapsed = started.elapsed();
    echo.join().map_err(|_| "echo server panicked")??;
    assert!(returned == payload, "the lossy path altered or truncated the bytes");
    assert!(
        elapsed < BOUND,
        "1 MiB each way took {elapsed:?} at 150 ms with {LOSS_PERMILLE}‰ loss"
    );
    Ok(())
}

/// A brief stall, longer than one contact exchange may take but shorter than
/// the silence a dead path shows, must not end the session or the tunnels on
/// it. On 20 October one failed exchange ended a laptop's session and with it
/// every SSH master riding it.
#[test]
fn a_tunnel_survives_a_stall_longer_than_one_contact_exchange() -> Result<(), Error> {
    let network = Network::new(53);
    let home = network.add_site(site(HOME_PUBLIC, Ipv4Addr::new(192, 168, 1, 0), Nat44::home_router()))?;
    let solis = network.add_host(Some(home))?;
    let laptop = network.add_host(Some(home))?;
    network.forward_udp(home, PORT, solis, PORT)?;
    let mut fleet = Fleet::pair(Arc::clone(&network), &[solis, laptop])?;
    fleet.start_all()?;
    wait_connected(&fleet, LAPTOP, SOLIS, Duration::from_secs(30))?.ok_or("no connection at home")?;
    add_mapped(fleet.computer(SOLIS)?, SocketAddrV4::new(HOME_PUBLIC, PORT))?;
    super::sim_harness::wait_mapped(&fleet, LAPTOP, SOLIS, SocketAddrV4::new(HOME_PUBLIC, PORT))?;
    let echo = expose_echo(fleet.computer(SOLIS)?, "ssh")?;
    wait_connected(&fleet, LAPTOP, SOLIS, Duration::from_mins(1))?.ok_or("no connection after exposure")?;
    let hotel = network.add_site(site(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 20, 0, 0),
        Nat44::symmetric(),
    ))?;
    network.move_host(laptop, Some(hotel))?;
    let forward = SocketAddr::new(IpAddr::V4(HOME_PUBLIC), PORT);
    eventually(Duration::from_mins(1), || {
        Ok(connection(fleet.computer(LAPTOP)?, fleet.computer(SOLIS)?.node)?.filter(|path| *path == forward))
    })?
    .ok_or("no connection from the hotel")?;

    // An SSH master's stream, open before the stall.
    let mut master = open_tunnel(fleet.computer(LAPTOP)?, fleet.computer(SOLIS)?.node, "ssh")?;
    master.write_all(b"before")?;
    network.set_loss_permille(hotel, 1_000)?;
    std::thread::sleep(Duration::from_secs(13));
    network.set_loss_permille(hotel, 0)?;
    master.write_all(b" and after")?;
    master.shutdown(std::net::Shutdown::Write)?;
    let mut returned = Vec::new();
    master.read_to_end(&mut returned)?;
    echo.join().map_err(|_| "echo server panicked")??;
    assert_eq!(returned, b"before and after", "the stall ended the tunnel");
    Ok(())
}

fn path_stats(computer: &super::sim_harness::Computer, peer: NodeId) -> Result<Option<PathStatistics>, Error> {
    let Some(ControlReply::Peers { value }) = crate::control::request(&computer.path, ControlRequest::Peers)? else {
        return Ok(None);
    };
    Ok(value
        .peers
        .into_iter()
        .find(|row| row.node_id == peer.to_string() && row.connected == Some(true))
        .and_then(|row| row.connection)
        .and_then(|connection| connection.path))
}

/// Repeated PMTU black holes do not mean a path carrying application bytes is
/// dead. An SSH master held through all three events must remain usable even
/// after the old reconnect deadline, when no other candidate authenticates.
#[test]
fn repeated_mtu_black_holes_keep_the_live_session_and_held_tunnel() -> Result<(), Error> {
    let network = Network::new(54);
    let home = network.add_site(site(HOME_PUBLIC, Ipv4Addr::new(192, 168, 1, 0), Nat44::home_router()))?;
    let solis = network.add_host(Some(home))?;
    let laptop = network.add_host(Some(home))?;
    network.forward_udp(home, PORT, solis, PORT)?;
    let mut fleet = Fleet::pair(Arc::clone(&network), &[solis, laptop])?;
    fleet.start_all()?;
    wait_connected(&fleet, LAPTOP, SOLIS, Duration::from_secs(30))?.ok_or("no connection at home")?;
    add_mapped(fleet.computer(SOLIS)?, SocketAddrV4::new(HOME_PUBLIC, PORT))?;
    super::sim_harness::wait_mapped(&fleet, LAPTOP, SOLIS, SocketAddrV4::new(HOME_PUBLIC, PORT))?;
    let echo = super::sim_harness::expose_echo_with_timeout(fleet.computer(SOLIS)?, "ssh", Duration::from_mins(8))?;
    wait_connected(&fleet, LAPTOP, SOLIS, Duration::from_mins(1))?.ok_or("no connection after exposure")?;
    let hotel = network.add_site(site(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 20, 0, 0),
        Nat44::symmetric(),
    ))?;
    fleet.stop(LAPTOP)?;
    network.move_host(laptop, Some(hotel))?;
    fleet.start(LAPTOP)?;
    let remote = fleet.computer(SOLIS)?.node;
    let forward = SocketAddr::new(IpAddr::V4(HOME_PUBLIC), PORT);
    eventually(Duration::from_mins(1), || {
        Ok(connection(fleet.computer(LAPTOP)?, remote)?.filter(|path| *path == forward))
    })?
    .ok_or("no connection from the hotel")?;
    let mut master = open_tunnel(fleet.computer(LAPTOP)?, remote, "ssh")?;
    master.write_all(b"before")?;

    for count in 1..=3 {
        let mut last_stats = None;
        // Quinn waits one minute after a detected black hole before probing
        // again, even when the path becomes clear immediately.
        let found = eventually(Duration::from_secs(75), || {
            master.write_all(&[b'p'; 8 * 1024])?;
            last_stats = path_stats(fleet.computer(LAPTOP)?, remote)?;
            Ok(last_stats.clone().filter(|stats| stats.current_mtu > 1_200))
        })?;
        if found.is_none() {
            return Err(format!(
                "PMTU discovery did not find the clear path: {last_stats:?}; network: {:?}",
                network.stats()?
            )
            .into());
        }
        network.set_family_mtu(hotel, IpFamily::V4, Some(1_200))?;
        eventually(Duration::from_secs(30), || {
            master.write_all(&[b'x'; 8 * 1024])?;
            Ok(path_stats(fleet.computer(LAPTOP)?, remote)?.filter(|stats| stats.black_holes_detected >= count))
        })?
        .ok_or("the live path did not report the expected MTU black hole")?;
        assert_eq!(connection(fleet.computer(LAPTOP)?, remote)?, Some(forward));
        network.set_family_mtu(hotel, IpFamily::V4, None)?;
    }

    std::thread::sleep(Duration::from_secs(50));
    assert_eq!(connection(fleet.computer(LAPTOP)?, remote)?, Some(forward));
    master.write_all(b" and after")?;
    master.shutdown(std::net::Shutdown::Write)?;
    let mut returned = Vec::new();
    master.read_to_end(&mut returned)?;
    echo.join().map_err(|_| "echo server panicked")??;
    assert!(returned.starts_with(b"before"));
    assert!(
        returned.ends_with(b" and after"),
        "the held tunnel was cut after the black holes"
    );
    Ok(())
}
