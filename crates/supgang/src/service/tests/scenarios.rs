//! Travel scenarios: the owner pairs a laptop with a home computer at home,
//! then takes the laptop to networks it does not control. Each scenario runs
//! the production service on both computers over a simulated Internet and
//! asserts the outcome the topology permits: an authenticated connection on
//! the expected path and working tunnel bytes, or honest unreachability with
//! the gateway that refused it identified.
//!
//! The public addresses are fixtures. Nothing here opens an operating-system
//! UDP socket; the tunnel's last hop is a loopback TCP echo server, as the
//! installed service's is a loopback SSH server.

use std::{
    io::{Read as _, Write as _},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use super::sim_harness::{
    Error, Fleet, PORT, add_mapped, connection, eventually, expose_echo, open_tunnel, tunnel_round_trip,
    wait_connected, wait_mapped,
};
use crate::simnet::{Discard, Firewall6, IpFamily, Nat44, Network, SiteId, SiteSpec, V4Access, V6Access};

const HOME_PUBLIC: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
const HOME_PREFIX: Ipv6Addr = Ipv6Addr::new(0x2600, 1, 2, 3, 0, 0, 0, 0);
const CELLULAR_PREFIX: Ipv6Addr = Ipv6Addr::new(0x2607, 4, 5, 6, 0, 0, 0, 0);
const SOLIS: usize = 0;
const LAPTOP: usize = 1;
/// Pairing at home includes an initial retry round and handshake.
const PAIRING: Duration = Duration::from_secs(30);
/// After the laptop retires its departed path, a connection over the new
/// network must form within this bound. The home computer probes its own
/// connection over the departed path when the laptop authenticates from a new
/// one, and retires it at once if it no longer answers (`service::liveness`),
/// instead of refusing the new connection until QUIC's idle timeout.
const ROAMING: Duration = Duration::from_secs(15);
/// An abruptly stopped peer sends no close; the survivor learns of it from
/// QUIC's 45-second idle timeout, then redials. This bounds that, not roaming.
const CRASH_RECOVERY: Duration = Duration::from_secs(90);
/// Back on the home LAN, a connection through the public forward keeps
/// working by hairpin; the laptop dials the directly attached path anyway and
/// that connection supersedes the indirect one on both sides.
const RETURN_HOME: Duration = ROAMING;
/// How long an unreachable topology is watched for a false connection.
const REFUSAL_WATCH: Duration = Duration::from_secs(25);
/// The quality monitor and one authenticated replacement dial fit in this window.
const QUALITY_MIGRATION: Duration = Duration::from_secs(45);

#[test]
fn a_live_but_degraded_ipv6_path_moves_to_clean_ipv4() -> Result<(), Error> {
    let world = paired_at_home(
        HomeGateway {
            ipv4_forward: true,
            ipv6: Ipv6Policy::Pinhole,
        },
        71,
    )?;
    publish_forward(&world)?;
    let echo =
        super::sim_harness::expose_echoes_with_timeout(world.fleet.computer(SOLIS)?, "ssh", 2, Duration::from_mins(3))?;
    let away = world.network.add_site(cellular_site())?;
    // Make IPv6 the only usable path for the first off-network connection.
    world.network.set_family_loss_permille(away, IpFamily::V4, 1_000)?;
    let solis = world.fleet.computer(SOLIS)?;
    let laptop = world.fleet.computer(LAPTOP)?;
    world.network.move_host(laptop.host, Some(away))?;
    eventually(ROAMING, || {
        Ok(connection(laptop, solis.node)?.filter(SocketAddr::is_ipv6))
    })?
    .ok_or("the laptop did not establish the initial IPv6 session")?;
    let mut master = open_tunnel(laptop, solis.node, "ssh")?;
    master
        .write_all(b"before")
        .map_err(|error| format!("held tunnel before migration: {error}"))?;

    // IPv6 remains alive but becomes 1.5 seconds slower round-trip. IPv4 is
    // available through the same previously published, signed peer record.
    world.network.set_family_loss_permille(away, IpFamily::V4, 0)?;
    world
        .network
        .set_family_latency(away, IpFamily::V6, Duration::from_millis(750))?;
    // Keep this case about RTT-driven migration; the separate PMTU scenario
    // exercises black-hole recovery while a tunnel remains on one path.
    eventually(QUALITY_MIGRATION, || {
        Ok(connection(laptop, solis.node)?.filter(SocketAddr::is_ipv4))
    })?
    .ok_or("the authenticated IPv4 alternative did not supersede degraded IPv6")?;
    eventually(Duration::from_secs(5), || {
        Ok(connection(solis, laptop.node)?.filter(SocketAddr::is_ipv4))
    })?
    .ok_or("the home peer did not retain the same IPv4 replacement")?;
    assert_eq!(
        tunnel_round_trip(laptop, solis.node, "ssh", b"new tunnel")?,
        b"new tunnel"
    );
    master
        .write_all(b" and after")
        .map_err(|error| format!("held tunnel after migration: {error}"))?;
    master
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| format!("held tunnel shutdown: {error}"))?;
    let mut returned = Vec::new();
    master
        .read_to_end(&mut returned)
        .map_err(|error| format!("held tunnel read: {error}"))?;
    assert_eq!(
        returned, b"before and after",
        "the held tunnel was cut during migration"
    );
    echo.join().map_err(|_| "echo server panicked")??;
    std::thread::sleep(Duration::from_secs(8));
    let laptop_after = connection(laptop, solis.node)?;
    assert!(
        laptop_after.is_some_and(|path| path.is_ipv4()),
        "laptop final path IPv4 status: {:?}",
        laptop_after.map(|path| path.is_ipv4())
    );
    assert!(connection(solis, laptop.node)?.is_some_and(|path| path.is_ipv4()));
    Ok(())
}

/// The old tunnel must survive when only the dialler considers an IPv4
/// replacement better. The receiving peer rejects that duplicate; its
/// shortened simulator drain deadline makes the former ten-minute failure
/// observable without a ten-minute test.
#[test]
fn asymmetric_rtt_rejection_preserves_the_old_tunnel_without_redial_loop() -> Result<(), Error> {
    let world = paired_at_home(
        HomeGateway {
            ipv4_forward: true,
            ipv6: Ipv6Policy::Pinhole,
        },
        72,
    )?;
    publish_forward(&world)?;
    let echo =
        super::sim_harness::expose_echo_with_timeout(world.fleet.computer(SOLIS)?, "ssh", Duration::from_mins(2))?;
    let away = world.network.add_site(cellular_site())?;
    world.network.set_family_loss_permille(away, IpFamily::V4, 1_000)?;
    let solis = world.fleet.computer(SOLIS)?;
    let laptop = world.fleet.computer(LAPTOP)?;
    world.network.move_host(laptop.host, Some(away))?;
    eventually(ROAMING, || {
        Ok(connection(laptop, solis.node)?.filter(SocketAddr::is_ipv6))
    })?
    .ok_or("the initial IPv6 session did not form")?;
    let mut master = open_tunnel(laptop, solis.node, "ssh")?;
    master.write_all(b"before")?;
    world.fleet.keep_old_rtt_view(SOLIS, Duration::from_secs(8))?;
    world.fleet.shorten_drain(LAPTOP, Duration::from_secs(8))?;
    let previous_candidates = world.fleet.replacement_attempts(SOLIS)?;
    world.network.set_family_loss_permille(away, IpFamily::V4, 0)?;
    world
        .network
        .set_family_latency(away, IpFamily::V6, Duration::from_millis(750))?;
    eventually(QUALITY_MIGRATION, || {
        Ok(
            (world.fleet.quality_dials(LAPTOP)? > 0 && world.fleet.replacement_attempts(SOLIS)? > previous_candidates)
                .then_some(()),
        )
    })?
    .ok_or("the quality alternative did not dial and authenticate")?;
    let quality_dials = world.fleet.quality_dials(LAPTOP)?;
    assert!(quality_dials > 0, "no quality replacement was dialled");
    // A rejected candidate cannot start a drain, and its quality retry gets
    // a cooldown longer than this observation window.
    std::thread::sleep(Duration::from_secs(20));
    assert_eq!(
        world.fleet.quality_dials(LAPTOP)?,
        quality_dials,
        "rejected candidate redialled"
    );
    assert!(connection(laptop, solis.node)?.is_some_and(|address| address.is_ipv6()));
    assert!(connection(solis, laptop.node)?.is_some_and(|address| address.is_ipv6()));
    master.write_all(b" and after")?;
    master.shutdown(std::net::Shutdown::Write)?;
    let mut returned = Vec::new();
    master.read_to_end(&mut returned)?;
    assert_eq!(
        returned, b"before and after",
        "the rejected replacement cut the held tunnel"
    );
    echo.join().map_err(|_| "echo server panicked")??;
    Ok(())
}

/// How the owner has configured the home gateway.
#[derive(Clone, Copy)]
struct HomeGateway {
    ipv4_forward: bool,
    ipv6: Ipv6Policy,
}

#[derive(Clone, Copy)]
enum Ipv6Policy {
    /// Unsolicited inbound IPv6 is admitted (the BGW320's Reflexive ACL off).
    Open,
    /// RFC 6092 default denial (Reflexive ACL on).
    DefaultDeny,
    /// Default denial with an inbound pinhole for Solis's UDP port.
    Pinhole,
}

struct World {
    network: Arc<Network>,
    home: SiteId,
    fleet: Fleet,
}

fn home_site(gateway: HomeGateway) -> SiteSpec {
    SiteSpec {
        v4: Some(V4Access::Translated {
            public: HOME_PUBLIC,
            lan: Ipv4Addr::new(192, 168, 1, 0),
            nat: Nat44::home_router(),
        }),
        v6: Some(V6Access {
            prefix: HOME_PREFIX,
            firewall: match gateway.ipv6 {
                Ipv6Policy::Open => Firewall6::Open,
                Ipv6Policy::DefaultDeny | Ipv6Policy::Pinhole => Firewall6::default_deny(),
            },
        }),
    }
}

/// A hotel or café: IPv4 only, behind a symmetric gateway.
fn hotel_site() -> SiteSpec {
    SiteSpec {
        v4: Some(V4Access::Translated {
            public: Ipv4Addr::new(8, 8, 8, 8),
            lan: Ipv4Addr::new(10, 20, 0, 0),
            nat: Nat44::symmetric(),
        }),
        v6: None,
    }
}

/// A phone hotspot: carrier-grade symmetric IPv4 and stateful native IPv6.
fn cellular_site() -> SiteSpec {
    SiteSpec {
        v4: Some(V4Access::Translated {
            public: Ipv4Addr::new(8, 8, 4, 4),
            lan: Ipv4Addr::new(10, 30, 0, 0),
            nat: Nat44::symmetric(),
        }),
        v6: Some(V6Access {
            prefix: CELLULAR_PREFIX,
            firewall: Firewall6::default_deny(),
        }),
    }
}

/// Pairs Solis and the laptop at home, starts both services, and waits for
/// them to connect, as the owner's computers are before a trip.
fn paired_at_home(gateway: HomeGateway, seed: u64) -> Result<World, Error> {
    let network = Network::new(seed);
    let home = network.add_site(home_site(gateway))?;
    let solis = network.add_host(Some(home))?;
    let laptop = network.add_host(Some(home))?;
    if gateway.ipv4_forward {
        network.forward_udp(home, PORT, solis, PORT)?;
    }
    if matches!(gateway.ipv6, Ipv6Policy::Pinhole) {
        network.pinhole_v6(home, solis, PORT)?;
    }
    let mut fleet = Fleet::pair(Arc::clone(&network), &[solis, laptop])?;
    fleet.start_all()?;
    wait_connected(&fleet, LAPTOP, SOLIS, PAIRING)?.ok_or("the computers never connected at home")?;
    Ok(World { network, home, fleet })
}

/// Publishes Solis's forwarded public IPv4 and waits until the laptop holds
/// it in Solis's signed record, as `supgang endpoint add-mapped` does at home.
fn publish_forward(world: &World) -> Result<(), Error> {
    let solis = world.fleet.computer(SOLIS)?;
    let mapped = SocketAddrV4::new(HOME_PUBLIC, PORT);
    add_mapped(solis, mapped)?;
    wait_mapped(&world.fleet, LAPTOP, SOLIS, mapped)
}

/// After a move, the connection over the old network must stop being
/// reported within this bound; the service polls interfaces every five seconds.
const STALE_PATH_RETIREMENT: Duration = Duration::from_secs(10);

/// Moves the laptop to a new site and waits until its service has noticed:
/// the connection made over the home LAN is no longer reported.
fn travel(world: &World, spec: SiteSpec) -> Result<(), Error> {
    let away = world.network.add_site(spec)?;
    let solis = world.fleet.computer(SOLIS)?;
    let laptop = world.fleet.computer(LAPTOP)?;
    let before = connection(laptop, solis.node)?.ok_or("not connected before travelling")?;
    world.network.move_host(laptop.host, Some(away))?;
    let retired = eventually(STALE_PATH_RETIREMENT, || {
        Ok(connection(laptop, solis.node)?
            .is_none_or(|path| path != before)
            .then_some(()))
    })?;
    assert!(
        retired.is_some(),
        "the connection over the home LAN was still reported {STALE_PATH_RETIREMENT:?} after leaving"
    );
    Ok(())
}

mod same_subnet;

/// A refused tunnel says which limit or state refused it and what to do, so
/// the owner can tell a full tunnel budget from a peer that is reconnecting.
#[test]
fn a_refused_tunnel_names_its_reason_and_the_remedy() -> Result<(), Error> {
    let mut world = paired_at_home(
        HomeGateway {
            ipv4_forward: false,
            ipv6: Ipv6Policy::DefaultDeny,
        },
        14,
    )?;
    world.fleet.set_tunnel_limits(LAPTOP, 1, 64)?;
    world.fleet.stop(LAPTOP)?;
    world.fleet.start(LAPTOP)?;
    wait_connected(&world.fleet, LAPTOP, SOLIS, PAIRING)?.ok_or("no reconnection after limits")?;
    let solis = world.fleet.computer(SOLIS)?.node;
    let echo = expose_echo(world.fleet.computer(SOLIS)?, "ssh")?;
    let held = eventually(ROAMING, || {
        Ok(open_tunnel(world.fleet.computer(LAPTOP)?, solis, "ssh").ok())
    })?
    .ok_or("the exposed service never accepted a tunnel")?;
    let Err(full) = open_tunnel(world.fleet.computer(LAPTOP)?, solis, "ssh") else {
        return Err("a tunnel beyond the per-peer limit was admitted".into());
    };
    assert!(full.to_string().contains("per-peer limit"), "{full}");
    held.shutdown(std::net::Shutdown::Both)?;
    drop(held);
    let _echo = echo.join();

    world.fleet.stop(SOLIS)?;
    let laptop = world.fleet.computer(LAPTOP)?;
    eventually(CRASH_RECOVERY, || {
        Ok(connection(laptop, solis)?.is_none().then_some(()))
    })?
    .ok_or("the laptop still reports the stopped computer")?;
    let Err(down) = open_tunnel(laptop, solis, "ssh") else {
        return Err("a tunnel to a stopped computer was admitted".into());
    };
    assert!(down.to_string().contains("not connected right now"), "{down}");
    Ok(())
}

/// The tunnel must carry bytes both ways through the connection that exists.
fn assert_tunnel(world: &World) -> Result<(), Error> {
    let solis = world.fleet.computer(SOLIS)?;
    let laptop = world.fleet.computer(LAPTOP)?;
    let echo = expose_echo(solis, "ssh")?;
    // Adding an exposure retains the established session; wait for both peers
    // to report it before opening the newly permitted service.
    wait_connected(&world.fleet, LAPTOP, SOLIS, ROAMING)?.ok_or("no connection after exposure")?;
    let Some(crate::control::ControlReply::Status { value }) =
        crate::control::request(&solis.path, crate::control::ControlRequest::Status)?
    else {
        return Err("no status after exposure".into());
    };
    assert!(
        value
            .recent_connections
            .iter()
            .all(|event| event.reason != "local tunnel policy changed"),
        "adding an exposure invalidated an established session"
    );
    let payload = (0..64 * 1024)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect::<Vec<_>>();
    let returned = tunnel_round_trip(laptop, solis.node, "ssh", &payload)?;
    echo.join().map_err(|_| "echo server panicked")??;
    assert_eq!(returned, payload, "the tunnel altered or truncated the bytes");
    Ok(())
}

fn assert_unreachable(world: &World) -> Result<(), Error> {
    let solis = world.fleet.computer(SOLIS)?;
    let laptop = world.fleet.computer(LAPTOP)?;
    let false_connection = eventually(REFUSAL_WATCH, || connection(laptop, solis.node))?;
    assert_eq!(false_connection, None, "a connection was reported where no path exists");
    Ok(())
}

fn connection_history(computer: &super::sim_harness::Computer) -> Result<Vec<crate::control::ConnectionEvent>, Error> {
    let Some(crate::control::ControlReply::Status { value }) =
        crate::control::request(&computer.path, crate::control::ControlRequest::Status)?
    else {
        return Err("no status for connection history".into());
    };
    Ok(value.recent_connections)
}

#[test]
fn at_home_the_laptop_reaches_solis_on_the_lan_and_the_tunnel_carries_bytes() -> Result<(), Error> {
    let world = paired_at_home(
        HomeGateway {
            ipv4_forward: false,
            ipv6: Ipv6Policy::DefaultDeny,
        },
        1,
    )?;
    let path = connection(world.fleet.computer(LAPTOP)?, world.fleet.computer(SOLIS)?.node)?.ok_or("not connected")?;
    // On the LAN the path stays inside the home: a private IPv4 or the home prefix.
    let inside = match path.ip() {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => address.segments().get(..4) == HOME_PREFIX.segments().get(..4),
    };
    assert!(inside, "LAN path left the home: {path}");
    assert_tunnel(&world)
}

#[test]
fn from_an_ipv4_only_hotel_the_laptop_reaches_solis_through_the_forward_then_returns_home() -> Result<(), Error> {
    let world = paired_at_home(
        HomeGateway {
            ipv4_forward: true,
            ipv6: Ipv6Policy::DefaultDeny,
        },
        2,
    )?;
    publish_forward(&world)?;
    travel(&world, hotel_site())?;
    let path = wait_connected(&world.fleet, LAPTOP, SOLIS, ROAMING)?.ok_or("no connection from the hotel")?;
    assert_eq!(path, SocketAddr::new(IpAddr::V4(HOME_PUBLIC), PORT));
    assert_tunnel(&world)?;

    let before_changes = world.fleet.interface_changes(LAPTOP)?;
    world
        .network
        .move_host(world.fleet.computer(LAPTOP)?.host, Some(world.home))?;
    let back = eventually(RETURN_HOME, || {
        let path = connection(world.fleet.computer(LAPTOP)?, world.fleet.computer(SOLIS)?.node)?;
        Ok(path.filter(|path| path.ip() != IpAddr::V4(HOME_PUBLIC)))
    })?;
    if back.is_none() {
        let laptop = world.fleet.computer(LAPTOP)?;
        let solis = world.fleet.computer(SOLIS)?;
        let after_changes = world.fleet.interface_changes(LAPTOP)?;
        return Err(format!(
            "the laptop did not return to the LAN path at home; laptop history {:?}; Solis history {:?}; \
             laptop recovery {:?}; Solis recovery {:?}; interface changes after move {}; quality dials {}; replacement attempts {}",
            connection_history(laptop)?,
            connection_history(solis)?,
            world
                .fleet
                .recovery_snapshot(LAPTOP, solis.node)?
                .map(|snapshot| snapshot.to_string()),
            world
                .fleet
                .recovery_snapshot(SOLIS, laptop.node)?
                .map(|snapshot| snapshot.to_string()),
            after_changes.saturating_sub(before_changes),
            world.fleet.quality_dials(LAPTOP)?,
            world.fleet.replacement_attempts(LAPTOP)?,
        )
        .into());
    }
    Ok(())
}

/// The owner published the mapped address but never added the router rule:
/// the laptop knows where to go, and the home gateway refuses it.
#[test]
fn from_an_ipv4_only_hotel_a_published_address_without_the_router_forward_is_refused_at_home() -> Result<(), Error> {
    let world = paired_at_home(
        HomeGateway {
            ipv4_forward: false,
            ipv6: Ipv6Policy::DefaultDeny,
        },
        3,
    )?;
    publish_forward(&world)?;
    travel(&world, hotel_site())?;
    assert_unreachable(&world)?;
    assert!(world.network.stats()?.dropped(Discard::NoMapping) > 0);
    Ok(())
}

#[test]
fn from_a_phone_hotspot_the_laptop_reaches_solis_over_ipv6_when_home_admits_inbound_ipv6() -> Result<(), Error> {
    let world = paired_at_home(
        HomeGateway {
            ipv4_forward: false,
            ipv6: Ipv6Policy::Open,
        },
        4,
    )?;
    travel(&world, cellular_site())?;
    let path = wait_connected(&world.fleet, LAPTOP, SOLIS, ROAMING)?.ok_or("no connection from the hotspot")?;
    assert!(path.is_ipv6(), "expected the native IPv6 path, got {path}");
    assert_tunnel(&world)
}

#[test]
fn from_a_phone_hotspot_a_default_deny_home_ipv6_firewall_refuses_the_laptop() -> Result<(), Error> {
    let world = paired_at_home(
        HomeGateway {
            ipv4_forward: false,
            ipv6: Ipv6Policy::DefaultDeny,
        },
        5,
    )?;
    travel(&world, cellular_site())?;
    assert_unreachable(&world)?;
    assert!(world.network.stats()?.dropped(Discard::Firewall) > 0);
    Ok(())
}

#[test]
fn from_a_phone_hotspot_an_ipv6_pinhole_admits_the_laptop() -> Result<(), Error> {
    let world = paired_at_home(
        HomeGateway {
            ipv4_forward: false,
            ipv6: Ipv6Policy::Pinhole,
        },
        6,
    )?;
    travel(&world, cellular_site())?;
    let path = wait_connected(&world.fleet, LAPTOP, SOLIS, ROAMING)?.ok_or("no connection through the pinhole")?;
    assert!(path.is_ipv6(), "expected the native IPv6 path, got {path}");
    assert_tunnel(&world)
}

#[test]
fn after_solis_restarts_while_the_laptop_is_away_the_laptop_reconnects_through_the_forward() -> Result<(), Error> {
    let mut world = paired_at_home(
        HomeGateway {
            ipv4_forward: true,
            ipv6: Ipv6Policy::DefaultDeny,
        },
        7,
    )?;
    publish_forward(&world)?;
    travel(&world, hotel_site())?;
    wait_connected(&world.fleet, LAPTOP, SOLIS, ROAMING)?.ok_or("no connection from the hotel")?;
    world.fleet.stop(SOLIS)?;
    world.fleet.start(SOLIS)?;
    let path =
        wait_connected(&world.fleet, LAPTOP, SOLIS, CRASH_RECOVERY)?.ok_or("no reconnection after the restart")?;
    assert_eq!(path, SocketAddr::new(IpAddr::V4(HOME_PUBLIC), PORT));
    Ok(())
}

/// The Labs workload from Europe: the broker's 32 dedicated SSH masters held
/// open at once, and bulk staging through one of them, across a 150 ms path.
#[test]
fn from_a_transatlantic_hotel_32_concurrent_tunnels_and_bulk_staging_work_through_the_forward() -> Result<(), Error> {
    use std::io::{Read as _, Write as _};
    const MASTERS: usize = 32;
    const BULK: usize = 8 * 1024 * 1024;
    let mut world = paired_at_home(
        HomeGateway {
            ipv4_forward: true,
            ipv6: Ipv6Policy::DefaultDeny,
        },
        8,
    )?;
    // Saved while running, then applied by a restart, as on a boot service.
    for computer in [SOLIS, LAPTOP] {
        world.fleet.set_tunnel_limits(computer, 40, 64)?;
        world.fleet.stop(computer)?;
    }
    world.fleet.start_all()?;
    wait_connected(&world.fleet, LAPTOP, SOLIS, PAIRING)?.ok_or("no reconnection after the limits change")?;
    publish_forward(&world)?;
    world.network.set_latency(world.home, Duration::from_millis(10))?;
    let away = world.network.add_site(hotel_site())?;
    world.network.set_latency(away, Duration::from_millis(65))?;
    world
        .network
        .move_host(world.fleet.computer(LAPTOP)?.host, Some(away))?;
    eventually(ROAMING, || {
        let path = connection(world.fleet.computer(LAPTOP)?, world.fleet.computer(SOLIS)?.node)?;
        Ok(path.filter(|path| *path == SocketAddr::new(IpAddr::V4(HOME_PUBLIC), PORT)))
    })?
    .ok_or("no connection from the hotel")?;

    let solis = world.fleet.computer(SOLIS)?;
    let laptop = world.fleet.computer(LAPTOP)?;
    let echo = super::sim_harness::expose_echoes(solis, "ssh", MASTERS + 1)?;
    wait_connected(&world.fleet, LAPTOP, SOLIS, ROAMING)?.ok_or("no connection after exposure")?;

    // Every master is open and has carried bytes before any of them closes.
    let mut masters = Vec::new();
    for index in 0..MASTERS {
        let mut stream = super::sim_harness::open_tunnel(laptop, solis.node, "ssh")?;
        stream.write_all(&[u8::try_from(index).unwrap_or(0); 4096])?;
        masters.push(stream);
    }
    for (index, mut stream) in masters.into_iter().enumerate() {
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut returned = Vec::new();
        stream.read_to_end(&mut returned)?;
        assert_eq!(
            returned,
            vec![u8::try_from(index).unwrap_or(0); 4096],
            "master {index} lost bytes"
        );
    }

    let payload = (0..BULK)
        .map(|index| u8::try_from(index % 253).unwrap_or(0))
        .collect::<Vec<_>>();
    let started = std::time::Instant::now();
    let mut staging = super::sim_harness::open_tunnel(laptop, solis.node, "ssh")?;
    staging.write_all(&payload)?;
    staging.shutdown(std::net::Shutdown::Write)?;
    let mut returned = Vec::with_capacity(BULK);
    staging.read_to_end(&mut returned)?;
    let elapsed = started.elapsed();
    assert!(returned == payload, "bulk staging altered or truncated the bytes");
    echo.join().map_err(|_| "echo server panicked")??;
    // 16 MiB crossed the path (8 MiB each way). A 64 KiB stream window allows
    // about 0.43 MB/s at 150 ms, about 39 s; the 1 MiB window allows about 7 MB/s.
    assert!(
        elapsed < Duration::from_secs(20),
        "8 MiB each way took {elapsed:?} at 150 ms round trip"
    );
    // The path statistics the owner reads to diagnose a slow tunnel reflect
    // the modelled path.
    let Some(crate::control::ControlReply::Peers { value }) =
        crate::control::request(&laptop.path, crate::control::ControlRequest::Peers)?
    else {
        return Err("no peers reply from the laptop".into());
    };
    let path = value
        .peers
        .iter()
        .find_map(|peer| peer.connection.as_ref()?.path.clone())
        .ok_or("no path statistics for the connection to Solis")?;
    assert!(
        (140..1_000).contains(&path.rtt_ms),
        "a 150 ms path reported {} ms",
        path.rtt_ms
    );
    assert!(path.sent_packets > 0 && path.congestion_window_bytes > 0, "{path:?}");
    Ok(())
}
