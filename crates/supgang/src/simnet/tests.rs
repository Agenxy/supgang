//! Calibration of the network model itself, with raw datagrams and no QUIC:
//! each modeled behaviour must hold before any scenario relies on it.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use super::{
    Behavior, Discard, Firewall6, HostId, IpFamily, Nat44, Network, SimSocket, SiteId, SiteSpec, V4Access, V6Access,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PORT: u16 = 44_330;
const HOME_PUBLIC: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
const SERVER_FIRST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

fn translated(public: Ipv4Addr, nat: Nat44, v6: Option<V6Access>) -> SiteSpec {
    SiteSpec {
        v4: Some(V4Access::Translated {
            public,
            lan: Ipv4Addr::new(192, 168, 1, 0),
            nat,
        }),
        v6,
    }
}

fn v6(prefix_third: u16, firewall: Firewall6) -> V6Access {
    V6Access {
        prefix: Ipv6Addr::new(0x2001, 0xdb8, prefix_third, 1, 0, 0, 0, 0),
        firewall,
    }
}

/// A public server site with two hosts, so filtering by address and by port
/// can both be told apart.
fn servers(network: &Network) -> Result<(HostId, HostId), Box<dyn std::error::Error>> {
    let site = network.add_site(SiteSpec {
        v4: Some(V4Access::Public { first: SERVER_FIRST }),
        v6: Some(v6(0xffff, Firewall6::Open)),
    })?;
    Ok((network.add_host(Some(site))?, network.add_host(Some(site))?))
}

fn received(socket: &SimSocket) -> Result<Option<SocketAddr>, Box<dyn std::error::Error>> {
    Ok(socket.try_receive()?.map(|(source, _)| source))
}

fn v4_of(network: &Network, host: HostId) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    network
        .host_addresses(host)?
        .into_iter()
        .find_map(|address| match address {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| "host has no IPv4".into())
}

fn v6_of(network: &Network, host: HostId) -> Result<Ipv6Addr, Box<dyn std::error::Error>> {
    network
        .host_addresses(host)?
        .into_iter()
        .find_map(|address| match address {
            IpAddr::V6(v6) => Some(v6),
            IpAddr::V4(_) => None,
        })
        .ok_or_else(|| "host has no IPv6".into())
}

struct Fixture {
    network: Arc<Network>,
    home: SiteId,
    inside: Arc<SimSocket>,
    server_a: Arc<SimSocket>,
    server_a_other_port: Arc<SimSocket>,
    server_b: Arc<SimSocket>,
}

fn fixture(nat: Nat44) -> Result<Fixture, Box<dyn std::error::Error>> {
    let network = Network::new(7);
    let home = network.add_site(translated(HOME_PUBLIC, nat, Some(v6(1, Firewall6::default_deny()))))?;
    let inside = network.add_host(Some(home))?;
    let (server_a, server_b) = servers(&network)?;
    Ok(Fixture {
        inside: network.bind(inside, PORT)?,
        server_a: network.bind(server_a, PORT)?,
        server_a_other_port: network.bind(server_a, PORT + 1)?,
        server_b: network.bind(server_b, PORT)?,
        home,
        network,
    })
}

fn server_address(fixture: &Fixture, socket: &SimSocket, port: u16) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    Ok(SocketAddr::new(
        IpAddr::V4(v4_of(&fixture.network, socket.host())?),
        port,
    ))
}

#[test]
fn a_home_router_preserves_the_port_and_admits_only_the_answering_endpoint() -> TestResult {
    let lab = fixture(Nat44::home_router())?;
    let server = server_address(&lab, &lab.server_a, PORT)?;
    lab.inside.send_raw(server, b"out")?;
    let external = received(&lab.server_a)?.ok_or("server saw nothing")?;
    assert_eq!(external, SocketAddr::new(IpAddr::V4(HOME_PUBLIC), PORT));

    lab.server_a.send_raw(external, b"reply")?;
    assert!(received(&lab.inside)?.is_some());
    lab.server_a_other_port.send_raw(external, b"other port")?;
    lab.server_b.send_raw(external, b"other host")?;
    assert!(received(&lab.inside)?.is_none());
    assert_eq!(lab.network.stats()?.dropped(Discard::Filtered), 2);
    Ok(())
}

#[test]
fn a_full_cone_admits_any_endpoint_once_mapped_but_nothing_before() -> TestResult {
    let lab = fixture(Nat44::full_cone())?;
    let external = SocketAddr::new(IpAddr::V4(HOME_PUBLIC), PORT);
    lab.server_b.send_raw(external, b"unsolicited")?;
    assert!(received(&lab.inside)?.is_none());
    assert_eq!(lab.network.stats()?.dropped(Discard::NoMapping), 1);

    lab.inside
        .send_raw(server_address(&lab, &lab.server_a, PORT)?, b"out")?;
    lab.server_b.send_raw(external, b"now admitted")?;
    assert!(received(&lab.inside)?.is_some());
    Ok(())
}

#[test]
fn a_symmetric_gateway_uses_a_different_port_per_destination() -> TestResult {
    let lab = fixture(Nat44::symmetric())?;
    lab.inside.send_raw(server_address(&lab, &lab.server_a, PORT)?, b"a")?;
    lab.inside.send_raw(server_address(&lab, &lab.server_b, PORT)?, b"b")?;
    let seen_by_a = received(&lab.server_a)?.ok_or("a saw nothing")?;
    let seen_by_b = received(&lab.server_b)?.ok_or("b saw nothing")?;
    assert_eq!(seen_by_a.ip(), seen_by_b.ip());
    assert_ne!(seen_by_a.port(), seen_by_b.port());
    // The port b learned is useless to a: that mapping filters a out.
    lab.server_a.send_raw(seen_by_b, b"cross")?;
    assert!(received(&lab.inside)?.is_none());
    assert_eq!(lab.network.stats()?.dropped(Discard::Filtered), 1);
    Ok(())
}

#[test]
fn the_same_seed_reproduces_random_port_choices() -> TestResult {
    let mut ports = Vec::new();
    for _ in 0..2 {
        let lab = fixture(Nat44::symmetric())?;
        lab.inside.send_raw(server_address(&lab, &lab.server_a, PORT)?, b"a")?;
        ports.push(received(&lab.server_a)?.ok_or("nothing")?.port());
    }
    assert_eq!(ports.first(), ports.get(1));
    Ok(())
}

#[test]
fn a_forward_admits_unsolicited_traffic_that_is_otherwise_refused() -> TestResult {
    let lab = fixture(Nat44::home_router())?;
    let external = SocketAddr::new(IpAddr::V4(HOME_PUBLIC), PORT);
    lab.server_b.send_raw(external, b"before")?;
    assert!(received(&lab.inside)?.is_none());
    lab.network.forward_udp(lab.home, PORT, lab.inside.host(), PORT)?;
    lab.server_b.send_raw(external, b"after")?;
    assert!(received(&lab.inside)?.is_some());
    Ok(())
}

#[test]
fn a_mapping_is_forgotten_after_its_idle_timeout() -> TestResult {
    let lab = fixture(Nat44 {
        timeout: Duration::from_millis(40),
        ..Nat44::home_router()
    })?;
    lab.inside
        .send_raw(server_address(&lab, &lab.server_a, PORT)?, b"out")?;
    let external = received(&lab.server_a)?.ok_or("nothing")?;
    std::thread::sleep(Duration::from_millis(80));
    lab.server_a.send_raw(external, b"late")?;
    assert!(received(&lab.inside)?.is_none());
    assert_eq!(lab.network.stats()?.dropped(Discard::NoMapping), 1);
    Ok(())
}

#[test]
fn hairpinning_follows_the_gateway_setting() -> TestResult {
    for (hairpin, expected) in [(true, true), (false, false)] {
        let network = Network::new(1);
        let home = network.add_site(translated(
            HOME_PUBLIC,
            Nat44 {
                hairpin,
                ..Nat44::home_router()
            },
            None,
        ))?;
        let first = network.bind(network.add_host(Some(home))?, PORT)?;
        let second_host = network.add_host(Some(home))?;
        let second = network.bind(second_host, PORT + 1)?;
        network.forward_udp(home, PORT + 1, second_host, PORT + 1)?;
        first.send_raw(SocketAddr::new(IpAddr::V4(HOME_PUBLIC), PORT + 1), b"loop")?;
        assert_eq!(received(&second)?.is_some(), expected);
    }
    Ok(())
}

#[test]
fn ipv6_default_deny_admits_replies_and_pinholes_only() -> TestResult {
    let lab = fixture(Nat44::home_router())?;
    let inside = SocketAddr::new(IpAddr::V6(v6_of(&lab.network, lab.inside.host())?), PORT);
    lab.server_b.send_raw(inside, b"unsolicited")?;
    assert!(received(&lab.inside)?.is_none());
    assert_eq!(lab.network.stats()?.dropped(Discard::Firewall), 1);

    let server = SocketAddr::new(IpAddr::V6(v6_of(&lab.network, lab.server_a.host())?), PORT);
    lab.inside.send_raw(server, b"out")?;
    lab.server_a.send_raw(inside, b"reply")?;
    assert!(received(&lab.inside)?.is_some());
    lab.server_b.send_raw(inside, b"still unsolicited")?;
    assert!(received(&lab.inside)?.is_none());

    lab.network.pinhole_v6(lab.home, lab.inside.host(), PORT)?;
    lab.server_b.send_raw(inside, b"pinholed")?;
    assert!(received(&lab.inside)?.is_some());
    Ok(())
}

#[test]
fn a_roaming_host_changes_addresses_and_loses_its_old_network() -> TestResult {
    let network = Network::new(3);
    let home = network.add_site(translated(
        HOME_PUBLIC,
        Nat44::home_router(),
        Some(v6(1, Firewall6::Open)),
    ))?;
    let hotel = network.add_site(translated(Ipv4Addr::new(203, 0, 113, 99), Nat44::symmetric(), None))?;
    let laptop = network.add_host(Some(home))?;
    let solis = network.add_host(Some(home))?;
    let laptop_socket = network.bind(laptop, PORT)?;
    let solis_socket = network.bind(solis, PORT)?;
    let solis_lan = SocketAddr::new(IpAddr::V4(v4_of(&network, solis)?), PORT);
    let solis_v6 = SocketAddr::new(IpAddr::V6(v6_of(&network, solis)?), PORT);
    laptop_socket.send_raw(solis_lan, b"on link")?;
    assert!(received(&solis_socket)?.is_some());

    network.move_host(laptop, Some(hotel))?;
    assert!(network.host_addresses(laptop)?.iter().all(IpAddr::is_ipv4));
    // Solis's private address is not routed from the hotel, and the hotel has
    // no IPv6 to reach Solis's global address with.
    laptop_socket.send_raw(solis_lan, b"off link")?;
    laptop_socket.send_raw(solis_v6, b"no ipv6")?;
    assert!(received(&solis_socket)?.is_none());
    let stats = network.stats()?;
    assert_eq!(stats.dropped(Discard::Unaddressed), 1);
    assert_eq!(stats.dropped(Discard::NoRoute), 1);

    network.move_host(laptop, None)?;
    assert!(network.host_addresses(laptop)?.is_empty());
    Ok(())
}

#[test]
fn seeded_loss_is_bounded_and_reproducible() -> TestResult {
    let mut deliveries = Vec::new();
    for _ in 0..2 {
        let lab = fixture(Nat44::home_router())?;
        lab.network.set_loss_permille(lab.home, 300)?;
        let server = server_address(&lab, &lab.server_a, PORT)?;
        for _ in 0..200 {
            lab.inside.send_raw(server, b"x")?;
            let _ = lab.server_a.try_receive()?;
        }
        deliveries.push(lab.network.stats()?.delivered);
    }
    let first = deliveries.first().copied().ok_or("no run")?;
    assert_eq!(Some(first), deliveries.get(1).copied());
    assert!((100..=180).contains(&first), "{first} of 200 delivered at 30% loss");
    Ok(())
}

#[test]
fn address_dependent_behaviour_with_sequential_ports_admits_other_ports_of_a_known_address() -> TestResult {
    let lab = fixture(Nat44 {
        mapping: Behavior::AddressDependent,
        filtering: Behavior::AddressDependent,
        ports: super::PortAssignment::Sequential,
        ..Nat44::home_router()
    })?;
    lab.inside.send_raw(server_address(&lab, &lab.server_a, PORT)?, b"a")?;
    lab.inside
        .send_raw(server_address(&lab, &lab.server_a, PORT + 1)?, b"a, other port")?;
    lab.inside.send_raw(server_address(&lab, &lab.server_b, PORT)?, b"b")?;
    let first = received(&lab.server_a)?.ok_or("a saw nothing")?;
    let second = received(&lab.server_a_other_port)?.ok_or("a's other port saw nothing")?;
    let third = received(&lab.server_b)?.ok_or("b saw nothing")?;
    // One mapping per remote address, numbered in order rather than preserved.
    assert_eq!(first, second);
    assert_eq!(first.port(), 20_000);
    assert_eq!(third.port(), 20_001);
    lab.server_a_other_port.send_raw(first, b"same address")?;
    assert!(received(&lab.inside)?.is_some());
    lab.server_b.send_raw(first, b"other address")?;
    assert!(received(&lab.inside)?.is_none());
    Ok(())
}

#[test]
fn renumbering_the_gateway_breaks_every_remembered_mapping() -> TestResult {
    let lab = fixture(Nat44::full_cone())?;
    lab.inside
        .send_raw(server_address(&lab, &lab.server_a, PORT)?, b"out")?;
    let old = received(&lab.server_a)?.ok_or("nothing")?;
    let renumbered = Ipv4Addr::new(203, 0, 113, 11);
    lab.network.renumber_public_v4(lab.home, renumbered)?;
    lab.server_a.send_raw(old, b"to the old address")?;
    assert!(received(&lab.inside)?.is_none());
    assert_eq!(lab.network.stats()?.dropped(Discard::Unaddressed), 1);
    lab.inside
        .send_raw(server_address(&lab, &lab.server_a, PORT)?, b"again")?;
    assert_eq!(
        received(&lab.server_a)?.map(|source| source.ip()),
        Some(IpAddr::V4(renumbered))
    );
    Ok(())
}

#[test]
fn routes_exist_only_for_the_families_a_site_provides() -> TestResult {
    let network = Network::new(5);
    let ipv4_only = network.add_site(translated(HOME_PUBLIC, Nat44::symmetric(), None))?;
    let host = network.add_host(Some(ipv4_only))?;
    assert!(network.has_route(host, IpAddr::V4(SERVER_FIRST))?);
    assert!(!network.has_route(host, IpAddr::V6(Ipv6Addr::LOCALHOST))?);
    network.move_host(host, None)?;
    assert!(!network.has_route(host, IpAddr::V4(SERVER_FIRST))?);
    Ok(())
}

#[test]
fn a_host_joining_a_site_never_takes_an_address_still_in_use() -> TestResult {
    let network = Network::new(9);
    let home = network.add_site(translated(HOME_PUBLIC, Nat44::home_router(), None))?;
    let away = network.add_site(translated(Ipv4Addr::new(203, 0, 113, 50), Nat44::home_router(), None))?;
    let first = network.add_host(Some(home))?;
    let second = network.add_host(Some(home))?;
    network.move_host(first, Some(away))?;
    let third = network.add_host(Some(home))?;
    assert_ne!(v4_of(&network, second)?, v4_of(&network, third)?);
    Ok(())
}

#[test]
fn a_forwarded_host_answers_from_the_forwarded_external_port() -> TestResult {
    let lab = fixture(Nat44::home_router())?;
    lab.network.forward_udp(lab.home, PORT + 7, lab.inside.host(), PORT)?;
    let external = SocketAddr::new(IpAddr::V4(HOME_PUBLIC), PORT + 7);
    lab.server_a.send_raw(external, b"inbound")?;
    let (source, _) = lab.inside.try_receive()?.ok_or("forward delivered nothing")?;
    lab.inside.send_raw(source, b"reply")?;
    assert_eq!(received(&lab.server_a)?, Some(external));
    Ok(())
}

#[test]
fn latency_delays_off_site_delivery_by_both_uplinks_but_not_the_lan() -> TestResult {
    let lab = fixture(Nat44::full_cone())?;
    lab.network.set_latency(lab.home, Duration::from_millis(30))?;
    let server = server_address(&lab, &lab.server_a, PORT)?;
    lab.inside.send_raw(server, b"delayed")?;
    assert!(received(&lab.server_a)?.is_none(), "arrived before its path delay");
    std::thread::sleep(Duration::from_millis(45));
    assert!(received(&lab.server_a)?.is_some(), "never arrived after its path delay");
    Ok(())
}

#[test]
fn an_ipv6_mtu_black_hole_drops_only_oversized_ipv6_datagrams() -> TestResult {
    let lab = fixture(Nat44::home_router())?;
    lab.network.set_family_mtu(lab.home, IpFamily::V6, Some(1_200))?;
    let v6_server = SocketAddr::new(IpAddr::V6(v6_of(&lab.network, lab.server_a.host())?), PORT);
    lab.inside.send_raw(v6_server, &[7; 1_201])?;
    assert!(received(&lab.server_a)?.is_none());
    assert_eq!(lab.network.stats()?.dropped(Discard::MtuBlackHole), 1);
    lab.inside.send_raw(v6_server, &[7; 1_200])?;
    assert!(received(&lab.server_a)?.is_some());
    lab.inside
        .send_raw(server_address(&lab, &lab.server_a, PORT)?, &[7; 1_201])?;
    assert!(received(&lab.server_a)?.is_some());
    Ok(())
}
