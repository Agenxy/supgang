//! `supgang forward`: a loopback TCP listener on the laptop whose connections
//! each ride one authenticated service stream to a peer's named service. Runs
//! over the production services on simulated computers, so the stream crosses
//! the same session, admission and tunnel code a real trip uses.

use std::{
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
    time::Duration,
};

use super::sim_harness::{Error, Fleet, PORT, add_mapped, eventually, expose_echoes, wait_connected};
use crate::{
    cli_tunnel::forward::serve,
    record::ServiceName,
    simnet::{Nat44, Network, SiteSpec, V4Access},
    tunnel_policy::encoded_name,
};

const SOLIS: usize = 0;
const LAPTOP: usize = 1;
const HOME_PUBLIC: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);

fn site(public: Ipv4Addr, lan: Ipv4Addr, nat: Nat44) -> SiteSpec {
    SiteSpec {
        v4: Some(V4Access::Translated { public, lan, nat }),
        v6: None,
    }
}

/// Carries `payload` through a TCP connection to `listen` and returns what
/// came back after end of input.
fn round_trip(listen: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let mut client = std::net::TcpStream::connect(listen)?;
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    client.write_all(payload)?;
    client.shutdown(std::net::Shutdown::Write)?;
    let mut returned = Vec::new();
    client.read_to_end(&mut returned)?;
    Ok(returned)
}

#[test]
fn forward_carries_concurrent_tcp_clients_from_a_hotel_and_closes_refused_ones() -> Result<(), Error> {
    const CLIENTS: usize = 6;
    const _: () = assert!(crate::cli_tunnel::forward::MAX_FORWARDED_CONNECTIONS >= CLIENTS);
    let network = Network::new(21);
    let home = network.add_site(site(HOME_PUBLIC, Ipv4Addr::new(192, 168, 1, 0), Nat44::home_router()))?;
    let solis = network.add_host(Some(home))?;
    let laptop = network.add_host(Some(home))?;
    network.forward_udp(home, PORT, solis, PORT)?;
    let mut fleet = Fleet::pair(Arc::clone(&network), &[solis, laptop])?;
    fleet.start_all()?;
    wait_connected(&fleet, LAPTOP, SOLIS, Duration::from_secs(30))?.ok_or("no connection at home")?;
    // The tunnel limits the owner's computers run with; defaults admit four.
    for computer in [SOLIS, LAPTOP] {
        fleet.set_tunnel_limits(computer, 40, 64)?;
        fleet.stop(computer)?;
    }
    fleet.start_all()?;
    wait_connected(&fleet, LAPTOP, SOLIS, Duration::from_secs(30))?.ok_or("no reconnection after limits")?;
    add_mapped(fleet.computer(SOLIS)?, SocketAddrV4::new(HOME_PUBLIC, PORT))?;
    let echo = expose_echoes(fleet.computer(SOLIS)?, "web", CLIENTS)?;
    // Exposure recycles sessions; wait until the laptop holds the forward in a
    // fresh record before leaving, as the owner does before a trip.
    wait_connected(&fleet, LAPTOP, SOLIS, Duration::from_mins(1))?.ok_or("no connection after exposure")?;
    let mapped = SocketAddrV4::new(HOME_PUBLIC, PORT).to_string();
    eventually(Duration::from_secs(30), || {
        let reply = crate::control::request(
            &fleet.computer(LAPTOP)?.path,
            crate::control::ControlRequest::Resolve(fleet.computer(SOLIS)?.node),
        )?;
        Ok(match reply {
            Some(crate::control::ControlReply::Resolve { value })
                if value.candidates.iter().any(|candidate| candidate.address == mapped) =>
            {
                Some(())
            }
            _ => None,
        })
    })?
    .ok_or("the laptop never received the forward")?;
    // Travel, so the forwarded stream crosses the router forward, not the LAN.
    let hotel = network.add_site(site(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 20, 0, 0),
        Nat44::symmetric(),
    ))?;
    network.move_host(laptop, Some(hotel))?;
    // Both sides must report the forward path and keep it before streams are
    // opened, so the test measures forwarding rather than the handover.
    let forward_path = SocketAddr::new(HOME_PUBLIC.into(), PORT);
    let stable = eventually(Duration::from_mins(2), || {
        let laptop_path = super::sim_harness::connection(fleet.computer(LAPTOP)?, fleet.computer(SOLIS)?.node)?;
        let solis_sees = super::sim_harness::connection(fleet.computer(SOLIS)?, fleet.computer(LAPTOP)?.node)?;
        if laptop_path != Some(forward_path)
            || solis_sees.is_none_or(|path| path.ip().is_ipv4() && path.ip().to_string().starts_with("192.168."))
        {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_secs(3));
        let again = super::sim_harness::connection(fleet.computer(LAPTOP)?, fleet.computer(SOLIS)?.node)?;
        Ok((again == Some(forward_path)).then_some(()))
    })?;
    stable.ok_or("no stable connection from the hotel")?;

    let runtime = crate::transport::build_runtime()?;
    let reports = Arc::new(Mutex::new(Vec::<String>::new()));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let laptop_path = fleet.computer(LAPTOP)?.path.clone();
    let target = fleet.computer(SOLIS)?.node;
    let listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))?;
    let listen = listener.local_addr()?;
    let refused_listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))?;
    let refused = refused_listener.local_addr()?;
    let sink = Arc::clone(&reports);
    let serving = std::thread::spawn(move || {
        runtime.block_on(async move {
            let name = encoded_name(&ServiceName::new("web").map_err(|error| error.to_string())?);
            let absent = encoded_name(&ServiceName::new("absent").map_err(|error| error.to_string())?);
            let (stop_refused, refused_stopped) = tokio::sync::oneshot::channel::<()>();
            let report = move |message: &str| {
                if let Ok(mut reports) = sink.lock() {
                    reports.push(message.to_owned());
                }
            };
            tokio::join!(
                serve(
                    listener,
                    laptop_path.clone(),
                    target,
                    name,
                    async {
                        let _ = stopped.await;
                        let _ = stop_refused.send(());
                    },
                    report.clone()
                ),
                serve(
                    refused_listener,
                    laptop_path,
                    target,
                    absent,
                    async {
                        let _ = refused_stopped.await;
                    },
                    report
                ),
            );
            Ok::<(), String>(())
        })
    });

    // Concurrent clients each get exactly their own bytes back.
    let clients = (0..CLIENTS)
        .map(|index| {
            std::thread::spawn(move || {
                let payload = vec![u8::try_from(index).unwrap_or(0); 48 * 1024];
                round_trip(listen, &payload)
                    .map(|returned| (returned == payload, index))
                    .map_err(|error| error.to_string())
            })
        })
        .collect::<Vec<_>>();
    for client in clients {
        let (intact, index) = client.join().map_err(|_| "client panicked")??;
        assert!(intact, "client {index} received altered bytes");
    }
    echo.join().map_err(|_| "echo panicked")??;

    // A service the peer does not expose closes the client and is reported,
    // without stopping the listener.
    // Closing a connection with unread input resets it; either way the client
    // gets no bytes from a service the peer never exposed.
    match round_trip(refused, b"hello") {
        Ok(returned) => assert!(returned.is_empty(), "a refused service returned bytes"),
        Err(error) => {
            let kind = error.downcast_ref::<std::io::Error>().map(std::io::Error::kind);
            assert!(
                matches!(
                    kind,
                    Some(std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe)
                ),
                "unexpected refusal: {error}"
            );
        }
    }
    let reported = eventually(Duration::from_secs(10), || {
        Ok(reports
            .lock()
            .map_err(|_| "poisoned")?
            .iter()
            .any(|message| !message.is_empty())
            .then_some(()))
    })?;
    assert!(reported.is_some(), "a refused stream was not reported");

    let _ = stop.send(());
    serving.join().map_err(|_| "forward panicked")??;
    Ok(())
}
