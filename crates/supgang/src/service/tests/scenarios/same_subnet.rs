use super::*;

/// A hotel whose LAN reuses the home subnet, 192.168.1.0/24, as many consumer
/// gateways do. Solis's home LAN address then looks directly attached.
fn same_subnet_hotel_site() -> SiteSpec {
    SiteSpec {
        v4: Some(V4Access::Translated {
            public: Ipv4Addr::new(8, 8, 8, 8),
            lan: Ipv4Addr::new(192, 168, 1, 0),
            nat: Nat44::symmetric(),
        }),
        v6: None,
    }
}

/// Travels to a same-subnet hotel where `guests` other devices joined first,
/// which decides the laptop's address there: with none it takes Solis's home
/// address, with one its own home address, with two an address new to it.
fn travel_to_same_subnet_hotel(guests: usize, seed: u64) -> Result<(), Error> {
    let world = paired_at_home(
        HomeGateway {
            ipv4_forward: true,
            ipv6: Ipv6Policy::DefaultDeny,
        },
        seed,
    )?;
    publish_forward(&world)?;
    let hotel = world.network.add_site(same_subnet_hotel_site())?;
    for _ in 0..guests {
        world.network.add_host(Some(hotel))?;
    }
    let solis = world.fleet.computer(SOLIS)?;
    let laptop = world.fleet.computer(LAPTOP)?;
    let before = connection(laptop, solis.node)?.ok_or("not connected before travelling")?;
    let home_path = match before.ip() {
        IpAddr::V4(address) if address.is_private() => "private-ipv4",
        IpAddr::V6(address) if address.segments().get(..4) == HOME_PREFIX.segments().get(..4) => "internet-ipv6",
        _ => return Err("the initial connection was not on the home LAN".into()),
    };
    let Some(crate::control::ControlReply::Status { value: before_status }) =
        crate::control::request(&laptop.path, crate::control::ControlRequest::Status)?
    else {
        return Err("no status from the laptop before travelling".into());
    };
    world.network.move_host(laptop.host, Some(hotel))?;
    let forward = SocketAddr::new(IpAddr::V4(HOME_PUBLIC), PORT);
    // The home IPv6 prefix is on-link, although history correctly labels its
    // globally scoped address as internet-ipv6. Match the path actually held
    // before moving rather than assuming the home connection used private v4.
    // Wait for the service to record both events within the existing roaming
    // bound; a control reply can see a new active path before history observes it.
    let mut last_events = Vec::new();
    let reached = eventually(STALE_PATH_RETIREMENT + ROAMING, || {
        let path = connection(laptop, solis.node)?;
        let Some(crate::control::ControlReply::Status { value }) =
            crate::control::request(&laptop.path, crate::control::ControlRequest::Status)?
        else {
            return Err("no status from the laptop".into());
        };
        last_events = value.recent_connections;
        let events = &last_events;
        let new_events = events
            .strip_prefix(before_status.recent_connections.as_slice())
            .unwrap_or(&[]);
        let ended = new_events
            .iter()
            .position(|event| event.event == "ended" && event.path == home_path && !event.reason.is_empty());
        let connected = ended.is_some_and(|index| {
            new_events
                .iter()
                .skip(index + 1)
                .any(|event| event.event == "connected" && event.path == "internet-ipv4")
        });
        Ok((path == Some(forward) && connected).then_some(()))
    })?;
    assert!(
        reached.is_some(),
        "no recorded transition from home-LAN {home_path} to the forward from a same-subnet hotel ({guests} guests); \
         the previous path {before} is now {:?}, history {last_events:?}",
        connection(laptop, solis.node)?,
    );
    assert_tunnel(&world)
}

#[test]
fn from_a_hotel_on_the_home_subnet_the_laptop_reaches_solis_through_the_forward() -> Result<(), Error> {
    travel_to_same_subnet_hotel(2, 11)
}

#[test]
fn from_a_hotel_on_the_home_subnet_that_reissues_the_laptops_home_address_the_forward_still_wins() -> Result<(), Error>
{
    travel_to_same_subnet_hotel(1, 12)
}

#[test]
fn from_a_hotel_on_the_home_subnet_that_issues_solis_home_address_the_forward_still_wins() -> Result<(), Error> {
    travel_to_same_subnet_hotel(0, 13)
}
