//! A deterministic in-memory network for scenario tests.
//!
//! Sites model access networks: an IPv4 side that is either public or
//! translated by a gateway NAT with the RFC 4787 behaviour categories, and an
//! IPv6 side that is either open or a stateful firewall with default inbound
//! denial (RFC 6092). Hosts join a site, can roam to another or go offline,
//! and bind dual-stack UDP sockets that carry real QUIC through
//! [`quinn::AsyncUdpSocket`]. Every dropped datagram is counted by reason so a
//! scenario can assert why a path failed, not only that it did.
//!
//! This is test equipment. It never opens an operating-system socket and its
//! public addresses are fixtures, never endpoints on the real Internet.

mod impairment;
mod nat;
mod socket;
#[cfg(test)]
mod tests;
mod view;

use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, Mutex, MutexGuard},
    task::Waker,
    time::Duration,
};

use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng as _};

use impairment::Impairment;
pub use impairment::IpFamily;
pub use nat::{Behavior, Firewall6, Nat44, PortAssignment};

pub use socket::SimSocket;
pub use view::HostView;

/// Most sites, hosts and sockets a scenario may create.
const MAX_SITES: usize = 32;
const MAX_HOSTS: usize = 64;
const MAX_SOCKETS_PER_HOST: usize = 8;
/// Datagrams in flight to or queued for one socket before further arrivals
/// are dropped. Large enough for a long, fast path's bandwidth-delay product.
const MAX_QUEUED_DATAGRAMS: usize = 8192;
const MAX_DATAGRAM_BYTES: usize = 65_535;

/// Identifies a site in one [`Network`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SiteId(usize);

/// Identifies a host in one [`Network`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HostId(usize);

/// How a site reaches the IPv4 Internet.
#[derive(Clone, Debug)]
pub enum V4Access {
    /// Each host receives its own public address, starting at `first`, with no
    /// translation or inbound filtering.
    Public { first: Ipv4Addr },
    /// Hosts share `public` behind a gateway; `lan` is the first address of a
    /// /24 that hosts are numbered from.
    Translated {
        public: Ipv4Addr,
        lan: Ipv4Addr,
        nat: Nat44,
    },
}

/// How a site reaches the IPv6 Internet.
#[derive(Clone, Debug)]
pub struct V6Access {
    /// The site's /64; hosts take interface identifiers inside it.
    pub prefix: Ipv6Addr,
    pub firewall: Firewall6,
}

/// The configuration of one access network.
#[derive(Clone, Debug)]
pub struct SiteSpec {
    pub v4: Option<V4Access>,
    pub v6: Option<V6Access>,
}

/// Why the network discarded a datagram.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Discard {
    /// The sender is offline or its site lacks the destination's family.
    NoRoute,
    /// No site, host or translation owns the destination address.
    Unaddressed,
    /// Inbound IPv4 reached the gateway without a mapping or forward.
    NoMapping,
    /// A mapping exists but its filtering refused the remote endpoint.
    Filtered,
    /// A stateful IPv6 firewall refused unsolicited inbound traffic.
    Firewall,
    /// The gateway does not loop traffic back to its own public address.
    NoHairpin,
    /// The destination host has no socket on that port.
    NoListener,
    /// The configured loss model discarded it.
    Loss,
    /// A path MTU black hole silently discarded an oversized datagram.
    MtuBlackHole,
    /// The destination socket's queue was full.
    QueueFull,
}

/// Counts of delivered and discarded datagrams since the network was built.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Stats {
    pub delivered: u64,
    /// Delivered on-link datagrams keyed by sender and receiver host IDs.
    pub on_link_delivered: BTreeMap<(HostId, HostId), u64>,
    pub dropped: BTreeMap<Discard, u64>,
}

impl Stats {
    pub fn dropped(&self, reason: Discard) -> u64 {
        self.dropped.get(&reason).copied().unwrap_or(0)
    }
}

#[derive(Debug)]
struct Site {
    spec: SiteSpec,
    nat: Option<nat::Table>,
    firewall: nat::FirewallTable,
    /// Bounded per-family latency, loss, and MTU controls for this uplink.
    impairment: [Impairment; 2],
}

#[derive(Debug)]
struct Host {
    site: Option<SiteId>,
    /// The host's position in its current site, which fixes its addresses.
    slot: u8,
    sockets: BTreeMap<u16, Inbox>,
}

#[derive(Debug, Default)]
struct Inbox {
    queue: VecDeque<Received>,
    reader: Option<Waker>,
    /// When a scheduled wake for the earliest delayed datagram fires.
    timer: Option<tokio::time::Instant>,
}

impl Inbox {
    /// Removes the first datagram whose path delay has elapsed.
    fn take_ready(&mut self, now: tokio::time::Instant) -> Option<Received> {
        let index = self.queue.iter().position(|received| received.ready_at <= now)?;
        self.queue.remove(index)
    }
}

#[derive(Debug)]
struct Received {
    source: SocketAddr,
    destination: IpAddr,
    bytes: Vec<u8>,
    ready_at: tokio::time::Instant,
}

#[derive(Debug)]
struct State {
    sites: Vec<Site>,
    hosts: Vec<Host>,
    stats: Stats,
    random: ChaCha8Rng,
}

/// The whole simulated Internet for one scenario.
#[derive(Debug)]
pub struct Network {
    state: Mutex<State>,
}

impl Network {
    /// Builds an empty network whose loss and port choices follow `seed`.
    pub fn new(seed: u64) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                sites: Vec::new(),
                hosts: Vec::new(),
                stats: Stats::default(),
                random: ChaCha8Rng::seed_from_u64(seed),
            }),
        })
    }

    fn lock(&self) -> io::Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("simulated network poisoned"))
    }

    pub fn add_site(&self, spec: SiteSpec) -> io::Result<SiteId> {
        let mut state = self.lock()?;
        if state.sites.len() >= MAX_SITES {
            return Err(io::Error::other("simulated site limit"));
        }
        let nat = match &spec.v4 {
            Some(V4Access::Translated { public, nat, .. }) => {
                if state.owns_public_v4(*public) {
                    return Err(io::Error::other("public IPv4 already assigned"));
                }
                Some(nat::Table::new(nat.clone(), *public))
            }
            Some(V4Access::Public { .. }) | None => None,
        };
        let firewall = nat::FirewallTable::new(spec.v6.as_ref().map(|v6| v6.firewall.clone()));
        state.sites.push(Site {
            spec,
            nat,
            firewall,
            impairment: [Impairment::default(); 2],
        });
        Ok(SiteId(state.sites.len() - 1))
    }

    /// Adds a host, attached to `site` or offline.
    pub fn add_host(&self, site: Option<SiteId>) -> io::Result<HostId> {
        let mut state = self.lock()?;
        if state.hosts.len() >= MAX_HOSTS {
            return Err(io::Error::other("simulated host limit"));
        }
        let host = HostId(state.hosts.len());
        state.hosts.push(Host {
            site: None,
            slot: 0,
            sockets: BTreeMap::new(),
        });
        let attached = state.attach(host, site);
        drop(state);
        attached.map(|()| host)
    }

    /// Moves a host to another site, or offline with `None`. Its sockets stay
    /// bound; its addresses change, as a laptop's do when it changes networks.
    pub fn move_host(&self, host: HostId, site: Option<SiteId>) -> io::Result<()> {
        self.lock()?.attach(host, site)
    }

    /// Installs an owner-configured IPv4 port forward on a translated site.
    pub fn forward_udp(&self, site: SiteId, external_port: u16, host: HostId, port: u16) -> io::Result<()> {
        let mut state = self.lock()?;
        state.require_host(host)?;
        state
            .site_mut(site)?
            .nat
            .as_mut()
            .ok_or_else(|| io::Error::other("site has no IPv4 gateway"))?
            .forward(external_port, host, port)
    }

    /// Opens an inbound IPv6 pinhole to one host and UDP port.
    pub fn pinhole_v6(&self, site: SiteId, host: HostId, port: u16) -> io::Result<()> {
        let mut state = self.lock()?;
        state.require_host(host)?;
        state.site_mut(site)?.firewall.pinhole(host, port)
    }

    /// Changes the public IPv4 address a translated site's gateway uses,
    /// discarding its dynamic mappings as a real address change would.
    pub fn renumber_public_v4(&self, site: SiteId, public: Ipv4Addr) -> io::Result<()> {
        let mut state = self.lock()?;
        if state.owns_public_v4(public) {
            return Err(io::Error::other("public IPv4 already assigned"));
        }
        let site = state.site_mut(site)?;
        let Some(V4Access::Translated { public: current, .. }) = site.spec.v4.as_mut() else {
            return Err(io::Error::other("site has no IPv4 gateway"));
        };
        *current = public;
        let renumbered = site
            .nat
            .as_mut()
            .map(|table| table.renumber(public))
            .ok_or_else(|| io::Error::other("site has no IPv4 gateway"));
        drop(state);
        renumbered
    }

    /// The addresses the host's interfaces carry now, as an operating system
    /// would enumerate them. An offline host has none.
    pub fn host_addresses(&self, host: HostId) -> io::Result<Vec<IpAddr>> {
        let state = self.lock()?;
        state.require_host(host)?;
        Ok(state.addresses(host))
    }

    /// Whether the host's current site routes the family of `destination`.
    pub fn has_route(&self, host: HostId, destination: IpAddr) -> io::Result<bool> {
        let state = self.lock()?;
        state.require_host(host)?;
        Ok(state.source_for(host, destination).is_some())
    }

    pub fn stats(&self) -> io::Result<Stats> {
        Ok(self.lock()?.stats.clone())
    }

    /// Binds a dual-stack UDP socket on `port` of `host`.
    pub fn bind(self: &Arc<Self>, host: HostId, port: u16) -> io::Result<Arc<SimSocket>> {
        let mut state = self.lock()?;
        let entry = state
            .hosts
            .get_mut(host.0)
            .ok_or_else(|| io::Error::other("unknown simulated host"))?;
        if port == 0 || entry.sockets.contains_key(&port) || entry.sockets.len() >= MAX_SOCKETS_PER_HOST {
            return Err(io::Error::from(io::ErrorKind::AddrInUse));
        }
        entry.sockets.insert(port, Inbox::default());
        drop(state);
        Ok(Arc::new(SimSocket::new(Arc::clone(self), host, port)))
    }

    fn unbind(&self, host: HostId, port: u16) {
        if let Ok(mut state) = self.lock()
            && let Some(host) = state.hosts.get_mut(host.0)
        {
            host.sockets.remove(&port);
        }
    }

    /// Carries one datagram from `host:port` towards `destination`.
    fn send(&self, host: HostId, port: u16, destination: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > MAX_DATAGRAM_BYTES {
            return Err(io::Error::other("simulated datagram limit"));
        }
        let destination = canonical(destination);
        let mut state = self.lock()?;
        let delivered = state.route(host, port, destination, bytes, tokio::time::Instant::now());
        let waker = match delivered {
            Ok(waker) => {
                state.stats.delivered += 1;
                waker
            }
            Err(reason) => {
                *state.stats.dropped.entry(reason).or_default() += 1;
                None
            }
        };
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }
}

/// Where a datagram is handed to after translation and filtering.
struct Arrival {
    host: HostId,
    port: u16,
    source: SocketAddr,
    destination: IpAddr,
}

impl State {
    fn require_host(&self, host: HostId) -> io::Result<()> {
        self.hosts
            .get(host.0)
            .map(|_| ())
            .ok_or_else(|| io::Error::other("unknown simulated host"))
    }

    fn site_mut(&mut self, site: SiteId) -> io::Result<&mut Site> {
        self.sites
            .get_mut(site.0)
            .ok_or_else(|| io::Error::other("unknown simulated site"))
    }

    fn owns_public_v4(&self, address: Ipv4Addr) -> bool {
        self.sites.iter().any(|site| match &site.spec.v4 {
            Some(V4Access::Translated { public, .. }) => *public == address,
            _ => false,
        }) || self
            .hosts
            .iter()
            .enumerate()
            .any(|(index, _)| self.addresses(HostId(index)).contains(&IpAddr::V4(address)))
    }

    fn attach(&mut self, host: HostId, site: Option<SiteId>) -> io::Result<()> {
        if let Some(site) = site
            && self.sites.get(site.0).is_none()
        {
            return Err(io::Error::other("unknown simulated site"));
        }
        // The lowest slot no other host on the site holds, so a newcomer
        // never takes an address that is still in use.
        let taken = self
            .hosts
            .iter()
            .enumerate()
            .filter(|(index, other)| *index != host.0 && site.is_some() && other.site == site)
            .map(|(_, other)| other.slot)
            .collect::<std::collections::BTreeSet<_>>();
        let slot = (1..=200_u8)
            .find(|slot| !taken.contains(slot))
            .ok_or_else(|| io::Error::other("simulated site is full"))?;
        let entry = self
            .hosts
            .get_mut(host.0)
            .ok_or_else(|| io::Error::other("unknown simulated host"))?;
        entry.site = site;
        entry.slot = slot;
        Ok(())
    }

    fn site_of(&self, host: HostId) -> Option<(SiteId, &Site, u8)> {
        let entry = self.hosts.get(host.0)?;
        let site = entry.site?;
        Some((site, self.sites.get(site.0)?, entry.slot))
    }

    fn v4_of(&self, host: HostId) -> Option<Ipv4Addr> {
        let (_, site, slot) = self.site_of(host)?;
        match site.spec.v4.as_ref()? {
            V4Access::Public { first } => Some(offset_v4(*first, slot - 1)),
            V4Access::Translated { lan, .. } => Some(offset_v4(*lan, slot)),
        }
    }

    fn v6_of(&self, host: HostId) -> Option<Ipv6Addr> {
        let (_, site, slot) = self.site_of(host)?;
        let prefix = site.spec.v6.as_ref()?.prefix.segments();
        let [a, b, c, d, ..] = prefix;
        Some(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0x10 + u16::from(slot)))
    }

    fn addresses(&self, host: HostId) -> Vec<IpAddr> {
        self.v4_of(host)
            .map(IpAddr::V4)
            .into_iter()
            .chain(self.v6_of(host).map(IpAddr::V6))
            .collect()
    }

    fn source_for(&self, host: HostId, destination: IpAddr) -> Option<IpAddr> {
        match destination {
            IpAddr::V4(_) => self.v4_of(host).map(IpAddr::V4),
            IpAddr::V6(_) => self.v6_of(host).map(IpAddr::V6),
        }
    }

    fn host_at(&self, site: SiteId, address: IpAddr) -> Option<HostId> {
        (0..self.hosts.len()).map(HostId).find(|host| {
            self.hosts.get(host.0).is_some_and(|entry| entry.site == Some(site))
                && self.addresses(*host).contains(&address)
        })
    }

    fn lossy(&mut self, site: SiteId, family: IpFamily) -> bool {
        use rand_chacha::rand_core::RngCore as _;
        let permille = self
            .sites
            .get(site.0)
            .and_then(|site| site.impairment.get(family.index()))
            .map_or(0, |impairment| impairment.loss_permille);
        permille > 0 && self.random.next_u32() % 1000 < u32::from(permille)
    }

    fn mtu_exceeded(&self, site: SiteId, family: IpFamily, bytes: usize) -> bool {
        self.sites
            .get(site.0)
            .and_then(|site| site.impairment.get(family.index()))
            .and_then(|impairment| impairment.max_datagram_bytes)
            .is_some_and(|limit| bytes > limit)
    }

    /// Routes one datagram and queues it, returning the reader to wake.
    fn route(
        &mut self,
        sender: HostId,
        port: u16,
        destination: SocketAddr,
        bytes: &[u8],
        now: tokio::time::Instant,
    ) -> Result<Option<Waker>, Discard> {
        let (site, _, _) = self.site_of(sender).ok_or(Discard::NoRoute)?;
        let source_ip = self.source_for(sender, destination.ip()).ok_or(Discard::NoRoute)?;
        let family = IpFamily::from_address(destination.ip());
        // On-link delivery never crosses the gateway, so it is neither
        // translated nor filtered nor subject to uplink loss.
        if let Some(host) = self.host_at(site, destination.ip()) {
            let queued = self.queue(
                now,
                &Arrival {
                    host,
                    port: destination.port(),
                    source: SocketAddr::new(source_ip, port),
                    destination: destination.ip(),
                },
                bytes,
            );
            if queued.is_ok() {
                *self.stats.on_link_delivered.entry((sender, host)).or_default() += 1;
            }
            return queued;
        }
        let outside = match (source_ip, destination) {
            (IpAddr::V4(source), SocketAddr::V4(destination)) => {
                self.outbound_v4(site, sender, SocketAddrV4::new(source, port), destination, now)?
            }
            (IpAddr::V6(source), SocketAddr::V6(destination)) => {
                let source = SocketAddrV6::new(source, port, 0, 0);
                self.sites
                    .get_mut(site.0)
                    .ok_or(Discard::NoRoute)?
                    .firewall
                    .outbound(source, destination, now);
                SocketAddr::V6(source)
            }
            _ => return Err(Discard::NoRoute),
        };
        if self.mtu_exceeded(site, family, bytes.len()) {
            return Err(Discard::MtuBlackHole);
        }
        if self.lossy(site, family) {
            return Err(Discard::Loss);
        }
        let arrival = self.inbound(outside, destination, site, now)?;
        let receiving = self
            .site_of(arrival.host)
            .map(|(site, _, _)| site)
            .ok_or(Discard::Unaddressed)?;
        if receiving != site && self.mtu_exceeded(receiving, family, bytes.len()) {
            return Err(Discard::MtuBlackHole);
        }
        if receiving != site && self.lossy(receiving, family) {
            return Err(Discard::Loss);
        }
        let delay = [site, receiving]
            .iter()
            .filter_map(|site| self.sites.get(site.0))
            .filter_map(|site| site.impairment.get(family.index()))
            .map(|impairment| impairment.latency)
            .sum::<Duration>();
        self.queue(now + delay, &arrival, bytes)
    }

    fn outbound_v4(
        &mut self,
        site: SiteId,
        sender: HostId,
        source: SocketAddrV4,
        destination: SocketAddrV4,
        now: tokio::time::Instant,
    ) -> Result<SocketAddr, Discard> {
        let entry = self.sites.get_mut(site.0).ok_or(Discard::NoRoute)?;
        let Some(table) = entry.nat.as_mut() else {
            return Ok(SocketAddr::V4(source));
        };
        if is_private(*destination.ip()) {
            // Another network's private address is not routed off this link.
            return Err(Discard::Unaddressed);
        }
        table
            .outbound(sender, source, destination, now, &mut self.random)
            .map(SocketAddr::V4)
    }

    /// Finds the host that receives a datagram arriving from `source`.
    fn inbound(
        &mut self,
        source: SocketAddr,
        destination: SocketAddr,
        from_site: SiteId,
        now: tokio::time::Instant,
    ) -> Result<Arrival, Discard> {
        match destination {
            SocketAddr::V4(destination) => {
                for index in 0..self.sites.len() {
                    let site = SiteId(index);
                    let Some(entry) = self.sites.get_mut(index) else {
                        continue;
                    };
                    if let Some(table) = entry.nat.as_mut()
                        && table.public() == *destination.ip()
                    {
                        if site == from_site && !table.hairpins() {
                            return Err(Discard::NoHairpin);
                        }
                        let SocketAddr::V4(remote) = source else {
                            return Err(Discard::Unaddressed);
                        };
                        let (host, port) = table.inbound(remote, destination.port(), now)?;
                        let address = self.v4_of(host).ok_or(Discard::NoRoute)?;
                        return Ok(Arrival {
                            host,
                            port,
                            source,
                            destination: IpAddr::V4(address),
                        });
                    }
                    if matches!(entry.spec.v4, Some(V4Access::Public { .. }))
                        && let Some(host) = self.host_at(site, IpAddr::V4(*destination.ip()))
                    {
                        return Ok(Arrival {
                            host,
                            port: destination.port(),
                            source,
                            destination: IpAddr::V4(*destination.ip()),
                        });
                    }
                }
                Err(Discard::Unaddressed)
            }
            SocketAddr::V6(destination) => {
                let site = (0..self.sites.len())
                    .map(SiteId)
                    .find(|site| self.host_at(*site, IpAddr::V6(*destination.ip())).is_some())
                    .ok_or(Discard::Unaddressed)?;
                let host = self
                    .host_at(site, IpAddr::V6(*destination.ip()))
                    .ok_or(Discard::Unaddressed)?;
                let SocketAddr::V6(remote) = source else {
                    return Err(Discard::Unaddressed);
                };
                self.sites
                    .get_mut(site.0)
                    .ok_or(Discard::Unaddressed)?
                    .firewall
                    .inbound(host, destination, remote, now)?;
                Ok(Arrival {
                    host,
                    port: destination.port(),
                    source,
                    destination: IpAddr::V6(*destination.ip()),
                })
            }
        }
    }

    fn queue(
        &mut self,
        ready_at: tokio::time::Instant,
        arrival: &Arrival,
        bytes: &[u8],
    ) -> Result<Option<Waker>, Discard> {
        let inbox = self
            .hosts
            .get_mut(arrival.host.0)
            .and_then(|host| host.sockets.get_mut(&arrival.port))
            .ok_or(Discard::NoListener)?;
        if inbox.queue.len() >= MAX_QUEUED_DATAGRAMS {
            return Err(Discard::QueueFull);
        }
        inbox.queue.push_back(Received {
            source: arrival.source,
            destination: arrival.destination,
            bytes: bytes.to_vec(),
            ready_at,
        });
        Ok(inbox.reader.take())
    }
}

fn offset_v4(base: Ipv4Addr, offset: u8) -> Ipv4Addr {
    let [a, b, c, d] = base.octets();
    Ipv4Addr::new(a, b, c, d.saturating_add(offset))
}

fn is_private(address: Ipv4Addr) -> bool {
    address.is_private() || address.is_loopback() || address.is_link_local()
}

/// Unwraps an IPv4-mapped IPv6 destination to the IPv4 the OS would send to.
fn canonical(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map_or(address, |v4| SocketAddr::new(IpAddr::V4(v4), v6.port())),
        SocketAddr::V4(_) => address,
    }
}

/// Lifetime helper for scenarios: the default RFC 4787 minimum UDP mapping
/// timeout of two minutes.
pub const RFC4787_MIN_TIMEOUT: Duration = Duration::from_mins(2);
