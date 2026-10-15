//! Gateway translation and stateful filtering, parameterised by the RFC 4787
//! behaviour categories so one table models full-cone, restricted and
//! symmetric gateways, and an IPv6 firewall with default inbound denial.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{Ipv4Addr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use rand_chacha::{ChaCha8Rng, rand_core::RngCore as _};
use tokio::time::Instant;

use super::{Discard, HostId};

/// Mappings and dynamic firewall entries a single gateway may hold.
const MAX_ENTRIES: usize = 4096;
/// Remote endpoints remembered per mapping for filtering decisions.
const MAX_PERMITTED: usize = 64;
const FORWARD_LIMIT: usize = 16;
const FIRST_DYNAMIC_PORT: u16 = 1024;

/// What a mapping or filter depends on, in RFC 4787's terms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Behavior {
    /// Only the internal endpoint: one mapping for every destination, and any
    /// remote endpoint may send inbound once the mapping exists.
    EndpointIndependent,
    /// The internal endpoint and the remote address.
    AddressDependent,
    /// The internal endpoint, remote address and remote port.
    AddressAndPortDependent,
}

/// How a gateway chooses the external port of a new mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortAssignment {
    /// Reuse the internal port when free, as many home gateways do.
    Preserve,
    /// Hand out ports in increasing order.
    Sequential,
    /// Choose ports pseudo-randomly from the network's seeded generator.
    Random,
}

/// The behaviour of one IPv4 gateway.
#[derive(Clone, Debug)]
pub struct Nat44 {
    pub mapping: Behavior,
    pub filtering: Behavior,
    pub ports: PortAssignment,
    /// Idle time after which a dynamic mapping is forgotten.
    pub timeout: Duration,
    /// Whether inbound traffic also keeps a mapping alive.
    pub inbound_refresh: bool,
    /// Whether hosts reach each other through the gateway's public address.
    pub hairpin: bool,
}

impl Nat44 {
    /// RFC 4787's recommended gateway: endpoint-independent mapping with
    /// address-and-port-dependent filtering, port preservation and hairpinning.
    /// Most home routers behave like this.
    pub const fn home_router() -> Self {
        Self {
            mapping: Behavior::EndpointIndependent,
            filtering: Behavior::AddressAndPortDependent,
            ports: PortAssignment::Preserve,
            timeout: super::RFC4787_MIN_TIMEOUT,
            inbound_refresh: false,
            hairpin: true,
        }
    }

    /// A "symmetric" gateway: a new random external port for every remote
    /// endpoint, with matching filtering. Common on enterprise, hotel and some
    /// carrier networks, and the hardest case for direct connections.
    pub const fn symmetric() -> Self {
        Self {
            mapping: Behavior::AddressAndPortDependent,
            filtering: Behavior::AddressAndPortDependent,
            ports: PortAssignment::Random,
            timeout: Duration::from_secs(30),
            inbound_refresh: false,
            hairpin: false,
        }
    }

    /// A permissive "full cone" gateway.
    pub const fn full_cone() -> Self {
        Self {
            mapping: Behavior::EndpointIndependent,
            filtering: Behavior::EndpointIndependent,
            ports: PortAssignment::Preserve,
            timeout: super::RFC4787_MIN_TIMEOUT,
            inbound_refresh: true,
            hairpin: true,
        }
    }
}

/// The inbound policy of a site's IPv6 side.
#[derive(Clone, Debug)]
pub enum Firewall6 {
    /// Every global address accepts unsolicited inbound traffic.
    Open,
    /// RFC 6092 simple security: inbound only answers traffic the host sent
    /// first, matched by `filtering`, or reaches an explicit pinhole.
    Stateful { filtering: Behavior, timeout: Duration },
}

impl Firewall6 {
    pub const fn default_deny() -> Self {
        Self::Stateful {
            filtering: Behavior::AddressAndPortDependent,
            timeout: super::RFC4787_MIN_TIMEOUT,
        }
    }
}

#[derive(Debug)]
struct Mapping {
    host: HostId,
    internal: SocketAddrV4,
    external_port: u16,
    permitted: BTreeSet<SocketAddrV4>,
    expires: Instant,
}

/// One IPv4 gateway's live translation state.
#[derive(Debug)]
pub(super) struct Table {
    config: Nat44,
    public: Ipv4Addr,
    mappings: Vec<Mapping>,
    forwards: BTreeMap<u16, (HostId, u16)>,
    next_port: u16,
}

impl Table {
    pub(super) const fn new(config: Nat44, public: Ipv4Addr) -> Self {
        Self {
            config,
            public,
            mappings: Vec::new(),
            forwards: BTreeMap::new(),
            next_port: 20_000,
        }
    }

    pub(super) const fn public(&self) -> Ipv4Addr {
        self.public
    }

    pub(super) const fn hairpins(&self) -> bool {
        self.config.hairpin
    }

    pub(super) fn renumber(&mut self, public: Ipv4Addr) {
        self.public = public;
        self.mappings.clear();
    }

    pub(super) fn forward(&mut self, external_port: u16, host: HostId, port: u16) -> io::Result<()> {
        if external_port == 0 || port == 0 || self.forwards.len() >= FORWARD_LIMIT {
            return Err(io::Error::other("invalid simulated forward"));
        }
        self.forwards.insert(external_port, (host, port));
        Ok(())
    }

    fn expire(&mut self, now: Instant) {
        self.mappings.retain(|mapping| mapping.expires > now);
    }

    fn matches(behavior: Behavior, permitted: SocketAddrV4, remote: SocketAddrV4) -> bool {
        match behavior {
            Behavior::EndpointIndependent => true,
            Behavior::AddressDependent => permitted.ip() == remote.ip(),
            Behavior::AddressAndPortDependent => permitted == remote,
        }
    }

    fn port_free(&self, port: u16) -> bool {
        port >= FIRST_DYNAMIC_PORT
            && !self.forwards.contains_key(&port)
            && self.mappings.iter().all(|mapping| mapping.external_port != port)
    }

    fn allocate(&mut self, internal: u16, random: &mut ChaCha8Rng) -> Result<u16, Discard> {
        if self.config.ports == PortAssignment::Preserve && self.port_free(internal) {
            return Ok(internal);
        }
        for _ in 0..u16::MAX {
            let candidate = if self.config.ports == PortAssignment::Random {
                let span = u32::from(u16::MAX - FIRST_DYNAMIC_PORT);
                u16::try_from(random.next_u32() % span).map_or(FIRST_DYNAMIC_PORT, |offset| FIRST_DYNAMIC_PORT + offset)
            } else {
                let port = self.next_port;
                self.next_port = self.next_port.checked_add(1).unwrap_or(FIRST_DYNAMIC_PORT);
                port
            };
            if self.port_free(candidate) {
                return Ok(candidate);
            }
        }
        Err(Discard::NoRoute)
    }

    /// Translates an outbound datagram, creating or refreshing its mapping.
    pub(super) fn outbound(
        &mut self,
        host: HostId,
        internal: SocketAddrV4,
        remote: SocketAddrV4,
        now: Instant,
        random: &mut ChaCha8Rng,
    ) -> Result<SocketAddrV4, Discard> {
        // A forward is a static two-way mapping: what the forwarded host sends
        // from that port leaves from the forwarded external port, as connection
        // tracking reverses the translation for replies on real gateways.
        if let Some(external) = self
            .forwards
            .iter()
            .find(|(_, target)| **target == (host, internal.port()))
            .map(|(external, _)| *external)
        {
            return Ok(SocketAddrV4::new(self.public, external));
        }
        self.expire(now);
        let mapping_kind = self.config.mapping;
        let existing = self.mappings.iter().position(|mapping| {
            mapping.internal == internal
                && match mapping_kind {
                    Behavior::EndpointIndependent => true,
                    // A dependent mapping is keyed by the first remote it served.
                    _ => mapping
                        .permitted
                        .iter()
                        .next()
                        .is_some_and(|first| Self::matches(mapping_kind, *first, remote)),
                }
        });
        let index = if let Some(index) = existing {
            index
        } else {
            if self.mappings.len() >= MAX_ENTRIES {
                return Err(Discard::NoRoute);
            }
            let external_port = self.allocate(internal.port(), random)?;
            self.mappings.push(Mapping {
                host,
                internal,
                external_port,
                permitted: BTreeSet::new(),
                expires: now,
            });
            self.mappings.len() - 1
        };
        let timeout = self.config.timeout;
        let mapping = self.mappings.get_mut(index).ok_or(Discard::NoRoute)?;
        if mapping.permitted.len() < MAX_PERMITTED {
            mapping.permitted.insert(remote);
        }
        mapping.expires = now + timeout;
        Ok(SocketAddrV4::new(self.public, mapping.external_port))
    }

    /// Finds the internal destination for an inbound datagram, if any.
    pub(super) fn inbound(&mut self, remote: SocketAddrV4, port: u16, now: Instant) -> Result<(HostId, u16), Discard> {
        if let Some(target) = self.forwards.get(&port) {
            return Ok(*target);
        }
        self.expire(now);
        let filtering = self.config.filtering;
        let refresh = self.config.inbound_refresh.then_some(now + self.config.timeout);
        let mapping = self
            .mappings
            .iter_mut()
            .find(|mapping| mapping.external_port == port)
            .ok_or(Discard::NoMapping)?;
        if !mapping
            .permitted
            .iter()
            .any(|permitted| Self::matches(filtering, *permitted, remote))
        {
            return Err(Discard::Filtered);
        }
        if let Some(expires) = refresh {
            mapping.expires = expires;
        }
        Ok((mapping.host, mapping.internal.port()))
    }
}

#[derive(Debug)]
struct Allowance {
    local: SocketAddrV6,
    permitted: BTreeSet<SocketAddrV6>,
    expires: Instant,
}

/// One site's IPv6 inbound policy and its dynamic state.
#[derive(Debug)]
pub(super) struct FirewallTable {
    policy: Option<Firewall6>,
    allowances: Vec<Allowance>,
    pinholes: BTreeSet<(HostId, u16)>,
}

impl FirewallTable {
    pub(super) const fn new(policy: Option<Firewall6>) -> Self {
        Self {
            policy,
            allowances: Vec::new(),
            pinholes: BTreeSet::new(),
        }
    }

    pub(super) fn pinhole(&mut self, host: HostId, port: u16) -> io::Result<()> {
        if port == 0 || self.pinholes.len() >= FORWARD_LIMIT {
            return Err(io::Error::other("invalid simulated pinhole"));
        }
        self.pinholes.insert((host, port));
        Ok(())
    }

    pub(super) fn outbound(&mut self, local: SocketAddrV6, remote: SocketAddrV6, now: Instant) {
        let Some(Firewall6::Stateful { timeout, .. }) = self.policy else {
            return;
        };
        self.allowances.retain(|allowance| allowance.expires > now);
        let index = self
            .allowances
            .iter()
            .position(|allowance| allowance.local == local)
            .or_else(|| {
                (self.allowances.len() < MAX_ENTRIES).then(|| {
                    self.allowances.push(Allowance {
                        local,
                        permitted: BTreeSet::new(),
                        expires: now,
                    });
                    self.allowances.len() - 1
                })
            });
        if let Some(allowance) = index.and_then(|index| self.allowances.get_mut(index)) {
            if allowance.permitted.len() < MAX_PERMITTED {
                allowance.permitted.insert(remote);
            }
            allowance.expires = now + timeout;
        }
    }

    pub(super) fn inbound(
        &mut self,
        host: HostId,
        local: SocketAddrV6,
        remote: SocketAddrV6,
        now: Instant,
    ) -> Result<(), Discard> {
        let Some(Firewall6::Stateful { filtering, .. }) = self.policy else {
            return Ok(());
        };
        if self.pinholes.contains(&(host, local.port())) {
            return Ok(());
        }
        self.allowances.retain(|allowance| allowance.expires > now);
        let allowed = self.allowances.iter().any(|allowance| {
            allowance.local == local
                && allowance.permitted.iter().any(|permitted| match filtering {
                    Behavior::EndpointIndependent => true,
                    Behavior::AddressDependent => permitted.ip() == remote.ip(),
                    Behavior::AddressAndPortDependent => {
                        permitted.ip() == remote.ip() && permitted.port() == remote.port()
                    }
                })
        });
        if allowed { Ok(()) } else { Err(Discard::Firewall) }
    }
}
