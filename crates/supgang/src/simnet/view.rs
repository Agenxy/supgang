//! The interface and route answers a simulated host's operating system gives.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use super::{HostId, Network};

/// What one simulated host's operating system reports about its interfaces
/// and routes, read live so a move between sites is seen immediately.
#[derive(Debug)]
pub struct HostView {
    network: Arc<Network>,
    host: HostId,
}

impl HostView {
    pub const fn new(network: Arc<Network>, host: HostId) -> Self {
        Self { network, host }
    }
}

impl crate::network::simulated::View for HostView {
    fn interfaces(&self) -> Vec<crate::network::InterfaceNetwork> {
        self.network
            .host_addresses(self.host)
            .unwrap_or_default()
            .into_iter()
            .map(|address| {
                let netmask = match address {
                    IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
                    IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0)),
                };
                crate::network::InterfaceNetwork::new(address, netmask)
            })
            .collect()
    }

    fn route_exists(&self, remote: SocketAddr) -> bool {
        self.network.has_route(self.host, remote.ip()).unwrap_or(false)
    }
}
