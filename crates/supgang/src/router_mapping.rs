//! Bounded, local-gateway-only UDP port mapping.

use std::{
    net::{SocketAddr, SocketAddrV4},
    num::NonZeroU16,
    time::{Duration, Instant},
};

use portmapper::{Client, Config, Protocol};
use tokio::sync::watch;

use crate::candidate::{CandidateKind, CandidateTransport, EndpointCandidate};

/// Time after which an absent usable mapping is reported as unavailable.
const MAPPING_CHECK_WINDOW: Duration = Duration::from_secs(5);
/// Maximum time spent probing the current gateway before attempting a mapping.
const GATEWAY_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// Grace period for an orderly gateway lease release during service shutdown.
const GATEWAY_RELEASE_GRACE: Duration = Duration::from_secs(1);

/// Current state of automatic local-router mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouterMappingStatus {
    /// Automatic mapping was not enabled for this service configuration.
    Disabled,
    /// Gateway protocols are being probed or a mapping request is pending.
    Checking,
    /// No globally usable mapping was obtained from the current gateway.
    Unavailable,
    /// The gateway returned this external UDP mapping.
    Mapped(SocketAddrV4),
}

impl RouterMappingStatus {
    /// Returns the stable machine-readable state name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Checking => "checking",
            Self::Unavailable => "unavailable",
            Self::Mapped(_) => "mapped-unverified",
        }
    }
}

/// Maintains one UDP lease using PCP or NAT-PMP on the local gateway.
///
/// `UPnP` is deliberately disabled: unauthenticated SSDP responders can supply
/// an arbitrary HTTP description location. The remaining protocols send only
/// to the operating system's selected local gateway.
#[derive(Debug)]
pub struct RouterMapping {
    client: Client,
    external: watch::Receiver<Option<SocketAddrV4>>,
    started: Instant,
    port: NonZeroU16,
    awaiting_network_refresh: bool,
    probe_task: Option<tokio::task::JoinHandle<()>>,
}

impl RouterMapping {
    /// Starts gateway probing and requests a renewable UDP mapping.
    #[must_use]
    pub fn start(port: NonZeroU16) -> Self {
        let client = Client::new(Config {
            enable_upnp: false,
            enable_pcp: true,
            enable_nat_pmp: true,
            protocol: Protocol::Udp,
        });
        let external = client.watch_external_address();
        let probe_task = Some(request_after_probe(client.clone(), port));
        Self {
            client,
            external,
            started: Instant::now(),
            port,
            awaiting_network_refresh: false,
            probe_task,
        }
    }

    /// Removes the old lease and probes the newly selected gateway.
    pub fn network_changed(&mut self) {
        if let Some(probe) = self.probe_task.take() {
            probe.abort();
        }
        self.client.deactivate();
        self.probe_task = Some(request_after_probe(self.client.clone(), self.port));
        self.started = Instant::now();
        self.awaiting_network_refresh = true;
    }

    /// Stops mapping after repeated interface-discovery failure.
    pub fn network_unavailable(&mut self) {
        if let Some(probe) = self.probe_task.take() {
            probe.abort();
        }
        self.client.deactivate();
        self.started = Instant::now();
        self.awaiting_network_refresh = true;
    }

    /// Requests lease deletion and gives the bounded gateway task time to send it.
    pub async fn shutdown(mut self) {
        if let Some(probe) = self.probe_task.take() {
            probe.abort();
            let _cancelled = probe.await;
        }
        self.client.deactivate();
        tokio::time::sleep(GATEWAY_RELEASE_GRACE).await;
    }

    /// Returns the latest mapping state without blocking the service loop.
    #[must_use]
    pub fn status(&self) -> RouterMappingStatus {
        if self.awaiting_network_refresh {
            return if self.started.elapsed() < MAPPING_CHECK_WINDOW {
                RouterMappingStatus::Checking
            } else {
                RouterMappingStatus::Unavailable
            };
        }
        classify_external(*self.external.borrow()).unwrap_or_else(|| {
            if self.started.elapsed() < MAPPING_CHECK_WINDOW {
                RouterMappingStatus::Checking
            } else {
                RouterMappingStatus::Unavailable
            }
        })
    }

    /// Marks the latest watch value observed and returns it if it changed.
    pub fn take_change(&mut self) -> Option<RouterMappingStatus> {
        match self.external.has_changed() {
            Ok(true) => {
                let value = *self.external.borrow_and_update();
                self.awaiting_network_refresh = false;
                Some(classify_external(value).unwrap_or(RouterMappingStatus::Unavailable))
            }
            Ok(false) | Err(_) => None,
        }
    }
}

/// Releases an optional active gateway lease during orderly service shutdown.
pub async fn shutdown(mapping: &mut Option<RouterMapping>) {
    if let Some(mapping) = mapping.take() {
        mapping.shutdown().await;
    }
}

fn classify_external(value: Option<SocketAddrV4>) -> Option<RouterMappingStatus> {
    value.and_then(|address| {
        EndpointCandidate::new(
            CandidateKind::Mapped,
            CandidateTransport::QuicV1,
            SocketAddr::V4(address),
        )
        .is_ok()
        .then_some(RouterMappingStatus::Mapped(address))
    })
}

fn request_after_probe(client: Client, port: NonZeroU16) -> tokio::task::JoinHandle<()> {
    let probe = client.probe();
    tokio::spawn(async move {
        let _probe_result = tokio::time::timeout(GATEWAY_PROBE_TIMEOUT, probe).await;
        client.update_local_port(port);
    })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::{RouterMappingStatus, classify_external};

    #[test]
    fn only_globally_routed_gateway_results_become_mapping_status() {
        let mapped = RouterMappingStatus::Mapped(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 44_330));
        assert_eq!(classify_external(mapped_address(mapped)), Some(mapped));

        let private = RouterMappingStatus::Mapped(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 44_330));
        assert!(classify_external(mapped_address(private)).is_none());

        let shared = RouterMappingStatus::Mapped(SocketAddrV4::new(Ipv4Addr::new(100, 64, 1, 1), 44_330));
        assert!(classify_external(mapped_address(shared)).is_none());
    }

    const fn mapped_address(status: RouterMappingStatus) -> Option<SocketAddrV4> {
        match status {
            RouterMappingStatus::Mapped(address) => Some(address),
            _ => None,
        }
    }
}
