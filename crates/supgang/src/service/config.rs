//! Additional service policy builders kept separate from the runtime loop.

use std::net::SocketAddr;

use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate, MAX_CANDIDATES},
    record::{MAX_SERVICE_ADVERTS, ServiceAdvert},
};

use super::{ServiceConfig, ServiceError};

impl ServiceConfig {
    /// Replaces the service advertisements signed into every endpoint record.
    ///
    /// # Errors
    ///
    /// Rejects more advertisements than a record carries.
    pub fn with_services(mut self, services: Vec<ServiceAdvert>) -> Result<Self, ServiceError> {
        if services.len() > MAX_SERVICE_ADVERTS {
            return Err(ServiceError::InvalidConfiguration);
        }
        self.services = services;
        self.services.sort_unstable();
        self.services.dedup();
        Ok(self)
    }

    /// Adds owner-declared public addresses forwarded to the listening socket
    /// by a locally managed gateway.
    ///
    /// # Errors
    ///
    /// Rejects non-global, duplicate, or over-budget mapped addresses.
    pub fn with_mapped_addresses(mut self, addresses: &[SocketAddr]) -> Result<Self, ServiceError> {
        if !addresses.is_empty() && self.listen.ip().is_loopback() {
            return Err(ServiceError::InvalidConfiguration);
        }
        let mut declared = self.candidates.clone();
        for address in addresses {
            let candidate = EndpointCandidate::new(CandidateKind::Mapped, CandidateTransport::QuicV1, *address)
                .map_err(|_| ServiceError::InvalidConfiguration)?;
            if self.candidates.iter().any(|existing| existing.address() == *address) {
                return Err(ServiceError::InvalidConfiguration);
            }
            declared.push(candidate);
        }
        let owner_declared = declared
            .iter()
            .filter(|candidate| matches!(candidate.kind(), CandidateKind::Mapped | CandidateKind::OwnedRelay))
            .count();
        if owner_declared > MAX_CANDIDATES {
            return Err(ServiceError::InvalidConfiguration);
        }
        // An owner-declared forward is the address that works from outside, so
        // it always fits: discovered interface addresses yield, by the same rule
        // the periodic interface refresh applies. Rejecting the whole
        // configuration instead stopped a computer whose interfaces had grown.
        let local = super::interface_refresh::interface_addresses(&declared, CandidateKind::Local);
        let direct = super::interface_refresh::interface_addresses(&declared, CandidateKind::Direct);
        self.candidates = super::interface_refresh::bounded_automatic_interfaces(&local, &direct, &declared);
        Ok(self)
    }
}

use super::{
    DEFAULT_ADDRESS_HISTORY, DEFAULT_RECORD_LIFETIME_SECONDS, DEFAULT_RETRY_SECONDS, MAX_ACTIVE_PEERS,
    MAX_ADDRESS_HISTORY, MAX_ANCHOR_PEERS, MIN_ADDRESS_HISTORY, bounded_automatic_interfaces, interface_addresses,
};
use crate::profile::PeerName;
use std::time::Duration;

impl ServiceConfig {
    /// Creates a strict service configuration from explicit local and direct addresses.
    /// # Errors
    ///
    /// Rejects port zero, absent or excessive advertisements, invalid address
    /// scope, retry below one second, and record lifetime outside one hour to
    /// seven days.
    pub fn new(
        display_name: PeerName,
        listen: SocketAddr,
        local_addresses: &[SocketAddr],
        direct_addresses: &[SocketAddr],
    ) -> Result<Self, ServiceError> {
        if listen.port() == 0 {
            return Err(ServiceError::InvalidConfiguration);
        }
        let count = local_addresses.len().saturating_add(direct_addresses.len());
        if count == 0 || count > MAX_CANDIDATES {
            return Err(ServiceError::InvalidConfiguration);
        }
        let mut candidates = Vec::with_capacity(count);
        for address in local_addresses {
            candidates.push(
                EndpointCandidate::new(CandidateKind::Local, CandidateTransport::QuicV1, *address)
                    .map_err(|_| ServiceError::InvalidConfiguration)?,
            );
        }
        for address in direct_addresses {
            candidates.push(
                EndpointCandidate::new(CandidateKind::Direct, CandidateTransport::QuicV1, *address)
                    .map_err(|_| ServiceError::InvalidConfiguration)?,
            );
        }
        candidates.sort_unstable();
        candidates.dedup();
        Ok(Self {
            display_name,
            listen,
            candidates,
            services: Vec::new(),
            retry_interval: Duration::from_secs(DEFAULT_RETRY_SECONDS),
            record_lifetime: Duration::from_secs(DEFAULT_RECORD_LIFETIME_SECONDS),
            address_history: DEFAULT_ADDRESS_HISTORY,
            automatic_interface_refresh: false,
            automatic_router_mapping: false,
            max_active_peers: MAX_ACTIVE_PEERS,
        })
    }

    /// Replaces retry and record lifetimes after enforcing release bounds.
    ///
    /// # Errors
    ///
    /// Rejects retry below one second and record lifetimes outside one hour to
    /// seven days.
    pub fn with_intervals(mut self, retry: Duration, record_lifetime: Duration) -> Result<Self, ServiceError> {
        if retry < Duration::from_secs(1)
            || !(Duration::from_hours(1)..=Duration::from_hours(168)).contains(&record_lifetime)
        {
            return Err(ServiceError::InvalidConfiguration);
        }
        self.retry_interval = retry;
        self.record_lifetime = record_lifetime;
        Ok(self)
    }

    /// Replaces the per-peer historical-address retry budget.
    ///
    /// # Errors
    ///
    /// Rejects values outside the fixed memory and retry bounds.
    pub fn with_address_history(mut self, address_history: usize) -> Result<Self, ServiceError> {
        if !(MIN_ADDRESS_HISTORY..=MAX_ADDRESS_HISTORY).contains(&address_history) {
            return Err(ServiceError::InvalidConfiguration);
        }
        self.address_history = address_history;
        Ok(self)
    }

    /// Enables side-effect-free interface re-enumeration for automatic mode.
    #[must_use]
    pub fn with_automatic_interface_refresh(mut self, enabled: bool) -> Self {
        self.automatic_interface_refresh = enabled;
        if enabled {
            let local = interface_addresses(&self.candidates, CandidateKind::Local);
            let direct = interface_addresses(&self.candidates, CandidateKind::Direct);
            self.candidates = bounded_automatic_interfaces(&local, &direct, &self.candidates);
        }
        self
    }

    /// Enables renewable local-gateway UDP mapping.
    #[must_use]
    pub const fn with_automatic_router_mapping(mut self, enabled: bool) -> Self {
        self.automatic_router_mapping = enabled;
        self
    }

    /// Enables the larger, still fixed neighbor budget for a user-owned anchor.
    #[must_use]
    pub const fn with_anchor_mode(mut self, enabled: bool) -> Self {
        self.max_active_peers = if enabled { MAX_ANCHOR_PEERS } else { MAX_ACTIVE_PEERS };
        self
    }
}
