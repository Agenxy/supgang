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
        if (!addresses.is_empty() && self.listen.ip().is_loopback())
            || self.candidates.len().saturating_add(addresses.len()) > MAX_CANDIDATES
        {
            return Err(ServiceError::InvalidConfiguration);
        }
        for address in addresses {
            let candidate = EndpointCandidate::new(CandidateKind::Mapped, CandidateTransport::QuicV1, *address)
                .map_err(|_| ServiceError::InvalidConfiguration)?;
            if self.candidates.iter().any(|existing| existing.address() == *address) {
                return Err(ServiceError::InvalidConfiguration);
            }
            self.candidates.push(candidate);
        }
        self.candidates.sort_unstable();
        Ok(self)
    }
}
