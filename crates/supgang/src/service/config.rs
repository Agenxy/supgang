//! Additional service policy builders kept separate from the runtime loop.

use std::net::SocketAddr;

use crate::candidate::{CandidateKind, CandidateTransport, EndpointCandidate, MAX_CANDIDATES};

use super::{ServiceConfig, ServiceError};

impl ServiceConfig {
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
