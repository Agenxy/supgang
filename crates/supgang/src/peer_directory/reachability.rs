//! Memory-only reachability claim admission and lookup.

use std::{collections::BTreeSet, net::SocketAddr};

use crate::{
    ids::NodeId,
    reachability::{MAX_REACHABILITY_CLAIMS, ReachabilityClaim, ReachabilityError, ReachabilitySource},
};

use super::{PeerDirectory, PeerDirectoryError};

impl PeerDirectory {
    /// Verifies and retains one short-lived, non-authoritative dial claim.
    ///
    /// Claims are intentionally memory-only. They preserve reporter identity
    /// and never advance the subject's durable signed endpoint sequence.
    ///
    /// # Errors
    ///
    /// Rejects invalid, expired, revoked, or cryptographically unauthorized claims.
    pub fn import_reachability(&mut self, claim: ReachabilityClaim, now: u64) -> Result<bool, PeerDirectoryError> {
        claim.verify(&self.root_key, now)?;
        if self.revocations.contains(&claim.subject)
            || self.revocations.contains(&claim.reporter)
            || claim.address.ip().is_loopback()
            || matches!(claim.address.ip(), std::net::IpAddr::V6(address) if address.is_unicast_link_local())
        {
            return Err(PeerDirectoryError::Reachability(ReachabilityError::InvalidAddress));
        }
        self.prune_reachability(now);
        let key = (claim.subject, claim.address, claim.reporter);
        if self
            .reachability
            .get(&key)
            .is_some_and(|existing| existing.issued_at >= claim.issued_at && existing.expires_at >= claim.expires_at)
        {
            return Ok(false);
        }
        if self.reachability.len() >= MAX_REACHABILITY_CLAIMS
            && !self.reachability.contains_key(&key)
            && let Some(oldest) = self
                .reachability
                .iter()
                .min_by_key(|(_, existing)| existing.expires_at)
                .map(|(existing_key, _)| *existing_key)
        {
            self.reachability.remove(&oldest);
        }
        self.reachability.insert(key, claim);
        Ok(true)
    }

    pub(crate) fn replace_local_gateway_reachability(
        &mut self,
        claim: Option<ReachabilityClaim>,
        now: u64,
    ) -> Result<bool, PeerDirectoryError> {
        if let Some(candidate) = claim.as_ref() {
            candidate.verify(&self.root_key, now)?;
            if candidate.source != ReachabilitySource::Gateway
                || candidate.subject != self.local_node
                || candidate.reporter != self.local_node
                || candidate.address.ip().is_loopback()
                || matches!(candidate.address.ip(), std::net::IpAddr::V6(address) if address.is_unicast_link_local())
            {
                return Err(PeerDirectoryError::Reachability(ReachabilityError::InvalidAddress));
            }
        }
        let previous = self
            .reachability
            .values()
            .filter(|existing| {
                existing.source == ReachabilitySource::Gateway
                    && existing.subject == self.local_node
                    && existing.reporter == self.local_node
            })
            .cloned()
            .collect::<Vec<_>>();
        let unchanged = claim.as_ref().map_or(previous.is_empty(), |candidate| {
            previous.as_slice() == core::slice::from_ref(candidate)
        });
        if unchanged {
            return Ok(false);
        }
        self.reachability.retain(|_, existing| {
            existing.source != ReachabilitySource::Gateway
                || existing.subject != self.local_node
                || existing.reporter != self.local_node
        });
        if let Some(candidate) = claim {
            self.reachability
                .insert((candidate.subject, candidate.address, candidate.reporter), candidate);
        }
        Ok(true)
    }

    /// Returns fresh ephemeral claims for bounded anti-entropy.
    #[must_use]
    pub fn reachability_claims(&self, now: u64) -> Vec<ReachabilityClaim> {
        self.reachability
            .values()
            .filter(|claim| claim.expires_at >= now)
            .take(MAX_REACHABILITY_CLAIMS)
            .cloned()
            .collect()
    }

    pub(super) fn reachability_addresses(
        &self,
        subject: NodeId,
        now: u64,
        seen: &mut BTreeSet<SocketAddr>,
    ) -> Vec<SocketAddr> {
        let mut claims = self
            .reachability
            .values()
            .filter(|claim| claim.subject == subject && claim.expires_at >= now)
            .collect::<Vec<_>>();
        claims.sort_unstable_by_key(|claim| match claim.source {
            ReachabilitySource::PeerObserved => 0,
            ReachabilitySource::Gateway => 1,
        });
        claims
            .into_iter()
            .map(|claim| claim.address)
            .filter(|address| seen.insert(*address))
            .collect()
    }

    fn prune_reachability(&mut self, now: u64) {
        self.reachability.retain(|_, claim| {
            claim.expires_at >= now
                && !self.revocations.contains(&claim.subject)
                && !self.revocations.contains(&claim.reporter)
        });
    }
}
