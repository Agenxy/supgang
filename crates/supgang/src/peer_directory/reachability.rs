//! Memory-only reachability claim admission and lookup.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
};

use crate::{
    ids::NodeId,
    reachability::{MAX_REACHABILITY_CLAIMS, ReachabilityClaim, ReachabilityError, ReachabilitySource},
};

use super::{PeerDirectory, PeerDirectoryError};

const MAX_CLAIMS_PER_REPORTER: usize = 4;

impl PeerDirectory {
    pub(crate) fn remember_authenticated_route(
        &mut self,
        device: &crate::identity::DeviceIdentity,
        contact: &crate::contact::PeerContact,
        address: SocketAddr,
        local_ip: Option<std::net::IpAddr>,
        now: u64,
    ) -> Result<(), PeerDirectoryError> {
        contact.verify(&self.root_key, now)?;
        let record = &contact.endpoint.record;
        if device.node_id() != self.local_node {
            return Err(PeerDirectoryError::InvalidRouteHistory);
        }
        if self.revocations.contains(&record.node_id)
            || self
                .entries
                .get(&record.node_id)
                .is_none_or(super::PeerEntry::is_conflicted)
        {
            return Ok(());
        }
        self.routes
            .remember(device, record.node_id, record.transport_key_id, address, local_ip, now)
    }

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
        // Gossip must not resurrect a withdrawn local gateway observation.
        // Locally generated gateway state enters only through its owning API.
        if claim.reporter == self.local_node {
            return Ok(false);
        }
        let address = claim.candidate()?.address();
        if self.revocations.contains(&claim.subject)
            || self.revocations.contains(&claim.reporter)
            || address.ip().is_loopback()
            || matches!(address.ip(), std::net::IpAddr::V6(address) if address.is_unicast_link_local())
        {
            return Err(PeerDirectoryError::Reachability(ReachabilityError::InvalidAddress));
        }
        self.prune_reachability(now);
        let key = (claim.subject, address, claim.reporter);
        if self
            .reachability
            .get(&key)
            .is_some_and(|existing| existing.issued_at >= claim.issued_at && existing.expires_at >= claim.expires_at)
        {
            return Ok(false);
        }
        if !self.reachability.contains_key(&key) && !self.reserve_reachability_slot(claim.reporter, false) {
            return Ok(false);
        }
        self.reachability.insert(key, claim);
        Ok(true)
    }

    pub(crate) fn replace_local_gateway_reachability(
        &mut self,
        claim: Option<ReachabilityClaim>,
        now: u64,
    ) -> Result<bool, PeerDirectoryError> {
        self.prune_reachability(now);
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
            if !self.reserve_reachability_slot(self.local_node, true) {
                return Err(PeerDirectoryError::Reachability(ReachabilityError::InvalidAddress));
            }
            self.reachability
                .insert((candidate.subject, candidate.address, candidate.reporter), candidate);
        }
        Ok(true)
    }

    fn reserve_reachability_slot(&mut self, reporter: NodeId, local_gateway: bool) -> bool {
        let mut counts = BTreeMap::<NodeId, usize>::new();
        for claim in self
            .reachability
            .values()
            .filter(|claim| claim.reporter != self.local_node)
        {
            *counts.entry(claim.reporter).or_default() += 1;
        }
        let own = counts.get(&reporter).copied().unwrap_or_default();
        let full = self.reachability.len() >= MAX_REACHABILITY_CLAIMS;
        let victim = if own >= MAX_CLAIMS_PER_REPORTER || (full && own > 0) {
            reporter
        } else if !full {
            return true;
        } else if let Some((largest, count)) = counts.into_iter().max_by_key(|(_, count)| *count) {
            // A new reporter can take an excess slot, not another reporter's
            // only observation. The local gateway always keeps one slot.
            if !local_gateway && count <= 1 {
                return false;
            }
            largest
        } else {
            return false;
        };
        if let Some(oldest) = self
            .reachability
            .iter()
            .filter(|(_, claim)| claim.reporter == victim)
            .min_by_key(|(_, claim)| claim.expires_at)
            .map(|(key, _)| *key)
        {
            self.reachability.remove(&oldest);
            return true;
        }
        false
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
            .map(|claim| crate::candidate::canonical_socket_address(claim.address))
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
