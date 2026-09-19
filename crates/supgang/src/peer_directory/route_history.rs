//! Locally attested successful routes, never gossiped as endpoint authority.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::Path,
};

use serde::{Deserialize, Serialize};

use super::PeerDirectoryError;
use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate, canonical_socket_address},
    identity::{DeviceIdentity, verify_domain},
    ids::{NodeId, TransportKeyId},
    journal::{Journal, JournalError},
    network::InterfaceNetwork,
    state::MAX_HIVE_MEMBERS,
};

const FILE: &str = "successful-routes.journal";
const DOMAIN: &[u8] = b"supgang/local-successful-route/v1\0";
const MAX_FRAME: usize = 768;
const COMPACT_AFTER: u64 = 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Route {
    peer: NodeId,
    pin: TransportKeyId,
    address: SocketAddr,
    local_ip: Option<IpAddr>,
    observed_at: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Attestation {
    route: Route,
    recorder_key: [u8; 32],
    signature: String,
}

pub(super) struct RouteHistory {
    records: BTreeMap<NodeId, Vec<Attestation>>,
    journal: Option<Journal>,
    limit: usize,
    compact_at: u64,
}

impl RouteHistory {
    pub(super) const fn empty(limit: usize) -> Self {
        Self {
            records: BTreeMap::new(),
            journal: None,
            limit,
            compact_at: COMPACT_AFTER,
        }
    }
    pub(super) fn open(
        directory: &Path,
        local: NodeId,
        limit: usize,
        read_only: bool,
    ) -> Result<Self, PeerDirectoryError> {
        let path = directory.join(FILE);
        let (journal, frames) = if read_only {
            let frames = match Journal::read(path) {
                Ok(frames) => frames,
                Err(JournalError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(error) => return Err(error.into()),
            };
            (None, frames)
        } else {
            let (journal, frames) = Journal::open(path)?;
            (Some(journal), frames)
        };
        let mut result = Self {
            records: BTreeMap::new(),
            journal,
            limit,
            compact_at: COMPACT_AFTER,
        };
        for frame in frames {
            if frame.len() > MAX_FRAME {
                return Err(PeerDirectoryError::InvalidRouteHistory);
            }
            let attestation: Attestation =
                serde_json::from_slice(&frame).map_err(|_| PeerDirectoryError::InvalidRouteHistory)?;
            attestation.verify(local)?;
            result.insert(attestation)?;
        }
        if !read_only {
            result.compact_if_needed()?;
        }
        Ok(result)
    }

    pub(super) fn remember(
        &mut self,
        device: &DeviceIdentity,
        peer: NodeId,
        pin: TransportKeyId,
        address: SocketAddr,
        local_ip: Option<IpAddr>,
        now: u64,
    ) -> Result<(), PeerDirectoryError> {
        let address = canonical_socket_address(address);
        let private = is_private(address);
        // Private paths require the same local interface address when reused.
        // No guessed network context is persisted when the socket lacks it.
        if private && local_ip.is_none() {
            return Ok(());
        }
        let route = Route {
            peer,
            pin,
            address,
            local_ip: private.then_some(local_ip).flatten(),
            observed_at: now,
        };
        route.validate()?;
        if self.records.get(&peer).is_some_and(|records| {
            records.iter().any(|record| {
                record.route.address == address
                    && record.route.pin == pin
                    && record.route.local_ip == route.local_ip
                    && now.saturating_sub(record.route.observed_at) < 3600
            })
        }) {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&route).map_err(|_| PeerDirectoryError::InvalidRouteHistory)?;
        let record = Attestation {
            route,
            recorder_key: device.verifying_key().to_bytes(),
            signature: hex::encode(device.sign_domain(DOMAIN, &bytes)),
        };
        record.verify(device.node_id())?;
        let encoded = serde_json::to_vec(&record).map_err(|_| PeerDirectoryError::InvalidRouteHistory)?;
        if encoded.len() > MAX_FRAME {
            return Err(PeerDirectoryError::InvalidRouteHistory);
        }
        if !self.records.contains_key(&peer) && self.records.len() >= MAX_HIVE_MEMBERS - 1 {
            return Err(PeerDirectoryError::DirectoryFull);
        }
        self.journal
            .as_mut()
            .ok_or(PeerDirectoryError::ReadOnlySnapshot)?
            .append(&encoded)?;
        self.insert(record)?;
        self.compact_if_needed()
    }

    pub(super) fn addresses(
        &self,
        peer: NodeId,
        pin: TransportKeyId,
        networks: &[InterfaceNetwork],
    ) -> Vec<SocketAddr> {
        self.records
            .get(&peer)
            .into_iter()
            .flatten()
            .filter(|record| {
                record.route.pin == pin
                    && record
                        .route
                        .local_ip
                        .is_none_or(|ip| networks.iter().any(|network| network.address() == ip))
            })
            .map(|record| record.route.address)
            .collect()
    }

    fn insert(&mut self, record: Attestation) -> Result<(), PeerDirectoryError> {
        if !self.records.contains_key(&record.route.peer) && self.records.len() >= MAX_HIVE_MEMBERS - 1 {
            return Err(PeerDirectoryError::DirectoryFull);
        }
        let records = self.records.entry(record.route.peer).or_default();
        records.retain(|old| {
            old.route.address != record.route.address
                || old.route.pin != record.route.pin
                || old.route.local_ip != record.route.local_ip
        });
        records.insert(0, record);
        records.truncate(self.limit);
        Ok(())
    }

    fn compact_if_needed(&mut self) -> Result<(), PeerDirectoryError> {
        let journal = self.journal.as_mut().ok_or(PeerDirectoryError::ReadOnlySnapshot)?;
        if journal.byte_len()? < self.compact_at {
            return Ok(());
        }
        let frames = self
            .records
            .values()
            .flat_map(|records| records.iter().rev())
            .map(serde_json::to_vec)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PeerDirectoryError::InvalidRouteHistory)?;
        journal.compact(&frames)?;
        self.compact_at = journal.byte_len()?.saturating_add(COMPACT_AFTER);
        Ok(())
    }
}

impl Route {
    fn validate(&self) -> Result<(), PeerDirectoryError> {
        let valid = EndpointCandidate::new(CandidateKind::Local, CandidateTransport::QuicV1, self.address)
            .or_else(|_| EndpointCandidate::new(CandidateKind::Reflexive, CandidateTransport::QuicV1, self.address))
            .is_ok();
        if !valid
            || self.address != canonical_socket_address(self.address)
            || self.observed_at == 0
            || (is_private(self.address) && self.local_ip.is_none())
        {
            return Err(PeerDirectoryError::InvalidRouteHistory);
        }
        Ok(())
    }
}

impl Attestation {
    fn verify(&self, local: NodeId) -> Result<(), PeerDirectoryError> {
        self.route.validate()?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.recorder_key)
            .map_err(|_| PeerDirectoryError::InvalidRouteHistory)?;
        let signature: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| PeerDirectoryError::InvalidRouteHistory)?
            .try_into()
            .map_err(|_| PeerDirectoryError::InvalidRouteHistory)?;
        let bytes = serde_json::to_vec(&self.route).map_err(|_| PeerDirectoryError::InvalidRouteHistory)?;
        if NodeId::from_verifying_key(&self.recorder_key) != local
            || self.route.peer == local
            || !verify_domain(&key, DOMAIN, &bytes, &signature)
        {
            return Err(PeerDirectoryError::InvalidRouteHistory);
        }
        Ok(())
    }
}

fn is_private(address: SocketAddr) -> bool {
    EndpointCandidate::new(CandidateKind::Local, CandidateTransport::QuicV1, address).is_ok()
}

#[cfg(test)]
mod tests {
    use super::RouteHistory;
    use crate::{identity::DeviceIdentity, ids::TransportKeyId, network::InterfaceNetwork};
    use std::net::IpAddr;

    #[test]
    fn successful_routes_survive_restart_but_require_pin_and_private_context() -> Result<(), Box<dyn std::error::Error>>
    {
        let temporary = tempfile::tempdir()?;
        let local = DeviceIdentity::generate()?;
        let peer = DeviceIdentity::generate()?.node_id();
        let pin = TransportKeyId::from_bytes([7; 32]);
        let interface: IpAddr = "192.168.2.3".parse()?;
        let mut history = RouteHistory::open(temporary.path(), local.node_id(), 8, false)?;
        for port in 1..=12 {
            history.remember(&local, peer, pin, format!("8.8.8.8:{port}").parse()?, None, 100)?;
        }
        let private = "192.168.2.4:44330".parse()?;
        history.remember(&local, peer, pin, private, Some(interface), 101)?;
        drop(history);
        let restored = RouteHistory::open(temporary.path(), local.node_id(), 8, true)?;
        let matching = [InterfaceNetwork::new(interface, "255.255.255.0".parse()?)];
        assert_eq!(restored.addresses(peer, pin, &matching).len(), 8);
        assert!(restored.addresses(peer, pin, &matching).contains(&private));
        assert_eq!(restored.addresses(peer, pin, &[]).len(), 7);
        assert!(
            restored
                .addresses(peer, TransportKeyId::from_bytes([8; 32]), &matching)
                .is_empty()
        );
        assert!(RouteHistory::open(temporary.path(), DeviceIdentity::generate()?.node_id(), 8, true).is_err());
        Ok(())
    }

    #[test]
    fn address_or_pin_tampering_fails_local_attestation() -> Result<(), Box<dyn std::error::Error>> {
        let local = DeviceIdentity::generate()?;
        let route = super::Route {
            peer: DeviceIdentity::generate()?.node_id(),
            pin: TransportKeyId::from_bytes([1; 32]),
            address: "8.8.8.8:44330".parse()?,
            local_ip: None,
            observed_at: 1,
        };
        let signature = hex::encode(local.sign_domain(super::DOMAIN, &serde_json::to_vec(&route)?));
        let mut record = super::Attestation {
            route,
            recorder_key: local.verifying_key().to_bytes(),
            signature,
        };
        record.verify(local.node_id())?;
        record.route.pin = TransportKeyId::from_bytes([2; 32]);
        assert!(record.verify(local.node_id()).is_err());
        Ok(())
    }
}
