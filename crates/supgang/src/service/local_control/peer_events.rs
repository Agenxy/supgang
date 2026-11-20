//! Single-owner processing of bounded authenticated peer events.

use super::{
    ActiveConnection, BTreeMap, BTreeSet, LocalState, NodeId, PeerDirectory, PeerEvent, ServiceError,
    SyncMutationBudget, close_if_revoked, import_received, import_received_reachability, is_current_connection,
    merge_received_revocations, prune_unauthorized, rendezvous, source_is_authorized, unix_time,
};

pub(in crate::service) struct PeerEventState<'a> {
    pub(in crate::service) state_directory: &'a std::path::Path,
    pub(in crate::service) authority_commit: &'a std::sync::Arc<std::sync::Mutex<()>>,
    pub(in crate::service) active: &'a mut BTreeMap<NodeId, ActiveConnection>,
    pub(in crate::service) draining: &'a mut crate::service::draining::DrainingConnections,
    pub(in crate::service) noncanonical_outbound: &'a mut BTreeSet<NodeId>,
    pub(in crate::service) local_state: &'a mut LocalState,
    pub(in crate::service) directory: &'a mut PeerDirectory,
    pub(in crate::service) rendezvous_offers: &'a mut Vec<rendezvous::RendezvousOfferEvent>,
    pub(in crate::service) rendezvous_intents: &'a mut rendezvous::RendezvousIntents,
    pub(in crate::service) sync_budget: &'a mut SyncMutationBudget,
}

pub(in crate::service) fn process_peer_events(
    receiver: &mut tokio::sync::mpsc::Receiver<PeerEvent>,
    state: PeerEventState<'_>,
) -> Result<bool, ServiceError> {
    let PeerEventState {
        state_directory,
        authority_commit,
        active,
        draining,
        noncanonical_outbound,
        local_state,
        directory,
        rendezvous_offers,
        rendezvous_intents,
        sync_budget,
    } = state;
    let mut directory_changed = false;
    while let Ok(event) = receiver.try_recv() {
        if event.source().is_some_and(|(peer, connection_id)| {
            !source_is_authorized(
                active,
                local_state,
                peer,
                connection_id,
                unix_time().unwrap_or(u64::MAX),
            )
        }) {
            continue;
        }
        match event {
            PeerEvent::AgentKeygen {
                peer,
                connection_id,
                request,
                prepared,
                reply,
                permit,
            } => {
                if reply.is_closed() {
                    continue;
                }
                let Some(connection) = active.get(&peer) else {
                    continue;
                };
                let transport = connection.connection().clone();
                let authorization = connection.authorization().clone();
                let _permit = permit;
                // The Secure Enclave preparation already ran on a bounded
                // worker. The final key commit is serialized with all root
                // state and connection changes on this service event thread.
                let created = crate::vault::keygen_member(
                    state_directory,
                    &crate::vault::SecureEnclave,
                    peer,
                    &request,
                    || {
                        !reply.is_closed()
                            && transport.stable_id() == connection_id
                            && transport.close_reason().is_none()
                            && unix_time().is_ok_and(|now| authorization.is_current(now))
                    },
                    authority_commit,
                    prepared,
                )
                .ok()
                .map(|identity| identity.public_key);
                let _sent = reply.send(created);
            }
            PeerEvent::Contacts {
                peer,
                connection_id,
                page,
            } => {
                if is_current_connection(active, peer, connection_id) {
                    if page
                        .revocations
                        .verify(&local_state.identity().root_verifying_key)
                        .is_err()
                    {
                        if let Some(connection) = active.remove(&peer) {
                            connection.invalidate(b"invalid revocation snapshot");
                        }
                        continue;
                    }
                    if merge_received_revocations(local_state, directory, active, draining, page.revocations)? {
                        directory_changed = true;
                    }
                    if close_if_revoked(active, local_state, peer) {
                        continue;
                    }
                    if sync_budget.allow(peer, tokio::time::Instant::now()) {
                        directory_changed |= import_received(directory, page.contacts, unix_time()?)?;
                        // Only the verified current peer record can extend this
                        // live session, and only for its original transport pin
                        // and generation. Gossip from an unproved node cannot.
                        let now = unix_time()?;
                        if let Some(contact) = directory.usable(&peer, now)
                            && let Some(connection) = active.get(&peer)
                        {
                            connection.renew_verified_record(peer, &contact.endpoint.record, now);
                        }
                        directory_changed |= import_received_reachability(directory, page.reachability, unix_time()?);
                    }
                }
            }
            PeerEvent::Revocations {
                peer,
                connection_id,
                revocations,
            } => {
                if !is_current_connection(active, peer, connection_id) {
                    continue;
                }
                if revocations.verify(&local_state.identity().root_verifying_key).is_err() {
                    if let Some(connection) = active.remove(&peer) {
                        connection.invalidate(b"invalid revocation snapshot");
                    }
                    continue;
                }
                if merge_received_revocations(local_state, directory, active, draining, revocations)? {
                    directory_changed = true;
                }
                close_if_revoked(active, local_state, peer);
            }
            PeerEvent::RendezvousRequest {
                peer,
                connection_id,
                rendezvous_id,
                target,
            } => {
                forward_rendezvous_request(active, local_state, peer, connection_id, rendezvous_id, target);
            }
            PeerEvent::RendezvousOffer {
                peer,
                connection_id,
                rendezvous_id,
                target,
                address,
            } => {
                if is_current_connection(active, peer, connection_id)
                    && peer != target
                    && !active.contains_key(&target)
                    && !local_state.revocations().contains(&target)
                    && rendezvous_intents.take(target, peer, connection_id, rendezvous_id, tokio::time::Instant::now())
                    && rendezvous_offers.len() < crate::service::PEER_EVENT_QUEUE
                {
                    rendezvous_offers.push(rendezvous::RendezvousOfferEvent {
                        introducer: peer,
                        rendezvous_id,
                        target,
                        address,
                    });
                }
            }
            PeerEvent::Closed { peer, connection_id } => {
                if is_current_connection(active, peer, connection_id) {
                    if let Some(connection) = active.remove(&peer) {
                        connection.authorization().invalidate();
                    }
                    noncanonical_outbound.remove(&peer);
                }
            }
        }
    }
    prune_unauthorized(active, local_state, unix_time()?);
    noncanonical_outbound.retain(|peer| active.contains_key(peer));
    Ok(directory_changed)
}

fn forward_rendezvous_request(
    active: &BTreeMap<NodeId, ActiveConnection>,
    local_state: &LocalState,
    peer: NodeId,
    connection_id: usize,
    rendezvous_id: [u8; crate::rendezvous::RENDEZVOUS_ID_BYTES],
    target: NodeId,
) {
    if is_current_connection(active, peer, connection_id) && !local_state.revocations().contains(&target) {
        let local_can_introduce = local_state.local_membership().is_some_and(|membership| {
            membership
                .certificate
                .roles
                .contains(crate::membership::MembershipRoles::INTRODUCER)
        });
        if local_can_introduce {
            let _delivered = rendezvous::introduce_active_pair(active, peer, rendezvous_id, target);
        }
    }
}
