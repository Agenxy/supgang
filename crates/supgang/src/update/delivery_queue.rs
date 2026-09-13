use std::{collections::BTreeSet, fs, io, path::Path};

use serde::{Deserialize, Serialize};

use crate::{artifact, ids::NodeId};

use super::{UPDATE_DIGEST_BYTES, UpdateError, updates_directory};

const DELIVERY_FILE: &str = "peer-deliveries.json";
const DELIVERY_SCHEMA: &str = "supgang.peer-update-deliveries/v1";
const MAX_DELIVERY_BYTES: usize = 4096;
const MAX_QUEUED_DELIVERIES: usize = 4;
const DELIVERY_LIFETIME_SECONDS: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueuedPeerDelivery {
    pub(crate) target: NodeId,
    pub(crate) digest: [u8; UPDATE_DIGEST_BYTES],
    pub(crate) queued_at: u64,
    pub(crate) expires_at: u64,
}

pub struct LoadedPeerDeliveries {
    pub(crate) deliveries: Vec<QueuedPeerDelivery>,
    pub(crate) cleanup_needed: bool,
}

#[derive(Deserialize, Serialize)]
struct DeliveryDocument {
    schema: String,
    deliveries: Vec<QueuedPeerDelivery>,
}

pub fn queue_peer_delivery(
    state_directory: &Path,
    target: NodeId,
    digest: [u8; UPDATE_DIGEST_BYTES],
    now: u64,
) -> Result<QueuedPeerDelivery, UpdateError> {
    let _lock = super::lock::UpdateLock::acquire(state_directory)?;
    drop(super::carriage::outbound_bundle(state_directory, &digest)?);
    let updates = updates_directory(state_directory, true)?;
    let mut deliveries = read(&updates)?;
    deliveries.retain(|delivery| delivery.expires_at > now);
    if deliveries.len() >= MAX_QUEUED_DELIVERIES && !deliveries.iter().any(|value| value.target == target) {
        return Err(UpdateError::Capacity);
    }
    let expires_at = now
        .checked_add(DELIVERY_LIFETIME_SECONDS)
        .ok_or(UpdateError::InvalidBundle)?;
    let queued = QueuedPeerDelivery {
        target,
        digest,
        queued_at: now,
        expires_at,
    };
    deliveries.retain(|value| value.target != target);
    deliveries.push(queued);
    deliveries.sort_by_key(|value| value.target);
    write(&updates, &deliveries)?;
    Ok(queued)
}

pub fn load_peer_deliveries(state_directory: &Path, now: u64) -> Result<LoadedPeerDeliveries, UpdateError> {
    let lock = match super::lock::UpdateLock::acquire(state_directory) {
        Ok(lock) => Some(lock),
        Err(UpdateError::Busy) => None,
        Err(error) => return Err(error),
    };
    let updates = updates_directory(state_directory, true)?;
    let mut deliveries = read(&updates)?;
    let original_length = deliveries.len();
    deliveries.retain(|delivery| delivery.expires_at > now);
    let cleanup_needed = deliveries.len() != original_length;
    if cleanup_needed && lock.is_some() {
        write(&updates, &deliveries)?;
    }
    Ok(LoadedPeerDeliveries {
        deliveries,
        cleanup_needed: cleanup_needed && lock.is_none(),
    })
}

pub fn prune_expired_peer_deliveries(state_directory: &Path, now: u64) -> Result<(), UpdateError> {
    let _lock = super::lock::UpdateLock::acquire(state_directory)?;
    let updates = updates_directory(state_directory, true)?;
    let mut deliveries = read(&updates)?;
    let original_length = deliveries.len();
    deliveries.retain(|delivery| delivery.expires_at > now);
    if deliveries.len() != original_length {
        write(&updates, &deliveries)?;
    }
    Ok(())
}

pub fn finish_peer_delivery(
    state_directory: &Path,
    target: NodeId,
    digest: [u8; UPDATE_DIGEST_BYTES],
) -> Result<(), UpdateError> {
    let _lock = super::lock::UpdateLock::acquire(state_directory)?;
    let updates = updates_directory(state_directory, true)?;
    let mut deliveries = read(&updates)?;
    let original_length = deliveries.len();
    deliveries.retain(|value| value.target != target || value.digest != digest);
    if deliveries.len() != original_length {
        write(&updates, &deliveries)?;
    }
    Ok(())
}

pub(super) fn protected_outbox_digests(
    updates: &Path,
    now: u64,
) -> Result<BTreeSet<[u8; UPDATE_DIGEST_BYTES]>, UpdateError> {
    Ok(read(updates)?
        .into_iter()
        .filter(|value| value.expires_at > now)
        .map(|value| value.digest)
        .collect())
}

pub(super) fn queued_delivery_count(updates: &Path) -> Result<usize, UpdateError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|_| UpdateError::InvalidBundle)?
        .as_secs();
    read(updates).map(|deliveries| {
        deliveries
            .into_iter()
            .filter(|delivery| delivery.expires_at > now)
            .count()
    })
}

fn read(updates: &Path) -> Result<Vec<QueuedPeerDelivery>, UpdateError> {
    let path = updates.join(DELIVERY_FILE);
    let bytes = match fs::symlink_metadata(&path) {
        Ok(_) => artifact::read(path, MAX_DELIVERY_BYTES)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let document: DeliveryDocument = serde_json::from_slice(&bytes).map_err(|_| UpdateError::InvalidBundle)?;
    if document.schema != DELIVERY_SCHEMA
        || document.deliveries.len() > MAX_QUEUED_DELIVERIES
        || serde_json::to_vec(&document).map_err(|_| UpdateError::InvalidBundle)? != bytes
    {
        return Err(UpdateError::InvalidBundle);
    }
    let mut targets = BTreeSet::new();
    for delivery in &document.deliveries {
        if delivery.expires_at <= delivery.queued_at
            || delivery.expires_at.saturating_sub(delivery.queued_at) > DELIVERY_LIFETIME_SECONDS
            || !targets.insert(delivery.target)
        {
            return Err(UpdateError::InvalidBundle);
        }
    }
    Ok(document.deliveries)
}

fn write(updates: &Path, deliveries: &[QueuedPeerDelivery]) -> Result<(), UpdateError> {
    if deliveries.len() > MAX_QUEUED_DELIVERIES {
        return Err(UpdateError::Capacity);
    }
    let bytes = serde_json::to_vec(&DeliveryDocument {
        schema: DELIVERY_SCHEMA.to_owned(),
        deliveries: deliveries.to_vec(),
    })
    .map_err(|_| UpdateError::InvalidBundle)?;
    if bytes.len() > MAX_DELIVERY_BYTES {
        return Err(UpdateError::Capacity);
    }
    super::lifecycle::write_atomic(updates, DELIVERY_FILE, &bytes, 0o600)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use crate::ids::NodeId;

    use super::{DELIVERY_LIFETIME_SECONDS, finish_peer_delivery, load_peer_deliveries, queue_peer_delivery};

    #[test]
    fn delivery_survives_restart_and_protects_its_prepared_bundle() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state = temporary.path().join("state");
        drop(crate::state::initialize(&state)?);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
            .as_secs();
        let mut digests = Vec::new();
        for index in 0_u8..5 {
            let source = temporary.path().join(format!("bundle-{index}"));
            fs::write(&source, [index.saturating_add(1)])?;
            fs::set_permissions(&source, fs::Permissions::from_mode(0o600))?;
            let digest = crate::update::prepare_outbound(&state, &source)?;
            if index == 0 {
                let _queued = queue_peer_delivery(&state, NodeId::from_bytes([7; 32]), digest, now)?;
            }
            digests.push(digest);
        }
        let first_digest = *digests.first().ok_or("missing prepared bundle")?;
        drop(crate::update::outbound_bundle(&state, &first_digest)?);
        let loaded = load_peer_deliveries(&state, now)?;
        assert_eq!(loaded.deliveries.len(), 1);
        let delivery = *loaded.deliveries.first().ok_or("missing queued delivery")?;
        assert_eq!(delivery.digest, first_digest);
        finish_peer_delivery(&state, delivery.target, delivery.digest)?;
        assert!(load_peer_deliveries(&state, now)?.deliveries.is_empty());
        Ok(())
    }

    #[test]
    fn expired_delivery_is_removed_durably() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state = temporary.path().join("state");
        drop(crate::state::initialize(&state)?);
        let source = temporary.path().join("bundle");
        fs::write(&source, b"queued update")?;
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600))?;
        let digest = crate::update::prepare_outbound(&state, &source)?;
        let _queued = queue_peer_delivery(&state, NodeId::from_bytes([9; 32]), digest, 100)?;
        assert!(
            load_peer_deliveries(&state, 100 + DELIVERY_LIFETIME_SECONDS)?
                .deliveries
                .is_empty()
        );
        assert!(load_peer_deliveries(&state, 100)?.deliveries.is_empty());
        Ok(())
    }

    #[test]
    fn supervisor_probation_lock_does_not_prevent_queue_recovery() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state = temporary.path().join("state");
        drop(crate::state::initialize(&state)?);
        let source = temporary.path().join("bundle");
        fs::write(&source, b"probation-safe queue")?;
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600))?;
        let digest = crate::update::prepare_outbound(&state, &source)?;
        let _queued = queue_peer_delivery(&state, NodeId::from_bytes([3; 32]), digest, 100)?;
        let supervisor_lock = crate::update::UpdateLock::acquire(&state)?;
        assert_eq!(load_peer_deliveries(&state, 101)?.deliveries.len(), 1);
        let deferred = load_peer_deliveries(&state, 100 + DELIVERY_LIFETIME_SECONDS)?;
        assert!(deferred.deliveries.is_empty());
        assert!(deferred.cleanup_needed);
        drop(supervisor_lock);
        super::prune_expired_peer_deliveries(&state, 100 + DELIVERY_LIFETIME_SECONDS)?;
        let recovered = load_peer_deliveries(&state, 100)?;
        assert!(recovered.deliveries.is_empty());
        assert!(!recovered.cleanup_needed);
        Ok(())
    }

    #[test]
    fn expired_deliveries_do_not_pin_the_bounded_outbox() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state = temporary.path().join("state");
        drop(crate::state::initialize(&state)?);
        for index in 0_u8..4 {
            let source = temporary.path().join(format!("bundle-{index}"));
            fs::write(&source, [index.saturating_add(1)])?;
            fs::set_permissions(&source, fs::Permissions::from_mode(0o600))?;
            let digest = crate::update::prepare_outbound(&state, &source)?;
            let _queued = queue_peer_delivery(&state, NodeId::from_bytes([index.saturating_add(1); 32]), digest, 100)?;
        }
        let replacement = temporary.path().join("replacement");
        fs::write(&replacement, b"new owner update")?;
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))?;
        let _digest = crate::update::prepare_outbound(&state, &replacement)?;
        Ok(())
    }
}
