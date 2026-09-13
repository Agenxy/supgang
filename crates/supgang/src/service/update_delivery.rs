//! Durable, bounded delivery of root-authorized updates across intermittent sessions.

use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};

use crate::{ids::NodeId, state::LocalState, update, update_wire::UpdateWireError};

use super::{ServiceError, active::ActiveConnection};

const RETRY_DELAY: Duration = Duration::from_secs(15);
const DELIVERY_TIMEOUT: Duration = Duration::from_mins(3);
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);

struct PendingDelivery {
    value: update::QueuedPeerDelivery,
    not_before: tokio::time::Instant,
}

struct DeliveryResult {
    value: update::QueuedPeerDelivery,
    outcome: Result<(), UpdateWireError>,
}

const fn delivery_is_terminal(outcome: Result<(), UpdateWireError>) -> bool {
    matches!(outcome, Ok(()) | Err(UpdateWireError::Rejected))
}

pub(super) struct UpdateDeliveryQueue {
    pending: BTreeMap<NodeId, PendingDelivery>,
    task: tokio::task::JoinSet<DeliveryResult>,
    in_flight: Option<update::QueuedPeerDelivery>,
    cleanup_needed: bool,
}

impl UpdateDeliveryQueue {
    pub(super) fn open(state_directory: &Path, now: u64) -> Result<Self, ServiceError> {
        let instant = tokio::time::Instant::now();
        let loaded = update::load_peer_deliveries(state_directory, now)?;
        let pending = loaded
            .deliveries
            .into_iter()
            .map(|value| {
                (
                    value.target,
                    PendingDelivery {
                        value,
                        not_before: instant,
                    },
                )
            })
            .collect();
        Ok(Self {
            pending,
            task: tokio::task::JoinSet::new(),
            in_flight: None,
            cleanup_needed: loaded.cleanup_needed,
        })
    }

    pub(super) fn enqueue(&mut self, value: update::QueuedPeerDelivery) {
        self.pending.insert(
            value.target,
            PendingDelivery {
                value,
                not_before: tokio::time::Instant::now(),
            },
        );
    }

    pub(super) fn drive(
        &mut self,
        state_directory: &Path,
        admission: &Arc<tokio::sync::Semaphore>,
        local_state: &LocalState,
        active: &BTreeMap<NodeId, ActiveConnection>,
        now: u64,
    ) -> Result<(), ServiceError> {
        self.reap(state_directory)?;
        if self.cleanup_needed {
            match update::prune_expired_peer_deliveries(state_directory, now) {
                Ok(()) => self.cleanup_needed = false,
                Err(update::UpdateError::Busy) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if update::activation_pending(state_directory)? {
            return Ok(());
        }
        self.expire_or_revoke(state_directory, local_state, now)?;
        if self.in_flight.is_some() {
            return Ok(());
        }
        let instant = tokio::time::Instant::now();
        let Some(value) = self
            .pending
            .values()
            .find(|pending| pending.not_before <= instant && active.contains_key(&pending.value.target))
            .map(|pending| pending.value)
        else {
            return Ok(());
        };
        let Some(root) = local_state.identity().root.as_ref() else {
            return Ok(());
        };
        let Some(connection) = active.get(&value.target).map(|active| active.connection().clone()) else {
            return Ok(());
        };
        let Ok(file) = update::outbound_bundle(state_directory, &value.digest) else {
            if Self::finish_persisted(state_directory, value)? {
                self.pending.remove(&value.target);
            } else {
                self.retry(value);
            }
            return Ok(());
        };
        let length = file.metadata().map_err(update::UpdateError::Io)?.len();
        let authorization = update::UpdateAuthorization::sign(
            root,
            local_state.identity().device.node_id(),
            value.target,
            value.digest,
            length,
            now,
        )
        .map_err(|_| ServiceError::InvalidSystemTime)?;
        let admission = Arc::clone(admission);
        self.in_flight = Some(value);
        self.task.spawn(async move {
            let Ok(Ok(_permit)) = tokio::time::timeout(ADMISSION_TIMEOUT, admission.acquire_owned()).await else {
                return DeliveryResult {
                    value,
                    outcome: Err(UpdateWireError::RetryLater),
                };
            };
            let outcome = tokio::time::timeout(
                DELIVERY_TIMEOUT,
                crate::update_wire::send(&connection, &authorization, file),
            )
            .await
            .unwrap_or(Err(UpdateWireError::Failed));
            DeliveryResult { value, outcome }
        });
        Ok(())
    }

    fn reap(&mut self, state_directory: &Path) -> Result<(), ServiceError> {
        let Some(result) = self.task.try_join_next() else {
            return Ok(());
        };
        let attempted = self.in_flight.take();
        match result {
            Ok(DeliveryResult { value, outcome }) => {
                if delivery_is_terminal(outcome) {
                    if Self::finish_persisted(state_directory, value)?
                        && self
                            .pending
                            .get(&value.target)
                            .is_some_and(|pending| pending.value.digest == value.digest)
                    {
                        self.pending.remove(&value.target);
                    } else {
                        self.retry(value);
                    }
                } else {
                    self.retry(value);
                }
            }
            Err(_) => {
                if let Some(value) = attempted {
                    self.retry(value);
                }
            }
        }
        Ok(())
    }

    fn retry(&mut self, value: update::QueuedPeerDelivery) {
        if let Some(pending) = self.pending.get_mut(&value.target)
            && pending.value.digest == value.digest
        {
            pending.not_before = tokio::time::Instant::now() + RETRY_DELAY;
        }
    }

    fn expire_or_revoke(
        &mut self,
        state_directory: &Path,
        local_state: &LocalState,
        now: u64,
    ) -> Result<(), ServiceError> {
        let removable: Vec<_> = self
            .pending
            .values()
            .filter(|pending| {
                pending.value.expires_at <= now || local_state.revocations().contains(&pending.value.target)
            })
            .map(|pending| pending.value)
            .collect();
        for value in removable {
            if self.in_flight != Some(value) && Self::finish_persisted(state_directory, value)? {
                self.pending.remove(&value.target);
            }
        }
        Ok(())
    }

    fn finish_persisted(state_directory: &Path, value: update::QueuedPeerDelivery) -> Result<bool, ServiceError> {
        match update::finish_peer_delivery(state_directory, value.target, value.digest) {
            Ok(()) => Ok(true),
            Err(update::UpdateError::Busy) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

impl Drop for UpdateDeliveryQueue {
    fn drop(&mut self) {
        self.task.abort_all();
    }
}

#[cfg(test)]
mod tests {
    use super::{UpdateWireError, delivery_is_terminal};

    #[test]
    fn only_acceptance_or_permanent_rejection_finishes_a_delivery() {
        assert!(delivery_is_terminal(Ok(())));
        assert!(delivery_is_terminal(Err(UpdateWireError::Rejected)));
        assert!(!delivery_is_terminal(Err(UpdateWireError::RetryLater)));
        assert!(!delivery_is_terminal(Err(UpdateWireError::Failed)));
    }
}
