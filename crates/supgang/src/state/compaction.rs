//! Canonical bounded snapshots for authoritative local state.

use super::{
    AUTHORITATIVE_COMPACTION_THRESHOLD_BYTES, LocalState, StateError,
    event::{StateEvent, encode_event, signed_checkpoint},
};

impl LocalState {
    /// Atomically replaces the authoritative transition history with one
    /// canonical signed checkpoint and the complete current authority state.
    ///
    /// # Errors
    ///
    /// Returns encoding, invariant, read-only, or crash-safe replacement
    /// failures without changing the active journal handle on success paths.
    pub fn compact(&mut self) -> Result<(), StateError> {
        let frames = self.compaction_frames()?;
        if let Err(error) = self.journal_mut()?.compact(&frames) {
            self.journal.take();
            return Err(error.into());
        }
        self.event_count = frames.len();
        Ok(())
    }

    pub(super) fn compaction_frames(&self) -> Result<Vec<Vec<u8>>, StateError> {
        let local = self.local_membership().cloned().ok_or(StateError::IdentityMismatch)?;
        let mut frames = vec![encode_event(&StateEvent::Genesis {
            membership: local.clone(),
            revocations: self.revocations.clone(),
        })?];
        let mut memberships = self
            .memberships
            .values()
            .filter(|membership| membership.certificate.node_id != local.certificate.node_id)
            .cloned()
            .collect::<Vec<_>>();
        memberships.sort_by_key(|membership| membership.certificate.serial);
        let mut expected_serial = local.certificate.serial;
        for membership in memberships {
            expected_serial = expected_serial.checked_add(1).ok_or(StateError::CounterExhausted)?;
            if membership.certificate.serial != expected_serial {
                return Err(StateError::InvalidMembershipSerial);
            }
            frames.push(encode_event(&StateEvent::Membership(membership))?);
        }
        if expected_serial != self.last_membership_serial {
            return Err(StateError::InvalidMembershipSerial);
        }
        let checkpoint = signed_checkpoint(&self.identity, self.generation, self.sequence, &frames)?;
        frames.push(encode_event(&checkpoint)?);
        Ok(frames)
    }

    pub(super) fn compact_if_needed(&mut self) -> Result<(), StateError> {
        if self.journal.as_ref().ok_or(StateError::ReadOnlySnapshot)?.byte_len()?
            >= AUTHORITATIVE_COMPACTION_THRESHOLD_BYTES
        {
            self.compact()?;
        }
        Ok(())
    }
}
