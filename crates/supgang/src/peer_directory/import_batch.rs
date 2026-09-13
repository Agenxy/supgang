//! Coalesced one-sync persistence for authenticated contact pages.

use std::collections::BTreeMap;

use crate::{contact::PeerContact, ids::NodeId, journal::JournalError};

use super::{PeerDirectory, PeerDirectoryError};

const MAX_PAGE_CONTACTS: usize = 8;

impl PeerDirectory {
    /// Coalesces one bounded peer page and persists all useful transitions with
    /// at most one journal synchronization.
    pub(crate) fn import_page(&mut self, contacts: Vec<PeerContact>, now: u64) -> Result<bool, PeerDirectoryError> {
        let candidates = self.coalesced_candidates(contacts, now);
        if candidates.is_empty() {
            return Ok(false);
        }
        let mut preview = Self {
            root_key: self.root_key,
            local_node: self.local_node,
            entries: self.entries.clone(),
            revocations: self.revocations.clone(),
            reachability: self.reachability.clone(),
            history_address_limit: self.history_address_limit,
            journal: None,
        };
        let mut accepted = Vec::new();
        for contact in candidates {
            let before = preview.entries.clone();
            let _decision = preview.apply(contact.clone(), false);
            if preview.entries != before {
                accepted.push(contact);
            }
        }
        if accepted.is_empty() {
            return Ok(false);
        }
        let frames = accepted
            .iter()
            .map(crate::contact::encode_contact)
            .collect::<Result<Vec<_>, _>>()?;
        self.compact_if_needed()?;
        match self.journal_mut()?.append_batch(&frames) {
            Ok(()) => {}
            Err(JournalError::JournalFull) => {
                self.compact()?;
                self.journal_mut()?.append_batch(&frames)?;
            }
            Err(error) => return Err(error.into()),
        }
        self.entries = preview.entries;
        Ok(true)
    }

    fn coalesced_candidates(&self, contacts: Vec<PeerContact>, now: u64) -> Vec<PeerContact> {
        let mut newest = BTreeMap::<NodeId, Vec<PeerContact>>::new();
        for contact in contacts.into_iter().take(MAX_PAGE_CONTACTS.saturating_add(1)) {
            let record = &contact.endpoint.record;
            if record.node_id == self.local_node
                || self.revocations.contains(&record.node_id)
                || contact.verify(&self.root_key, now).is_err()
            {
                continue;
            }
            let values = newest.entry(record.node_id).or_default();
            let incoming = (record.generation, record.sequence);
            let retained = values
                .first()
                .map(|value| (value.endpoint.record.generation, value.endpoint.record.sequence));
            match retained {
                Some(current) if incoming < current => {}
                Some(current) if incoming == current => {
                    if !values.contains(&contact) && values.len() < 2 {
                        values.push(contact);
                    }
                }
                Some(_) => {
                    values.clear();
                    values.push(contact);
                }
                None => values.push(contact),
            }
        }
        newest.into_values().flatten().collect()
    }
}
