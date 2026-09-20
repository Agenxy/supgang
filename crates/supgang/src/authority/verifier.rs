//! Bounded per-device rollback and equivocation state.

use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

use super::{
    AuthorityError, AuthorityManifest, CertificateId, CertifiedKey, CertifiedKeyRevocations, MAX_CERTIFICATES,
    MAX_USED_IDS, Purpose, codec, device_node_id,
};
use crate::{
    device_key::DevicePublicKey,
    ids::{HiveId, NodeId},
};

const MAX_DEVICES: usize = 64;

#[derive(Clone)]
struct DeviceState {
    watermark: (u64, u64),
    issued_at: u64,
    digest: [u8; 32],
    manifest: Option<AuthorityManifest>,
    certificates: BTreeMap<CertificateId, CertifiedKey>,
    history: BTreeMap<CertificateId, [u8; 32]>,
    history_exhausted: bool,
    revocations: CertifiedKeyRevocations,
    // Keep the prior epoch's complete set. No time-based eviction is needed:
    // retaining one bounded prior set exceeds the required age retention.
    previous_revocations: CertifiedKeyRevocations,
}

/// Library verifier scoped to one hive, with at most 64 tracked devices.
///
/// Watermarks never evict automatically. Omitted unexpired certificates remain
/// live, bounded to 16; historical ids remain remembered up to 4096 per device.
/// Equivocation removes both authority records and quarantines that epoch until
/// a higher epoch is accepted. Keep this object for the consumer's lifetime;
/// durable consumer-state integration and root membership checks are separate.
pub struct AuthorityVerifier {
    hive: HiveId,
    devices: BTreeMap<NodeId, DeviceState>,
}

impl AuthorityVerifier {
    /// Creates a verifier for one independently authenticated hive.
    #[must_use]
    pub const fn new(hive: HiveId) -> Self {
        Self {
            hive,
            devices: BTreeMap::new(),
        }
    }

    /// Authenticates a manifest before changing any remembered state.
    ///
    /// Equal content with another valid ECDSA signature is a duplicate.
    /// Equal epoch/revision with different authenticated content removes both
    /// manifests; subsequent replay cannot resurrect either one.
    ///
    /// # Errors
    /// Refuses signatures, proofs, rollback, future skew, non-monotonic
    /// revocations, reused ids, equivocation and bounded-state exhaustion.
    pub fn accept(
        &mut self,
        manifest: AuthorityManifest,
        key: DevicePublicKey,
        now: u64,
    ) -> Result<(), AuthorityError> {
        manifest.verify(self.hive, key)?;
        let content = &manifest.content;
        let future = content.issued_at > now.saturating_add(300);
        let node = device_node_id(key);
        let watermark = (content.epoch, content.revision);
        let digest: [u8; 32] = Sha256::digest(codec::content_bytes(content)?).into();
        if let Some(state) = self.devices.get_mut(&node) {
            if watermark < state.watermark {
                return Err(AuthorityError::Older);
            }
            if watermark == state.watermark {
                if digest != state.digest || state.manifest.is_none() {
                    quarantine(state, &manifest);
                    return Err(AuthorityError::Equivocation);
                }
                return if future { Err(AuthorityError::Future) } else { Ok(()) };
            }
            if content.epoch == state.watermark.0 && state.manifest.is_none() {
                return Err(AuthorityError::Equivocation);
            }
        } else if self.devices.len() == MAX_DEVICES {
            return Err(AuthorityError::Bound);
        }
        if future {
            return Err(AuthorityError::Future);
        }
        let state = next_state(self.devices.get(&node), manifest, digest, now)?;
        self.devices.insert(node, state);
        Ok(())
    }

    /// Returns a certificate only under the ADR's freshness intersection.
    ///
    /// `issued_at <= now <= next_update`, `now - issued_at <= max_status_age`,
    /// `not_before <= now <= not_after`, current epoch, absent from revocations.
    /// The caller must additionally establish root membership and protocol
    /// possession, and call `authorize` with the actual audience and operation.
    /// Ambiguous ids across devices fail closed; use `certificate_for` when the
    /// issuer is known. No receipt timestamp participates in this decision.
    ///
    /// # Errors
    /// No match, stale status, clock rollback, revocation, wrong purpose,
    /// expiration, equivocation or an ambiguous id returns `Unavailable`.
    pub fn certificate(
        &self,
        id: CertificateId,
        purpose: Purpose,
        now: u64,
        max_status_age: u64,
    ) -> Result<&CertifiedKey, AuthorityError> {
        let mut matches = self
            .devices
            .values()
            .filter_map(|state| usable(state, id, purpose, now, max_status_age));
        let first = matches.next().ok_or(AuthorityError::Unavailable)?;
        if matches.next().is_some() {
            return Err(AuthorityError::Unavailable);
        }
        Ok(first)
    }

    /// Looks up a certificate for an explicitly selected issuing device.
    ///
    /// # Errors
    /// Returns `Unavailable` unless every local certificate freshness check passes.
    pub fn certificate_for(
        &self,
        issuer: NodeId,
        id: CertificateId,
        purpose: Purpose,
        now: u64,
        max_status_age: u64,
    ) -> Result<&CertifiedKey, AuthorityError> {
        self.devices
            .get(&issuer)
            .and_then(|state| usable(state, id, purpose, now, max_status_age))
            .ok_or(AuthorityError::Unavailable)
    }
}

fn usable(
    state: &DeviceState,
    id: CertificateId,
    purpose: Purpose,
    now: u64,
    max_status_age: u64,
) -> Option<&CertifiedKey> {
    let manifest = state.manifest.as_ref()?;
    let content = &manifest.content;
    if now < content.issued_at
        || now > content.next_update
        || now - content.issued_at > max_status_age
        || content.revocations.ids.binary_search(&id).is_ok()
    {
        return None;
    }
    let certificate = state.certificates.get(&id)?;
    let claims = &certificate.claims;
    if claims.epoch != content.epoch || claims.purpose != purpose || now < claims.not_before || now > claims.not_after {
        return None;
    }
    Some(certificate)
}

fn next_state(
    previous: Option<&DeviceState>,
    manifest: AuthorityManifest,
    digest: [u8; 32],
    now: u64,
) -> Result<DeviceState, AuthorityError> {
    let content = &manifest.content;
    let mut state = previous.cloned().unwrap_or_else(|| DeviceState {
        watermark: (content.epoch, 0),
        issued_at: content.issued_at,
        digest,
        manifest: None,
        certificates: BTreeMap::new(),
        history: BTreeMap::new(),
        history_exhausted: false,
        revocations: CertifiedKeyRevocations::default(),
        previous_revocations: CertifiedKeyRevocations::default(),
    });
    if state.history_exhausted {
        return Err(AuthorityError::Bound);
    }
    if content.issued_at < state.issued_at {
        return Err(AuthorityError::Older);
    }
    if content.epoch == state.watermark.0 {
        content.revocations.extends(&state.revocations)?;
    } else {
        state.previous_revocations = state.revocations.clone();
        state.certificates.clear();
    }
    state
        .certificates
        .retain(|id, c| c.claims.not_after >= now && content.revocations.ids.binary_search(id).is_err());
    for certificate in &content.certificates {
        let id = certificate.claims.id;
        let hash: [u8; 32] = Sha256::digest(codec::certificate_bytes(certificate)?).into();
        if state.history.get(&id).is_some_and(|old| *old != hash) {
            return Err(AuthorityError::ReusedId);
        }
        remember(&mut state.history, id, hash)?;
        if certificate.claims.not_after >= now {
            state.certificates.insert(id, certificate.clone());
        }
    }
    for id in &content.revocations.ids {
        // Unknown revoked ids become tombstones; their future certification fails.
        if !state.history.contains_key(id) {
            remember(&mut state.history, *id, [0; 32])?;
        }
    }
    if state.certificates.len() > MAX_CERTIFICATES {
        return Err(AuthorityError::Bound);
    }
    state.watermark = (content.epoch, content.revision);
    state.issued_at = content.issued_at;
    state.digest = digest;
    state.revocations.clone_from(&content.revocations);
    state.manifest = Some(manifest);
    Ok(state)
}

fn remember(
    history: &mut BTreeMap<CertificateId, [u8; 32]>,
    id: CertificateId,
    digest: [u8; 32],
) -> Result<(), AuthorityError> {
    if !history.contains_key(&id) && history.len() == MAX_USED_IDS {
        return Err(AuthorityError::Bound);
    }
    history.insert(id, digest);
    Ok(())
}

fn quarantine(state: &mut DeviceState, conflicting: &AuthorityManifest) {
    state.manifest = None;
    state.certificates.clear();
    state.issued_at = state.issued_at.max(conflicting.content.issued_at);
    // Neither conflicting record grants authority, but ids in either signed
    // record must never become reusable after a later epoch advance.
    for id in conflicting
        .content
        .certificates
        .iter()
        .map(|c| c.claims.id)
        .chain(conflicting.content.revocations.ids.iter().copied())
    {
        if !state.history.contains_key(&id) && remember(&mut state.history, id, [0; 32]).is_err() {
            state.history_exhausted = true;
        }
    }
}
