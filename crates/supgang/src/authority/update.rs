//! Typed authority mutation; no arbitrary device-signing endpoint.

use super::{
    AUTHORITY_DOMAIN, AuthorityContent, AuthorityError, AuthorityManifest, CertificateId, CertifiedKey,
    CertifiedKeyRevocations, MAX_CERTIFICATES, MAX_REVOCATIONS, RevisionStore, codec, device_node_id,
};
use crate::{device_key::DeviceSigner, ids::HiveId, record::ServiceAdvert};

/// One owner-approved authority change, validated before revision reservation.
#[derive(Clone, Debug, Default)]
pub struct AuthorityUpdate {
    /// Newly possessed certificates; ids may never be reused.
    pub add: Vec<CertifiedKey>,
    /// Ids to revoke, including previously omitted ids.
    pub revoke: Vec<CertificateId>,
    /// Replace all service claims, or retain the existing claims.
    pub services: Option<Vec<ServiceAdvert>>,
    /// Advance exactly one epoch, clearing certificates and revocations first.
    /// Additions in the same operation must name the new epoch and fresh ids.
    pub advance_epoch: bool,
}

impl AuthorityUpdate {
    /// Validates, durably reserves a revision, signs and durably commits it.
    ///
    /// No manifest is returned before commit succeeds. A failed signature or
    /// commit burns its reserved revision. The store is scoped to this hive and
    /// signer, compares the durable predecessor, and remembers all used ids.
    ///
    /// # Errors
    /// Refuses invalid proofs, issuers, bounds, reuses, rollback, or storage and
    /// signer failures. Epoch overflow and revision overflow fail closed.
    pub fn apply(
        &self,
        current: Option<&AuthorityManifest>,
        hive: HiveId,
        signer: &impl DeviceSigner,
        store: &mut impl RevisionStore,
        issued_at: u64,
        next_update: u64,
    ) -> Result<AuthorityManifest, AuthorityError> {
        if self.add.len() > MAX_CERTIFICATES || self.revoke.len() > MAX_REVOCATIONS {
            return Err(AuthorityError::Bound);
        }
        if self.advance_epoch && !self.revoke.is_empty() {
            return Err(AuthorityError::Invalid);
        }
        if let Some(services) = &self.services {
            crate::record::validate_services(services)?;
        }
        if let Some(current) = current {
            current.verify(hive, signer.public_key())?;
            if issued_at < current.content.issued_at {
                return Err(AuthorityError::Older);
            }
        }
        let old_epoch = current.map_or(0, |m| m.content.epoch);
        let epoch = if self.advance_epoch {
            old_epoch.checked_add(1).ok_or(AuthorityError::Bound)?
        } else {
            old_epoch
        };
        let mut content = AuthorityContent {
            epoch,
            revision: 1,
            issued_at,
            next_update,
            certificates: current
                .filter(|_| !self.advance_epoch)
                .map_or_else(Vec::new, |m| m.content.certificates.clone()),
            revocations: current
                .filter(|_| !self.advance_epoch)
                .map_or_else(CertifiedKeyRevocations::default, |m| m.content.revocations.clone()),
            services: self
                .services
                .clone()
                .unwrap_or_else(|| current.map_or_else(Vec::new, |m| m.content.services.clone())),
        };
        for id in &self.revoke {
            if content.revocations.ids.binary_search(id).is_err() {
                content.revocations.ids.push(*id);
                content.revocations.ids.sort_unstable();
            }
        }
        content
            .certificates
            .retain(|c| content.revocations.ids.binary_search(&c.claims.id).is_err());
        for certificate in &self.add {
            certificate.verify_possession()?;
            let claims = &certificate.claims;
            if claims.hive != hive || claims.issuer != device_node_id(signer.public_key()) || claims.epoch != epoch {
                return Err(AuthorityError::Issuer);
            }
            if current.is_some_and(|m| {
                m.content.certificates.iter().any(|c| c.claims.id == claims.id)
                    || m.content.revocations.ids.contains(&claims.id)
            }) || content.revocations.ids.contains(&claims.id)
            {
                return Err(AuthorityError::ReusedId);
            }
            content.certificates.push(certificate.clone());
        }
        content.certificates.sort_by_key(|c| c.claims.id);
        content.validate()?;
        // Reserve a worst-case u64 revision in the size calculation before any
        // durable mutation. The real reservation can never need more bytes.
        content.revision = u64::MAX;
        if codec::content_bytes(&content)?.len().saturating_add(72) > super::MAX_MANIFEST_BYTES {
            return Err(AuthorityError::Bound);
        }
        store.reserve(current, &mut content)?;
        let payload = codec::content_bytes(&content)?;
        let signature = signer.sign_domain(AUTHORITY_DOMAIN, &payload)?;
        let manifest = AuthorityManifest { content, signature };
        manifest.verify(hive, signer.public_key())?;
        store.commit(&manifest)?;
        Ok(manifest)
    }
}
