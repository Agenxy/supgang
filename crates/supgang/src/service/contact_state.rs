//! Locally signed endpoint publication and bounded contact gossip.

use crate::{
    contact::PeerContact,
    membership::MembershipRoles,
    peer_directory::PeerDirectory,
    record::Capabilities,
    state::{LocalState, StateError},
    sync::{MAX_SYNC_CONTACTS, SyncPage},
    transport::TransportIdentity,
};

use super::{ServiceConfig, ServiceError, unix_time};

/// Wall time keeps advancing while some platform monotonic clocks pause in sleep.
/// Check signed validity independently of the in-process refresh deadline.
pub(super) const fn needs_wall_clock_refresh(issued_at: u64, expires_at: u64, now: u64, margin: u64) -> bool {
    let actual_margin = expires_at.saturating_sub(issued_at) / 2;
    let margin = if margin < actual_margin { margin } else { actual_margin };
    now < issued_at || expires_at.saturating_sub(now) <= margin
}

pub(super) fn refresh_contact_if_due(
    state: &mut LocalState,
    identity: &TransportIdentity,
    config: &ServiceConfig,
    contact: &mut PeerContact,
    deadline: &mut tokio::time::Instant,
    clocks: (tokio::time::Instant, u64),
    interfaces_changed: bool,
) -> Result<bool, ServiceError> {
    let (monotonic, wall) = clocks;
    require_live_membership(state, wall)?;
    let delay = config.record_lifetime / 2;
    let record = &contact.endpoint.record;
    if !interfaces_changed
        && monotonic < *deadline
        && !needs_wall_clock_refresh(record.issued_at, record.expires_at, wall, delay.as_secs())
    {
        return Ok(false);
    }
    *contact = make_local_contact(state, identity, config)?;
    *deadline = monotonic + delay;
    Ok(true)
}

pub(super) fn make_local_contact(
    state: &mut LocalState,
    transport_identity: &TransportIdentity,
    config: &ServiceConfig,
) -> Result<PeerContact, ServiceError> {
    let now = unix_time()?;
    require_live_membership(state, now)?;
    let membership = state.local_membership().cloned().ok_or(StateError::IdentityMismatch)?;
    let capabilities = if membership.certificate.roles.contains(MembershipRoles::INTRODUCER) {
        Capabilities::INTRODUCER
    } else {
        Capabilities::NONE
    };
    let endpoint = state.sign_endpoint_record(
        config.display_name.clone(),
        transport_identity.key_id(),
        config.candidates.clone(),
        capabilities,
        now,
        now.saturating_add(config.record_lifetime.as_secs())
            .min(membership.certificate.expires_at),
    )?;
    Ok(PeerContact { membership, endpoint })
}

fn require_live_membership(state: &LocalState, now: u64) -> Result<(), ServiceError> {
    let membership = state.local_membership().ok_or(StateError::IdentityMismatch)?;
    if membership.certificate.expires_at <= now {
        return Err(ServiceError::MembershipExpired);
    }
    Ok(())
}

pub(super) fn gossip_page(
    local: &PeerContact,
    directory: &PeerDirectory,
    revocations: &crate::revocation::SignedRevocationList,
    now: u64,
    cursor: &mut usize,
) -> SyncPage {
    let peers = directory.usable_contacts(now);
    let mut page = Vec::with_capacity(MAX_SYNC_CONTACTS);
    page.push(local.clone());
    if peers.is_empty() {
        return SyncPage {
            contacts: page,
            reachability: directory.reachability_claims(now),
            revocations: revocations.clone(),
        };
    }
    for offset in 0..MAX_SYNC_CONTACTS.saturating_sub(1).min(peers.len()) {
        if let Some(contact) = peers.get(cursor.wrapping_add(offset) % peers.len()) {
            page.push((*contact).clone());
        }
    }
    *cursor = cursor.wrapping_add(MAX_SYNC_CONTACTS.saturating_sub(1));
    SyncPage {
        contacts: page,
        reachability: directory.reachability_claims(now),
        revocations: revocations.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::needs_wall_clock_refresh;

    #[test]
    fn sleeping_past_record_expiry_forces_a_new_contact_without_a_timer_tick() {
        assert!(!needs_wall_clock_refresh(1_000, 22_600, 1_001, 10_800));
        // The monotonic refresh timer has not moved, but wall time passed the lifetime.
        assert!(needs_wall_clock_refresh(1_000, 22_600, 30_000, 10_800));
        assert!(needs_wall_clock_refresh(1_000, 22_600, 11_800, 10_800));
        assert!(needs_wall_clock_refresh(1_000, 22_600, 999, 10_800));
        assert!(!needs_wall_clock_refresh(30_000, 51_600, 30_001, 10_800));
        // Near membership expiry the shortened record must not cause a signing storm.
        assert!(!needs_wall_clock_refresh(30_000, 30_100, 30_001, 10_800));
    }

    #[test]
    fn wake_refresh_signs_a_fresh_record_while_the_monotonic_deadline_is_in_the_future()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("state");
        let mut state = crate::state::initialize(&path)?;
        let identity = crate::transport_storage::load_or_create(&path)?;
        let config = super::ServiceConfig::new(
            crate::profile::PeerName::new("sleep-test")?,
            "127.0.0.1:44330".parse()?,
            &["127.0.0.1:44330".parse()?],
            &[],
        )?;
        let mut contact = super::make_local_contact(&mut state, &identity, &config)?;
        let previous_sequence = contact.endpoint.record.sequence;
        let simulated_wall = super::unix_time()?;
        let mut expired = contact.endpoint.record.clone();
        expired.issued_at = simulated_wall.saturating_sub(21_600);
        expired.expires_at = simulated_wall.saturating_sub(1);
        contact.endpoint = crate::record::SignedEndpointRecord::sign(expired, &state.identity().device)?;
        assert!(
            contact
                .verify(&state.identity().root_verifying_key, simulated_wall)
                .is_err()
        );
        let now = tokio::time::Instant::now();
        let mut deadline = now + std::time::Duration::from_secs(10_000);
        assert!(super::refresh_contact_if_due(
            &mut state,
            &identity,
            &config,
            &mut contact,
            &mut deadline,
            (now, simulated_wall),
            false,
        )?);
        assert!(contact.endpoint.record.sequence > previous_sequence);
        contact.verify(&state.identity().root_verifying_key, super::unix_time()?)?;
        assert_eq!(deadline, now + config.record_lifetime / 2);
        assert!(!super::refresh_contact_if_due(
            &mut state,
            &identity,
            &config,
            &mut contact,
            &mut deadline,
            (now, super::unix_time()?),
            false,
        )?);
        Ok(())
    }

    #[test]
    fn expired_membership_stops_refresh_without_signing_or_advancing_the_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("state");
        let mut state = crate::state::initialize(&path)?;
        let identity = crate::transport_storage::load_or_create(&path)?;
        let config = super::ServiceConfig::new(
            crate::profile::PeerName::new("expiry-test")?,
            "127.0.0.1:44330".parse()?,
            &["127.0.0.1:44330".parse()?],
            &[],
        )?;
        let mut contact = super::make_local_contact(&mut state, &identity, &config)?;
        let original = contact.clone();
        let now = tokio::time::Instant::now();
        let mut deadline = now;
        for wall in [
            original.membership.certificate.expires_at,
            original.membership.certificate.expires_at + 1,
        ] {
            assert!(matches!(
                super::refresh_contact_if_due(
                    &mut state,
                    &identity,
                    &config,
                    &mut contact,
                    &mut deadline,
                    (now, wall),
                    true,
                ),
                Err(super::ServiceError::MembershipExpired)
            ));
            assert_eq!(contact, original);
            assert_eq!(deadline, now);
        }
        Ok(())
    }
}
