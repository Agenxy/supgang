//! Bounded audit reservations and activation checks.

use super::*;

pub(in crate::vault) fn preflight_nonce(directory: &Path, nonce: &[u8; 32]) -> Result<(), VaultError> {
    let _lock = Lock::open(directory, LOCK_NAME, false).map_err(|_| VaultError::AgentAudit)?;
    let state = scan(directory)?;
    if state.sequence == 0 {
        return Err(VaultError::AgentAudit);
    }
    if state.used_nonces.contains(nonce) {
        return Err(VaultError::AgentNonceReplay);
    }
    Ok(())
}

/// A first purpose key may create the first audit record; still check any
/// existing chain for a spent nonce before generating a new key.
pub(in crate::vault) fn preflight_creation_nonce(directory: &Path, nonce: &[u8; 32]) -> Result<(), VaultError> {
    let _lock = Lock::open(directory, LOCK_NAME, false).map_err(|_| VaultError::AgentAudit)?;
    if scan(directory)?.used_nonces.contains(nonce) {
        return Err(VaultError::AgentNonceReplay);
    }
    Ok(())
}

pub(in crate::vault) fn create_reserved(
    directory: &Path,
    requester: NodeId,
    purpose: &str,
    policy: &[u8],
    public_key: &[u8; 32],
    require_existing: bool,
    nonce: Option<([u8; 32], u64)>,
) -> Result<(), VaultError> {
    let digest: [u8; 32] = Sha256::digest(policy).into();
    append(
        directory,
        Event {
            requester,
            action: Action::CreateReserved,
            purpose,
            context: None,
            digest: &digest,
            public_key: Some(public_key),
        },
        require_existing,
        nonce,
    )
}

/// Make a previously reserved remote creation usable only after the vault
/// document is durable and the member/session authorization still holds.
pub(in crate::vault) fn create_activated(
    directory: &Path,
    requester: NodeId,
    purpose: &str,
    policy: &[u8],
    public_key: &[u8; 32],
) -> Result<(), VaultError> {
    let digest: [u8; 32] = Sha256::digest(policy).into();
    append(
        directory,
        Event {
            requester,
            action: Action::CreateActivated,
            purpose,
            context: None,
            digest: &digest,
            public_key: Some(public_key),
        },
        true,
        None,
    )
}

/// Refuse signing by a remote-created key until its activation is durable.
pub(in crate::vault) fn ensure_activated(
    directory: &Path,
    purpose: &str,
    policy: &[u8],
    public_key: &[u8; 32],
) -> Result<(), VaultError> {
    let digest: [u8; 32] = Sha256::digest(policy).into();
    let event = Event {
        requester: NodeId::from_bytes([0; 32]),
        action: Action::CreateActivated,
        purpose,
        context: None,
        digest: &digest,
        public_key: Some(public_key),
    };
    let _lock = Lock::open(directory, LOCK_NAME, false).map_err(|_| VaultError::AgentAudit)?;
    let state = scan(directory)?;
    if state.sequence == 0 {
        return Err(VaultError::AgentAudit);
    }
    if state.created_keys.get(&key_ref(&event)?) == Some(&true) {
        Ok(())
    } else {
        Err(VaultError::AgentPolicyDenied)
    }
}

pub(in crate::vault) fn signed(
    directory: &Path,
    requester: NodeId,
    purpose: &str,
    context: &str,
    digest: &[u8; 32],
    public_key: &[u8; 32],
) -> Result<(), VaultError> {
    append(
        directory,
        Event {
            requester,
            action: Action::Sign,
            purpose,
            context: Some(context),
            digest,
            public_key: Some(public_key),
        },
        true,
        None,
    )
}

/// Records an authenticated, policy-level refusal and spends its nonce.
/// Unknown purposes have no key fingerprint to attribute.
pub(in crate::vault) fn denied(
    directory: &Path,
    requester: NodeId,
    request: &crate::agent_sign_protocol::SignRequest,
    public_key: Option<&[u8; 32]>,
) -> Result<(), VaultError> {
    append(
        directory,
        Event {
            requester,
            action: Action::Denied,
            purpose: &request.purpose,
            context: Some(&request.context),
            digest: &request.digest,
            public_key,
        },
        true,
        Some((request.nonce, request.expires_at)),
    )
}

pub(in crate::vault) fn revoke_reserved(
    directory: &Path,
    requester: NodeId,
    purpose: &str,
    policy: &[u8],
    public_key: &[u8; 32],
) -> Result<(), VaultError> {
    let digest: [u8; 32] = Sha256::digest(policy).into();
    append(
        directory,
        Event {
            requester,
            action: Action::RevokeReserved,
            purpose,
            context: None,
            digest: &digest,
            public_key: Some(public_key),
        },
        true,
        None,
    )
}

pub(in crate::vault) fn reserve_nonce(
    directory: &Path,
    requester: NodeId,
    request: &crate::agent_sign_protocol::SignRequest,
    public_key: &[u8; 32],
) -> Result<(), VaultError> {
    append(
        directory,
        Event {
            requester,
            action: Action::NonceReserved,
            purpose: &request.purpose,
            context: Some(&request.context),
            digest: &request.digest,
            public_key: Some(public_key),
        },
        true,
        Some((request.nonce, request.expires_at)),
    )
}
