//! Vault entry removal with an agent-key audit reservation.

use std::path::Path;

use super::{AgentPolicy, Kind, Lock, VERSION, VaultError, agent_audit, audit, load, save, signing, validate_name};

/// Removes one secret. The vault key stays, so later additions need no enclave.
///
/// # Errors
/// Refuses unknown names, a busy lock, policy denial and storage failures.
pub fn remove(state_directory: &Path, name: &str) -> Result<(), VaultError> {
    validate_name(name)?;
    let (directory, _lock) = Lock::acquire(state_directory)?;
    let mut document = load(&directory)?.ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    let index = document
        .entries
        .iter()
        .position(|entry| entry.name == name)
        .ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
    let entry = document.entries.get(index).ok_or(VaultError::Corrupt)?;
    if entry.kind == Kind::LmsSha256H20W1 {
        return Err(VaultError::LmsRootRetained);
    }
    let agent_key = entry.policy.is_some();
    if let Some(policy_bytes) = entry.policy.as_deref() {
        let policy = AgentPolicy::decode(policy_bytes)?;
        let remote_ssh = entry.kind == Kind::SshEd25519 && entry.remote_creator.is_some();
        let requester = if remote_ssh {
            current_local_member_for_ssh_removal(state_directory)?
        } else {
            signing::current_member(state_directory)?
        };
        let public_key = entry.signing_public.ok_or(VaultError::Corrupt)?;
        // A remote creation interrupted after its vault write is inert, but
        // it can occupy a purpose name. The root may explicitly remove that
        // pending entry even when the creator narrowed the signing allowlist.
        let pending = matches!(
            agent_audit::ensure_activated(&directory, name, policy_bytes, &public_key),
            Err(VaultError::AgentPolicyDenied)
        );
        if !remote_ssh && !policy.admits_member(requester) && !pending {
            return Err(VaultError::AgentPolicyDenied);
        }
        agent_audit::revoke_reserved(&directory, requester, name, policy_bytes, &public_key)?;
    }
    document.entries.remove(index);
    document.version = VERSION;
    save(&directory, &document)?;
    if !agent_key {
        audit(&directory, "remove", name, None);
    }
    Ok(())
}

fn current_local_member_for_ssh_removal(state_directory: &Path) -> Result<crate::ids::NodeId, VaultError> {
    let state = crate::state::open_read_only(state_directory).map_err(|_| VaultError::MemberAuthority)?;
    let node = state.identity().device.node_id();
    if state.revocations().contains(&node) {
        return Err(VaultError::MemberAuthority);
    }
    state
        .local_membership()
        .ok_or(VaultError::MemberAuthority)?
        .certificate
        .validate_time(super::unix_now())
        .map_err(|_| VaultError::MemberAuthority)?;
    Ok(node)
}
