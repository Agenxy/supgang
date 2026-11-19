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
        let requester = signing::current_member(state_directory)?;
        if !policy.admits_member(requester) {
            return Err(VaultError::AgentPolicyDenied);
        }
        agent_audit::revoke_reserved(
            &directory,
            requester,
            name,
            policy_bytes,
            &entry.signing_public.ok_or(VaultError::Corrupt)?,
        )?;
    }
    document.entries.remove(index);
    document.version = VERSION;
    save(&directory, &document)?;
    if !agent_key {
        audit(&directory, "remove", name, None);
    }
    Ok(())
}
