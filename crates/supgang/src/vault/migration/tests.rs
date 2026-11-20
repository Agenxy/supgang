use std::{
    fs,
    sync::atomic::{AtomicUsize, Ordering},
};

use super::{migrate_agent_policy, migrate_with_authority};
use crate::vault::{
    AgentPolicy, VaultError, keygen, sign,
    tests::{Software, state_directory},
};

#[test]
fn legacy_key_keeps_its_public_identity_and_gains_exact_policy() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let original = keygen(&path, &Software, "build", "existing consumer pin")?;
    let policy = AgentPolicy::new(vec!["build.stage".to_owned()], None)?;
    let migrated = migrate_agent_policy(&path, &Software, "build", &original.fingerprint, &policy)?;
    assert_eq!(migrated, original);
    sign(&path, &Software, "build", "build.stage", &[1; 32])?;
    assert!(matches!(
        sign(&path, &Software, "build", "build.release", &[1; 32]),
        Err(VaultError::AgentPolicyDenied)
    ));
    let audit = String::from_utf8(fs::read(path.join("vault-agent-audit-0000.log"))?)?;
    assert!(audit.contains("create-reserved"));
    assert!(audit.contains("create-activated"));
    Ok(())
}

#[test]
fn migration_rejects_wrong_pin_and_policy_replacement() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let original = keygen(&path, &Software, "build", "")?;
    let policy = AgentPolicy::new(vec!["build.stage".to_owned()], None)?;
    assert!(matches!(
        migrate_agent_policy(&path, &Software, "build", &"0".repeat(64), &policy),
        Err(VaultError::AgentFingerprintMismatch)
    ));
    assert!(!path.join("vault-agent-audit-0000.log").exists());
    migrate_agent_policy(&path, &Software, "build", &original.fingerprint, &policy)?;
    let audit_before = fs::read(path.join("vault-agent-audit-0000.log"))?;
    assert_eq!(
        migrate_agent_policy(&path, &Software, "build", &original.fingerprint, &policy)?,
        original
    );
    assert_eq!(fs::read(path.join("vault-agent-audit-0000.log"))?, audit_before);
    let different = AgentPolicy::new(vec!["build.release".to_owned()], None)?;
    assert!(matches!(
        migrate_agent_policy(&path, &Software, "build", &original.fingerprint, &different),
        Err(VaultError::AgentPolicyAlreadySet)
    ));
    Ok(())
}

#[test]
fn migration_cannot_exclude_its_current_certified_member() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let original = keygen(&path, &Software, "build", "")?;
    let outsider = crate::ids::NodeId::from_bytes([255; 32]);
    let policy = AgentPolicy::new(vec!["build.stage".to_owned()], Some(vec![outsider]))?;
    assert!(matches!(
        migrate_agent_policy(&path, &Software, "build", &original.fingerprint, &policy),
        Err(VaultError::AgentPolicyDenied)
    ));
    assert!(!path.join("vault-agent-audit-0000.log").exists());
    Ok(())
}

#[test]
fn interrupted_migration_is_inert_and_retry_activates() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let original = keygen(&path, &Software, "build", "")?;
    let policy = AgentPolicy::new(vec!["build.stage".to_owned()], None)?;
    let requester = crate::state::open_read_only(&path)?.identity().device.node_id();
    let checks = AtomicUsize::new(0);
    assert!(matches!(
        migrate_with_authority(&path, &Software, "build", &original.fingerprint, &policy, &|| {
            if checks.fetch_add(1, Ordering::SeqCst) < 2 {
                Ok(requester)
            } else {
                Err(VaultError::MemberAuthority)
            }
        }),
        Err(VaultError::MemberAuthority)
    ));
    assert!(matches!(
        sign(&path, &Software, "build", "build.stage", &[2; 32]),
        Err(VaultError::AgentPolicyDenied)
    ));
    assert_eq!(
        migrate_agent_policy(&path, &Software, "build", &original.fingerprint, &policy)?,
        original
    );
    sign(&path, &Software, "build", "build.stage", &[2; 32])?;
    Ok(())
}

#[test]
fn reservation_before_vault_save_can_be_resumed_without_a_second_creation() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let original = keygen(&path, &Software, "build", "")?;
    let policy = AgentPolicy::new(vec!["build.stage".to_owned()], None)?;
    let requester = crate::state::open_read_only(&path)?.identity().device.node_id();
    crate::vault::agent_audit::create_reserved(
        &path,
        requester,
        "build",
        &policy.encode()?,
        &original.public_key,
        false,
        Some(([7; 32], crate::vault::unix_now() + 60)),
    )?;
    assert_eq!(
        migrate_agent_policy(&path, &Software, "build", &original.fingerprint, &policy)?,
        original
    );
    let audit = String::from_utf8(fs::read(path.join("vault-agent-audit-0000.log"))?)?;
    assert_eq!(audit.matches("create-reserved").count(), 1);
    assert_eq!(audit.matches("create-activated").count(), 1);
    sign(&path, &Software, "build", "build.stage", &[3; 32])?;
    Ok(())
}
