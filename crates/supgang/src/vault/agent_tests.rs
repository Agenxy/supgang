//! Agent-purpose vault policy and audit tests.

use std::fs;

use super::{
    VaultError, list, remove, save, sign,
    tests::{Software, state_directory},
};
use crate::state;

#[test]
fn agent_policy_is_immutable_and_restricts_creation_and_signing() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let local = state::open_read_only(&path)?.identity().device.node_id();
    let other = crate::ids::NodeId::from_bytes([7; 32]);
    let denied = super::AgentPolicy::new(vec!["build.stage".to_owned()], Some(vec![other]))?;
    assert!(matches!(
        super::keygen_agent(&path, &Software, "build", "", &denied),
        Err(VaultError::AgentPolicyDenied)
    ));
    assert_eq!(list(&path)?, Vec::<super::Summary>::new());

    let policy = super::AgentPolicy::new(vec!["build.stage".to_owned()], Some(vec![local]))?;
    super::keygen_agent(&path, &Software, "build", "", &policy)?;
    sign(&path, &Software, "build", "build.stage", &[1; 32])?;
    let audit_path = path.join("vault-agent-audit-0000.log");
    let audit = String::from_utf8(fs::read(&audit_path)?)?;
    assert!(audit.contains(&local.to_string()));
    assert!(audit.contains("build.stage"));
    assert!(matches!(
        sign(&path, &Software, "build", "build.release", &[1; 32]),
        Err(VaultError::AgentPolicyDenied)
    ));

    let directory = crate::storage::validate_directory(&path)?;
    let mut document = super::load(&directory)?.ok_or("missing vault")?;
    let entry = document.entries.first_mut().ok_or("missing key")?;
    entry.policy = None;
    save(&directory, &document)?;
    assert!(matches!(
        sign(&path, &Software, "build", "build.stage", &[1; 32]),
        Err(VaultError::Corrupt)
    ));
    Ok(())
}

#[test]
fn non_authority_member_cannot_use_local_agent_key_path() -> Result<(), Box<dyn std::error::Error>> {
    use crate::{
        ids::HiveId,
        invitation::JoinBundle,
        membership::{MAX_MEMBERSHIP_LIFETIME_SECONDS, MembershipRoles},
    };

    let temporary = tempfile::tempdir()?;
    let founder_path = temporary.path().join("founder");
    let joiner_path = temporary.path().join("joiner");
    let mut founder = state::initialize(&founder_path)?;
    let request = state::create_join_request(&joiner_path)?;
    let node = crate::ids::NodeId::from_verifying_key(&request.device_verifying_key);
    let now = super::unix_now();
    let membership = founder.authorize_join_request(
        &request,
        node,
        MembershipRoles::DEVICE,
        now,
        now.saturating_add(MAX_MEMBERSHIP_LIFETIME_SECONDS),
    )?;
    let bundle = JoinBundle::new(
        founder.identity().root.as_ref().ok_or("missing root")?,
        membership,
        founder.revocations().clone(),
        now,
    )?;
    let hive = HiveId::from_root_verifying_key(&bundle.root_verifying_key);
    drop(state::install_join_bundle(&joiner_path, &bundle, hive)?);
    let policy = super::AgentPolicy::new(vec!["build.stage".to_owned()], None)?;
    assert!(matches!(
        super::keygen_agent(&joiner_path, &Software, "build", "", &policy),
        Err(VaultError::MemberAuthority)
    ));
    assert_eq!(list(&joiner_path)?, Vec::<super::Summary>::new());
    Ok(())
}

#[test]
fn agent_audit_failure_refuses_key_creation_and_signature_release() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let policy = super::AgentPolicy::new(vec!["build.stage".to_owned()], None)?;
    let audit_path = path.join("vault-agent-audit-0000.log");
    fs::create_dir(&audit_path)?;
    assert!(matches!(
        super::keygen_agent(&path, &Software, "build", "", &policy),
        Err(VaultError::AgentAudit)
    ));
    assert_eq!(list(&path)?, Vec::<super::Summary>::new());
    fs::remove_dir(&audit_path)?;
    super::keygen_agent(&path, &Software, "build", "", &policy)?;
    let mut bytes = fs::read(&audit_path)?;
    bytes.pop();
    fs::write(&audit_path, bytes)?;
    assert!(matches!(
        sign(&path, &Software, "build", "build.stage", &[1; 32]),
        Err(VaultError::AgentAudit)
    ));
    Ok(())
}

#[test]
fn agent_key_removal_is_scoped_and_audited_before_change() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let policy = super::AgentPolicy::new(vec!["build.stage".to_owned()], None)?;
    super::keygen_agent(&path, &Software, "build", "", &policy)?;
    let audit_path = path.join("vault-agent-audit-0000.log");
    let before = fs::read(&audit_path)?;
    fs::write(&audit_path, b"broken\n")?;
    assert!(matches!(remove(&path, "build"), Err(VaultError::AgentAudit)));
    assert_eq!(list(&path)?.len(), 1);
    fs::write(&audit_path, before)?;
    remove(&path, "build")?;
    assert_eq!(list(&path)?, Vec::<super::Summary>::new());
    let audit = String::from_utf8(fs::read(audit_path)?)?;
    assert!(audit.contains("revoke-reserved"));
    Ok(())
}
