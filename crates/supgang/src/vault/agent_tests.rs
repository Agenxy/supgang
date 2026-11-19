//! Agent-purpose vault policy and audit tests.

use std::fs;

use super::{
    VaultError, list, remove, save, sign,
    tests::{Software, state_directory},
};
use crate::agent_sign_protocol::SignRequest;
use crate::state;

#[test]
fn remote_member_nonce_is_spent_before_signing_and_replay_refuses() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let requester = state::open_read_only(&path)?.identity().device.node_id();
    let policy = super::AgentPolicy::new(vec!["build.stage".to_owned()], None)?;
    super::keygen_agent(&path, &Software, "build", "", &policy)?;
    let request = SignRequest {
        nonce: [42; 32],
        purpose: "build".to_owned(),
        context: "build.stage".to_owned(),
        digest: [7; 32],
        expires_at: super::unix_now() + 300,
    };
    let first = super::sign_member(&path, &Software, requester, &request, || true)?;
    assert_eq!(first.identity.public_key.len(), 32);
    let read_audit = fs::read(path.join(super::AUDIT_FILE_NAME))?;
    assert!(matches!(
        super::sign_member(&path, &Software, requester, &request, || true),
        Err(VaultError::AgentNonceReplay)
    ));
    let changed = SignRequest {
        digest: [8; 32],
        ..request.clone()
    };
    assert!(matches!(
        super::sign_member(&path, &Software, requester, &changed, || true),
        Err(VaultError::AgentNonceReplay)
    ));
    assert_eq!(fs::read(path.join(super::AUDIT_FILE_NAME))?, read_audit);
    let audit = String::from_utf8(fs::read(path.join("vault-agent-audit-0000.log"))?)?;
    assert!(audit.contains("nonce-reserved"));
    assert!(audit.contains(&hex::encode(request.nonce)));
    Ok(())
}

#[test]
fn remote_member_session_refusal_does_not_spend_nonce() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let requester = state::open_read_only(&path)?.identity().device.node_id();
    let policy = super::AgentPolicy::new(vec!["build.stage".to_owned()], None)?;
    super::keygen_agent(&path, &Software, "build", "", &policy)?;
    let request = SignRequest {
        nonce: [43; 32],
        purpose: "build".to_owned(),
        context: "build.stage".to_owned(),
        digest: [7; 32],
        expires_at: super::unix_now() + 300,
    };
    assert!(matches!(
        super::sign_member(&path, &Software, requester, &request, || false),
        Err(VaultError::MemberAuthority)
    ));
    super::sign_member(&path, &Software, requester, &request, || true)?;
    Ok(())
}

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
    let identity = super::keygen_agent(&path, &Software, "build", "", &policy)?;
    sign(&path, &Software, "build", "build.stage", &[1; 32])?;
    let audit_path = path.join("vault-agent-audit-0000.log");
    let audit = String::from_utf8(fs::read(&audit_path)?)?;
    assert!(audit.contains(&local.to_string()));
    assert!(audit.contains("build.stage"));
    assert!(audit.contains(&identity.fingerprint));
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
fn missing_agent_audit_refuses_existing_key_use_and_new_key_creation() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let policy = super::AgentPolicy::new(vec!["build.stage".to_owned()], None)?;
    super::keygen_agent(&path, &Software, "build", "", &policy)?;
    fs::remove_file(path.join("vault-agent-audit-0000.log"))?;
    assert!(matches!(
        sign(&path, &Software, "build", "build.stage", &[1; 32]),
        Err(VaultError::AgentAudit)
    ));
    assert!(matches!(
        super::keygen_agent(&path, &Software, "second", "", &policy),
        Err(VaultError::AgentAudit)
    ));
    fs::remove_file(path.join("vault-agent-audit.head"))?;
    assert!(matches!(
        sign(&path, &Software, "build", "build.stage", &[1; 32]),
        Err(VaultError::AgentAudit)
    ));
    assert!(matches!(
        super::keygen_agent(&path, &Software, "second", "", &policy),
        Err(VaultError::AgentAudit)
    ));
    Ok(())
}

#[test]
fn signing_and_removal_share_the_vault_lock() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let policy = super::AgentPolicy::new(vec!["build.stage".to_owned()], None)?;
    super::keygen_agent(&path, &Software, "build", "", &policy)?;
    let (_directory, lock) = super::Lock::acquire(&path)?;
    assert!(matches!(
        sign(&path, &Software, "build", "build.stage", &[1; 32]),
        Err(VaultError::Busy)
    ));
    drop(lock);
    remove(&path, "build")?;
    assert!(matches!(
        sign(&path, &Software, "build", "build.stage", &[1; 32]),
        Err(VaultError::NotFound(_))
    ));
    Ok(())
}

#[test]
fn contended_read_audit_does_not_hold_key_removal_lock() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let policy = super::AgentPolicy::new(vec!["build.stage".to_owned()], None)?;
    super::keygen_agent(&path, &Software, "build", "", &policy)?;
    let audit_lock = super::Lock::open(&path, super::AUDIT_LOCK_FILE_NAME, false)?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker_path = path.clone();
    let worker = std::thread::spawn(move || {
        let refused = matches!(
            sign(&worker_path, &Software, "build", "build.stage", &[1; 32]),
            Err(VaultError::Audit)
        );
        let _sent = sender.send(refused);
    });
    let refused = receiver.recv_timeout(std::time::Duration::from_secs(2))?;
    assert!(refused, "signing did not refuse a contended read audit");
    worker.join().map_err(|_| "signing worker panicked")?;
    let (_directory, vault_lock) = super::Lock::acquire(&path)?;
    drop(vault_lock);
    drop(audit_lock);
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
