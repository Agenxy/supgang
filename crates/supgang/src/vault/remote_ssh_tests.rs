//! Remote member SSH vault creation and provenance tests.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::{VaultError, list, tests::Software};
use crate::{agent_keygen_protocol::KeygenRequest, state};

struct RemoteSshTarget {
    _temporary: tempfile::TempDir,
    founder_path: std::path::PathBuf,
    target_path: std::path::PathBuf,
    founder_id: crate::ids::NodeId,
    target_id: crate::ids::NodeId,
}

fn remote_ssh_target() -> Result<RemoteSshTarget, Box<dyn std::error::Error>> {
    use crate::{
        ids::HiveId,
        invitation::JoinBundle,
        membership::{MAX_MEMBERSHIP_LIFETIME_SECONDS, MembershipRoles},
    };

    let temporary = tempfile::tempdir()?;
    let founder_path = temporary.path().join("founder");
    let target_path = temporary.path().join("target");
    let mut founder = state::initialize(&founder_path)?;
    let founder_id = founder.identity().device.node_id();
    let request = state::create_join_request(&target_path)?;
    let target_id = crate::ids::NodeId::from_verifying_key(&request.device_verifying_key);
    let now = super::unix_now();
    let membership = founder.authorize_join_request(
        &request,
        target_id,
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
    drop(state::install_join_bundle(&target_path, &bundle, hive)?);
    let founder_membership = founder.local_membership().ok_or("missing founder membership")?.clone();
    let founder_endpoint = founder.sign_endpoint_record(
        crate::profile::PeerName::new("Founder")?,
        crate::ids::TransportKeyId::from_public_material(b"founder transport"),
        crate::record::EndpointClaims {
            candidates: vec![crate::candidate::EndpointCandidate::new(
                crate::candidate::CandidateKind::Local,
                crate::candidate::CandidateTransport::QuicV1,
                std::net::SocketAddr::from(([127, 0, 0, 1], 44330)),
            )?],
            capabilities: crate::record::Capabilities::NONE,
            services: Vec::new(),
        },
        now,
        now + 3600,
    )?;
    let target_state = state::open_read_only(&target_path)?;
    let mut peer_directory = crate::peer_directory::PeerDirectory::open(
        &target_path,
        target_state.identity().root_verifying_key,
        target_id,
        target_state.revocations(),
    )?;
    peer_directory.import(
        crate::contact::PeerContact {
            membership: founder_membership,
            endpoint: founder_endpoint,
        },
        now,
    )?;
    drop(peer_directory);

    Ok(RemoteSshTarget {
        _temporary: temporary,
        founder_path,
        target_path,
        founder_id,
        target_id,
    })
}

#[test]
fn remote_ssh_key_is_created_only_on_non_root_target_with_creator_and_nonce() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = remote_ssh_target()?;
    let RemoteSshTarget {
        founder_path,
        target_path,
        founder_id,
        ..
    } = &fixture;
    let founder_id = *founder_id;
    let now = super::unix_now();

    let keygen = KeygenRequest {
        ssh: true,
        nonce: [37; 32],
        purpose: "q42-kvm-admin".to_owned(),
        note: "NanoKVM".to_owned(),
        policy: super::AgentPolicy::new(vec!["ssh.keygen".to_owned()], Some(vec![founder_id]))?,
        expires_at: now + 60,
    };
    let commit_lock = std::sync::Mutex::new(());
    assert!(matches!(
        super::prepare_member_vault(founder_path, &Software, founder_id, &keygen, || true),
        Err(VaultError::MemberAuthority)
    ));
    assert!(matches!(
        super::keygen_member(
            founder_path,
            &Software,
            founder_id,
            &keygen,
            || true,
            &commit_lock,
            None
        ),
        Err(VaultError::MemberAuthority)
    ));
    assert_eq!(list(founder_path)?, Vec::<super::Summary>::new());

    let prepared = super::prepare_member_vault(target_path, &Software, founder_id, &keygen, || true)?;
    let created = super::keygen_member(
        target_path,
        &Software,
        founder_id,
        &keygen,
        || true,
        &commit_lock,
        prepared,
    )?;
    let entries = list(target_path)?;
    assert_eq!(entries.len(), 1);
    let created_entry = entries.first().ok_or("missing created SSH key")?;
    assert_eq!(created_entry.kind, "ssh-ed25519");
    assert_eq!(created_entry.remote_creator, Some(founder_id));
    let public = super::ssh_public_key(target_path, &Software, &keygen.purpose)?;
    assert_eq!(public.public_key, created.public_key);
    assert_eq!(public.remote_creator, Some(founder_id));
    assert_eq!(public.fingerprint, created.fingerprint);
    assert_eq!(
        super::ssh_sign(target_path, &Software, &keygen.purpose, b"ssh challenge")?
            .signature
            .len(),
        64
    );
    assert!(matches!(
        super::keygen_member(target_path, &Software, founder_id, &keygen, || true, &commit_lock, None),
        Err(VaultError::AgentNonceReplay)
    ));
    super::remove(target_path, &keygen.purpose)?;
    assert_eq!(list(target_path)?, Vec::<super::Summary>::new());

    Ok(())
}

#[test]
fn remote_ssh_pending_activation_and_creator_tamper_refuse_use() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = remote_ssh_target()?;
    let RemoteSshTarget {
        target_path,
        founder_id,
        target_id,
        ..
    } = &fixture;
    let founder_id = *founder_id;
    let keygen = KeygenRequest {
        ssh: true,
        nonce: [37; 32],
        purpose: "q42-kvm-admin".to_owned(),
        note: String::new(),
        policy: super::AgentPolicy::new(vec!["ssh.keygen".to_owned()], None)?,
        expires_at: super::unix_now() + 60,
    };
    let commit_lock = std::sync::Mutex::new(());
    let prepared = super::prepare_member_vault(target_path, &Software, founder_id, &keygen, || true)?;
    super::keygen_member(
        target_path,
        &Software,
        founder_id,
        &keygen,
        || true,
        &commit_lock,
        prepared,
    )?;
    let pending = KeygenRequest {
        nonce: [38; 32],
        purpose: "q42-pending".to_owned(),
        ..keygen.clone()
    };
    let checks = AtomicUsize::new(0);
    let pending_result = super::keygen_member(
        target_path,
        &Software,
        founder_id,
        &pending,
        || checks.fetch_add(1, Ordering::SeqCst) < 3,
        &commit_lock,
        None,
    );
    assert!(
        matches!(pending_result, Err(VaultError::MemberAuthority)),
        "{pending_result:?}"
    );
    assert!(matches!(
        super::ssh_sign(target_path, &Software, &pending.purpose, b"ssh challenge"),
        Err(VaultError::AgentPolicyDenied)
    ));

    let mut document = super::load(target_path)?.ok_or("missing vault")?;
    let entry = document
        .entries
        .iter_mut()
        .find(|entry| entry.name == keygen.purpose)
        .ok_or("missing entry")?;
    entry.remote_creator = Some(*target_id);
    super::save(target_path, &document)?;
    assert!(matches!(
        super::ssh_public_key(target_path, &Software, &keygen.purpose),
        Err(VaultError::Corrupt)
    ));
    Ok(())
}

#[test]
fn revoked_target_refuses_remote_ssh_creation_before_vault_mutation() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = remote_ssh_target()?;
    let mut founder = state::open(&fixture.founder_path)?;
    let revoked = founder.revoke(fixture.target_id, super::unix_now())?;
    drop(founder);
    let mut target = state::open(&fixture.target_path)?;
    assert!(target.merge_revocations(revoked)?);
    drop(target);
    let request = KeygenRequest {
        ssh: true,
        nonce: [39; 32],
        purpose: "revoked-target".to_owned(),
        note: String::new(),
        policy: super::AgentPolicy::new(vec!["ssh.keygen".to_owned()], None)?,
        expires_at: super::unix_now() + 60,
    };
    assert!(matches!(
        super::prepare_member_vault(&fixture.target_path, &Software, fixture.founder_id, &request, || true),
        Err(VaultError::MemberAuthority)
    ));
    assert_eq!(list(&fixture.target_path)?, Vec::<super::Summary>::new());
    Ok(())
}
