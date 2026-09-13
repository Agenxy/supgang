use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::SocketAddr,
    num::NonZeroU64,
    os::unix::fs::PermissionsExt,
    str::FromStr,
    time::{Duration, SystemTime},
};

#[cfg(target_os = "macos")]
use std::process::Command;

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use tough::{
    TargetName,
    schema::{
        Hashes, Metafile, Role, RoleKeys, RoleType, Root, Signature, Signed, Snapshot, Target, Targets, Timestamp,
        decoded::Decoded,
        key::{Ed25519Key, Ed25519Scheme, Key},
    },
};

use super::{
    UpdateAuthorization, UpdateError, activate_staged, bundle_digest, initialize_installed, pack_repository,
    prepare_outbound, status, trust_root, validate_target_name, verify_and_stage,
};

const TUF_SPEC: &str = "1.0.0";

struct SignedRepository {
    metadata: tempfile::TempDir,
    targets: tempfile::TempDir,
    _trust: Option<tempfile::TempDir>,
    root: std::path::PathBuf,
    target_name: String,
    target_digest: String,
}

fn initialize_active_fixture(
    state: &std::path::Path,
    directory: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let executable = directory.join("installed-supgang");
    fs::copy(std::env::current_exe()?, &executable)?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
    sign_update_fixture(&executable, 1)?;
    let _installed = initialize_installed(state, &executable)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn sign_update_fixture(path: &std::path::Path, marker: u8) -> Result<(), Box<dyn std::error::Error>> {
    let entitlements = path.with_extension(format!("entitlements-{marker}.plist"));
    fs::write(
        &entitlements,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>org.agenxy.supgang.test-marker</key><integer>{marker}</integer></dict></plist>\n"
        ),
    )?;
    let output = Command::new("/usr/bin/codesign")
        .args([
            "--force",
            "--sign",
            "-",
            "--identifier",
            "org.agenxy.supgang.update-test",
            "--requirements",
            "=designated => identifier \"org.agenxy.supgang.update-test\"",
            "--entitlements",
        ])
        .arg(&entitlements)
        .args(["--timestamp=none"])
        .arg(path)
        .output()?;
    fs::remove_file(entitlements)?;
    if output.status.success() {
        Ok(())
    } else {
        Err("codesign did not prepare the update fixture".into())
    }
}

#[cfg(not(target_os = "macos"))]
fn sign_update_fixture(path: &std::path::Path, marker: u8) -> Result<(), Box<dyn std::error::Error>> {
    OpenOptions::new().append(true).open(path)?.write_all(&[marker])?;
    Ok(())
}

fn sign_role<T: Role>(
    role: T,
    key_id: &Decoded<tough::schema::decoded::Hex>,
    key: &SigningKey,
) -> Result<Signed<T>, Box<dyn std::error::Error>> {
    let signature = key.sign(&role.canonical_form()?);
    Ok(Signed {
        signed: role,
        signatures: vec![Signature {
            keyid: key_id.clone(),
            sig: signature.to_bytes().to_vec().into(),
        }],
    })
}

fn metadata_description(bytes: &[u8]) -> Result<Metafile, Box<dyn std::error::Error>> {
    Ok(Metafile {
        length: Some(u64::try_from(bytes.len())?),
        hashes: Some(Hashes {
            sha256: Sha256::digest(bytes).to_vec().into(),
            _extra: HashMap::new(),
        }),
        version: NonZeroU64::MIN,
        _extra: HashMap::new(),
    })
}

fn signed_repository() -> Result<SignedRepository, Box<dyn std::error::Error>> {
    let metadata = tempfile::tempdir()?;
    let targets_directory = tempfile::tempdir()?;
    let target_name = format!("supgang-9999.0.0-{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let target_path = targets_directory.path().join(&target_name);
    fs::copy(std::env::current_exe()?, &target_path)?;
    fs::set_permissions(&target_path, fs::Permissions::from_mode(0o700))?;
    sign_update_fixture(&target_path, 2)?;
    let target_payload = fs::read(&target_path)?;
    let target_digest = Sha256::digest(&target_payload);
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let tuf_key = Key::Ed25519 {
        keyval: Ed25519Key {
            public: signing_key.verifying_key().to_bytes().to_vec().into(),
            _extra: HashMap::new(),
        },
        scheme: Ed25519Scheme::Ed25519,
        _extra: HashMap::new(),
    };
    let key_id = tuf_key.key_id()?;
    let role_keys = RoleKeys {
        keyids: vec![key_id.clone()],
        threshold: NonZeroU64::MIN,
        _extra: HashMap::new(),
    };
    let expires = jiff::Timestamp::from_str("2099-01-01T00:00:00Z")?;
    let root = Root {
        spec_version: TUF_SPEC.to_owned(),
        consistent_snapshot: false,
        version: NonZeroU64::MIN,
        expires,
        keys: HashMap::from([(key_id.clone(), tuf_key)]),
        roles: HashMap::from([
            (RoleType::Root, role_keys.clone()),
            (RoleType::Snapshot, role_keys.clone()),
            (RoleType::Targets, role_keys.clone()),
            (RoleType::Timestamp, role_keys),
        ]),
        _extra: HashMap::new(),
    };
    let mut targets = Targets::new(TUF_SPEC.to_owned(), NonZeroU64::MIN, expires);
    targets.targets.insert(
        TargetName::new(target_name.clone())?,
        Target {
            length: u64::try_from(target_payload.len())?,
            hashes: Hashes {
                sha256: target_digest.to_vec().into(),
                _extra: HashMap::new(),
            },
            custom: HashMap::new(),
            _extra: HashMap::new(),
        },
    );
    let root_bytes = serde_json::to_vec(&sign_role(root, &key_id, &signing_key)?)?;
    let targets_bytes = serde_json::to_vec(&sign_role(targets, &key_id, &signing_key)?)?;
    let mut snapshot = Snapshot::new(TUF_SPEC.to_owned(), NonZeroU64::MIN, expires);
    snapshot
        .meta
        .insert("targets.json".to_owned(), metadata_description(&targets_bytes)?);
    let snapshot_bytes = serde_json::to_vec(&sign_role(snapshot, &key_id, &signing_key)?)?;
    let mut timestamp = Timestamp::new(TUF_SPEC.to_owned(), NonZeroU64::MIN, expires);
    timestamp
        .meta
        .insert("snapshot.json".to_owned(), metadata_description(&snapshot_bytes)?);
    let timestamp_bytes = serde_json::to_vec(&sign_role(timestamp, &key_id, &signing_key)?)?;
    for (name, bytes) in [
        ("root.json", root_bytes),
        ("targets.json", targets_bytes),
        ("snapshot.json", snapshot_bytes),
        ("timestamp.json", timestamp_bytes),
    ] {
        fs::write(metadata.path().join(name), bytes)?;
    }
    let root = metadata.path().join("root.json");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o600))?;
    Ok(SignedRepository {
        metadata,
        targets: targets_directory,
        _trust: None,
        root,
        target_name,
        target_digest: hex::encode(target_digest),
    })
}

fn repository_with_root_rotation(seed: u8, version: &str) -> Result<SignedRepository, Box<dyn std::error::Error>> {
    let metadata = tempfile::tempdir()?;
    let targets_directory = tempfile::tempdir()?;
    let trust = tempfile::tempdir()?;
    let target_name = format!("supgang-{version}-{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let target_path = targets_directory.path().join(&target_name);
    fs::copy(std::env::current_exe()?, &target_path)?;
    fs::set_permissions(&target_path, fs::Permissions::from_mode(0o700))?;
    sign_update_fixture(&target_path, 2)?;
    let target_payload = fs::read(&target_path)?;
    let target_digest = Sha256::digest(&target_payload);
    let old_signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let new_signing_key = SigningKey::from_bytes(&[seed; 32]);
    let old_key = Key::Ed25519 {
        keyval: Ed25519Key {
            public: old_signing_key.verifying_key().to_bytes().to_vec().into(),
            _extra: HashMap::new(),
        },
        scheme: Ed25519Scheme::Ed25519,
        _extra: HashMap::new(),
    };
    let new_key = Key::Ed25519 {
        keyval: Ed25519Key {
            public: new_signing_key.verifying_key().to_bytes().to_vec().into(),
            _extra: HashMap::new(),
        },
        scheme: Ed25519Scheme::Ed25519,
        _extra: HashMap::new(),
    };
    let old_key_id = old_key.key_id()?;
    let new_key_id = new_key.key_id()?;
    let old_role = RoleKeys {
        keyids: vec![old_key_id.clone()],
        threshold: NonZeroU64::MIN,
        _extra: HashMap::new(),
    };
    let new_role = RoleKeys {
        keyids: vec![new_key_id.clone()],
        threshold: NonZeroU64::MIN,
        _extra: HashMap::new(),
    };
    let expires = jiff::Timestamp::from_str("2099-01-01T00:00:00Z")?;
    let root_v1 = Root {
        spec_version: TUF_SPEC.to_owned(),
        consistent_snapshot: false,
        version: NonZeroU64::MIN,
        expires,
        keys: HashMap::from([(old_key_id.clone(), old_key)]),
        roles: HashMap::from([
            (RoleType::Root, old_role.clone()),
            (RoleType::Snapshot, old_role.clone()),
            (RoleType::Targets, old_role.clone()),
            (RoleType::Timestamp, old_role),
        ]),
        _extra: HashMap::new(),
    };
    let root_v2 = Root {
        spec_version: TUF_SPEC.to_owned(),
        consistent_snapshot: false,
        version: NonZeroU64::new(2).ok_or("root version")?,
        expires,
        keys: HashMap::from([(new_key_id.clone(), new_key)]),
        roles: HashMap::from([
            (RoleType::Root, new_role.clone()),
            (RoleType::Snapshot, new_role.clone()),
            (RoleType::Targets, new_role.clone()),
            (RoleType::Timestamp, new_role),
        ]),
        _extra: HashMap::new(),
    };
    let canonical_root_v2 = root_v2.canonical_form()?;
    let signed_root_v2 = Signed {
        signed: root_v2,
        signatures: vec![
            Signature {
                keyid: old_key_id.clone(),
                sig: old_signing_key.sign(&canonical_root_v2).to_bytes().to_vec().into(),
            },
            Signature {
                keyid: new_key_id.clone(),
                sig: new_signing_key.sign(&canonical_root_v2).to_bytes().to_vec().into(),
            },
        ],
    };
    let root_v1_bytes = serde_json::to_vec(&sign_role(root_v1, &old_key_id, &old_signing_key)?)?;
    let root_v2_bytes = serde_json::to_vec(&signed_root_v2)?;
    let root = trust.path().join("root.json");
    fs::write(&root, root_v1_bytes)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o600))?;

    let mut targets = Targets::new(TUF_SPEC.to_owned(), NonZeroU64::MIN, expires);
    targets.targets.insert(
        TargetName::new(target_name.clone())?,
        Target {
            length: u64::try_from(target_payload.len())?,
            hashes: Hashes {
                sha256: target_digest.to_vec().into(),
                _extra: HashMap::new(),
            },
            custom: HashMap::new(),
            _extra: HashMap::new(),
        },
    );
    let targets_bytes = serde_json::to_vec(&sign_role(targets, &new_key_id, &new_signing_key)?)?;
    let mut snapshot = Snapshot::new(TUF_SPEC.to_owned(), NonZeroU64::MIN, expires);
    snapshot
        .meta
        .insert("targets.json".to_owned(), metadata_description(&targets_bytes)?);
    let snapshot_bytes = serde_json::to_vec(&sign_role(snapshot, &new_key_id, &new_signing_key)?)?;
    let mut timestamp = Timestamp::new(TUF_SPEC.to_owned(), NonZeroU64::MIN, expires);
    timestamp
        .meta
        .insert("snapshot.json".to_owned(), metadata_description(&snapshot_bytes)?);
    let timestamp_bytes = serde_json::to_vec(&sign_role(timestamp, &new_key_id, &new_signing_key)?)?;
    for (name, bytes) in [
        ("root.json", root_v2_bytes.clone()),
        ("2.root.json", root_v2_bytes),
        ("targets.json", targets_bytes),
        ("snapshot.json", snapshot_bytes),
        ("timestamp.json", timestamp_bytes),
    ] {
        fs::write(metadata.path().join(name), bytes)?;
    }
    Ok(SignedRepository {
        metadata,
        targets: targets_directory,
        _trust: Some(trust),
        root,
        target_name,
        target_digest: hex::encode(target_digest),
    })
}

#[test]
fn target_names_bind_version_platform_and_architecture() -> Result<(), Box<dyn std::error::Error>> {
    let valid = format!(
        "supgang-0.2.0-alpha.10-{}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    assert_eq!(validate_target_name(&valid)?.to_string(), "0.2.0-alpha.10");
    assert!(matches!(
        validate_target_name("supgang-9.9.9-linux-wrong"),
        Err(UpdateError::WrongPlatform)
    ));
    assert!(
        validate_target_name(&format!(
            "supgang-../x-{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ))
        .is_err()
    );
    Ok(())
}

#[test]
fn trust_root_is_local_only_and_rejects_invalid_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    let initialized = crate::state::initialize(&state)?;
    drop(initialized);
    let root = temporary.path().join("root.json");
    fs::write(&root, b"not a root")?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o600))?;
    assert!(matches!(
        super::trust_root(&state, &root),
        Err(UpdateError::InvalidTrustRoot)
    ));
    Ok(())
}

#[test]
fn update_status_is_plain_and_empty_before_trust_is_established() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    let report = status(&state)?;
    assert!(!report.trusted);
    assert_eq!(report.active_version, crate::VERSION);
    assert_eq!(report.staged_version, None);
    assert!(!report.activation_pending);
    assert_eq!(report.queued_peer_deliveries, 0);
    Ok(())
}

#[test]
fn update_status_rejects_a_corrupted_pinned_root() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    let updates = super::updates_directory(&state, true)?;
    let root = updates.join(super::TRUSTED_ROOT_FILE);
    fs::write(&root, b"corrupted root metadata")?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o600))?;
    assert!(matches!(status(&state), Err(UpdateError::InvalidTrustRoot)));
    Ok(())
}

#[test]
fn update_status_rejects_a_corrupted_pending_record() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    let executable = temporary.path().join("supgang");
    fs::copy(std::env::current_exe()?, &executable)?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
    let _installed = initialize_installed(&state, &executable)?;
    let updates = super::updates_directory(&state, false)?;
    let pending = updates.join("pending.json");
    fs::write(&pending, b"corrupted pending record")?;
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600))?;
    assert!(matches!(status(&state), Err(UpdateError::InvalidBundle)));
    Ok(())
}

#[test]
fn local_reinstall_refreshes_changed_bytes_at_the_same_version() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    let executable = temporary.path().join("supgang");
    fs::copy(std::env::current_exe()?, &executable)?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
    sign_update_fixture(&executable, 1)?;
    let first = initialize_installed(&state, &executable)?;
    sign_update_fixture(&executable, 2)?;
    let second = initialize_installed(&state, &executable)?;
    assert_ne!(first, second);
    assert_eq!(fs::read(second)?, fs::read(executable)?);
    Ok(())
}

#[test]
fn a_zero_length_crash_temporary_cannot_wedge_the_prepared_outbox() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    let source = temporary.path().join("source.bundle");
    fs::write(&source, b"bounded test carriage")?;
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600))?;
    let updates = super::updates_directory(&state, true)?;
    let outbox = super::ensure_child(&updates, "outbox")?;
    let abandoned = outbox.join(format!(".{}.tmp", "0".repeat(32)));
    fs::write(&abandoned, [])?;
    fs::set_permissions(&abandoned, fs::Permissions::from_mode(0o600))?;
    let _digest = prepare_outbound(&state, &source)?;
    assert!(!abandoned.exists());
    Ok(())
}

#[tokio::test]
async fn real_tuf_repository_is_verified_staged_and_rollback_protected() -> Result<(), Box<dyn std::error::Error>> {
    let repository = signed_repository()?;
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    initialize_active_fixture(&state, temporary.path())?;
    trust_root(&state, &repository.root)?;
    let bundle = temporary.path().join("release.bundle");
    let digest = pack_repository(
        repository.metadata.path(),
        repository.targets.path(),
        &repository.target_name,
        &bundle,
    )?;
    assert_eq!(digest.len(), 64);
    let updates = super::updates_directory(&state, true)?;
    let slots = super::ensure_child(&updates, super::SLOTS_DIRECTORY)?;
    let slot = super::ensure_child(&slots, &repository.target_digest)?;
    let stale_target = slot.join(format!(".supgang-{}.tmp", "0".repeat(32)));
    fs::write(&stale_target, [])?;
    fs::set_permissions(&stale_target, fs::Permissions::from_mode(0o600))?;
    let corrupt = temporary.path().join("corrupt.bundle");
    fs::copy(&bundle, &corrupt)?;
    fs::set_permissions(&corrupt, fs::Permissions::from_mode(0o600))?;
    let mut corrupt_file = OpenOptions::new().read(true).write(true).open(&corrupt)?;
    corrupt_file.seek(SeekFrom::End(-1))?;
    let mut final_byte = [0_u8; 1];
    corrupt_file.read_exact(&mut final_byte)?;
    corrupt_file.seek(SeekFrom::End(-1))?;
    let [byte] = final_byte;
    corrupt_file.write_all(&[byte ^ 0xff])?;
    corrupt_file.sync_all()?;
    assert!(matches!(
        verify_and_stage(&state, &corrupt).await,
        Err(UpdateError::InvalidBundle)
    ));
    let staged = verify_and_stage(&state, &bundle).await?;
    assert_eq!(staged.version, "9999.0.0");
    assert_eq!(staged.executable.metadata()?.permissions().mode() & 0o777, 0o700);
    assert!(!stale_target.exists());
    assert!(matches!(
        verify_and_stage(&state, &bundle).await,
        Err(UpdateError::Rollback)
    ));
    let outside = temporary.path().join("outside-supgang");
    fs::copy(&staged.executable, &outside)?;
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o700))?;
    let staged_record = updates.join("staged.json");
    let mut record: super::lifecycle::SlotRecord = serde_json::from_slice(&fs::read(&staged_record)?)?;
    record.executable = outside;
    fs::write(&staged_record, serde_json::to_vec(&record)?)?;
    fs::set_permissions(&staged_record, fs::Permissions::from_mode(0o600))?;
    assert!(matches!(activate_staged(&state), Err(UpdateError::InvalidBundle)));
    Ok(())
}

#[tokio::test]
async fn rotated_root_is_the_restart_anchor_and_retired_key_forks_are_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let legitimate = repository_with_root_rotation(8, "9998.0.0")?;
    let retired_key_fork = repository_with_root_rotation(9, "9999.0.0")?;
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    initialize_active_fixture(&state, temporary.path())?;
    trust_root(&state, &legitimate.root)?;

    let legitimate_bundle = temporary.path().join("legitimate.bundle");
    pack_repository(
        legitimate.metadata.path(),
        legitimate.targets.path(),
        &legitimate.target_name,
        &legitimate_bundle,
    )?;
    assert_eq!(verify_and_stage(&state, &legitimate_bundle).await?.version, "9998.0.0");
    let updates = super::updates_directory(&state, false)?;
    let root_state: serde_json::Value = serde_json::from_slice(&fs::read(updates.join("root-state.json"))?)?;
    assert_eq!(
        root_state.pointer("/current/signed/version"),
        Some(&serde_json::json!(2))
    );
    assert_eq!(
        root_state.pointer("/previous/signed/version"),
        Some(&serde_json::json!(1))
    );

    let fork_bundle = temporary.path().join("fork.bundle");
    pack_repository(
        retired_key_fork.metadata.path(),
        retired_key_fork.targets.path(),
        &retired_key_fork.target_name,
        &fork_bundle,
    )?;
    assert!(matches!(
        verify_and_stage(&state, &fork_bundle).await,
        Err(UpdateError::Tuf)
    ));
    Ok(())
}

#[test]
fn missing_promoted_root_state_fails_closed_without_bootstrap_fallback() -> Result<(), Box<dyn std::error::Error>> {
    let repository = signed_repository()?;
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    trust_root(&state, &repository.root)?;
    let updates = super::updates_directory(&state, false)?;
    fs::remove_file(updates.join("root-state.json"))?;
    assert!(matches!(status(&state), Err(UpdateError::InvalidTrustRoot)));
    Ok(())
}

#[test]
fn interrupted_initial_root_pin_can_resume_only_with_the_same_root() -> Result<(), Box<dyn std::error::Error>> {
    let repository = signed_repository()?;
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    trust_root(&state, &repository.root)?;
    let updates = super::updates_directory(&state, false)?;
    fs::remove_file(updates.join(super::TRUSTED_ROOT_FILE))?;
    trust_root(&state, &repository.root)?;
    assert!(status(&state)?.trusted);
    Ok(())
}

#[test]
fn root_authorized_bundle_crosses_real_quic_and_is_independently_verified() -> Result<(), Box<dyn std::error::Error>> {
    crate::transport::build_runtime()?.block_on(async {
        let repository = signed_repository()?;
        let temporary = tempfile::tempdir()?;
        let state = temporary.path().join("receiver-state");
        drop(crate::state::initialize(&state)?);
        initialize_active_fixture(&state, temporary.path())?;
        trust_root(&state, &repository.root)?;
        let bundle = temporary.path().join("release.bundle");
        pack_repository(
            repository.metadata.path(),
            repository.targets.path(),
            &repository.target_name,
            &bundle,
        )?;
        let digest = bundle_digest(&bundle)?;
        let root = crate::identity::RootIdentity::generate()?;
        let issuer = crate::identity::DeviceIdentity::generate()?.node_id();
        let target = crate::identity::DeviceIdentity::generate()?.node_id();
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
        let authorization =
            UpdateAuthorization::sign(&root, issuer, target, digest, fs::metadata(&bundle)?.len(), now)?;

        let server_identity = crate::transport::TransportIdentity::generate()?;
        let server = quinn::Endpoint::server(server_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let client_identity = crate::transport::TransportIdentity::generate()?;
        let client = quinn::Endpoint::server(client_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let accepting = server.clone();
        let accepted = tokio::spawn(async move {
            accepting
                .accept()
                .await
                .ok_or("server endpoint closed")?
                .await
                .map_err(|error| error.to_string())
        });
        let client_connection = tokio::time::timeout(
            Duration::from_secs(5),
            client.connect_with(
                crate::transport::pinned_client_config(server_identity.key_id())?,
                server.local_addr()?,
                "supgang.invalid",
            )?,
        )
        .await??;
        let server_connection = accepted.await??;
        let receiving_connection = server_connection.clone();
        let receiving_state = state.clone();
        let root_key = root.verifying_key();
        let hive_id = root.hive_id();
        let session_authorization = crate::service::SessionAuthorization::new(now.saturating_add(60), now)
            .ok_or("test session authorization expired")?;
        let update_admission = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let receiver = tokio::spawn(async move {
            let (kind, send, receive) = crate::peer_stream::accept(&receiving_connection)
                .await
                .map_err(|error| error.to_string())?;
            if kind != crate::peer_stream::StreamKind::Update {
                return Err("unexpected stream kind".to_owned());
            }
            crate::update_wire::receive(
                send,
                receive,
                crate::update_wire::ReceiveContext {
                    state_directory: &receiving_state,
                    root_key: &root_key,
                    hive_id,
                    local_node: target,
                    authenticated_peer: issuer,
                    authorization: &session_authorization,
                    admission: &update_admission,
                },
            )
            .await
            .map_err(|error| error.to_string())
        });
        let sent = crate::update_wire::send(&client_connection, &authorization, File::open(&bundle)?).await;
        let receive_result = receiver.await?;
        if let Err(error) = sent {
            return Err(format!("sender: {error:?}; receiver: {receive_result:?}").into());
        }
        assert_eq!(receive_result?, Some(digest));
        let report = status(&state)?;
        assert_eq!(report.staged_version.as_deref(), Some("9999.0.0"));
        assert!(!report.activation_pending);
        server.close(0_u8.into(), b"test complete");
        client.close(0_u8.into(), b"test complete");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
