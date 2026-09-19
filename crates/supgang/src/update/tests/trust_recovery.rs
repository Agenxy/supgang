//! Recovery must retain role floors without defeating authorized key rotation.

use std::{fs, num::NonZeroU64, os::unix::fs::PermissionsExt};

use ed25519_dalek::SigningKey;
use tough::schema::{RoleType, Root, Signed, Snapshot, Timestamp};

use super::{
    SignedRepository, initialize_active_fixture, metadata_description, repository_with_root_rotation, sign_role,
};
use crate::update::{
    UpdateError, pack_repository, root_state, trust_root, tuf_state, updates_directory, verify_and_stage,
};

fn version(value: u64) -> Result<NonZeroU64, Box<dyn std::error::Error>> {
    NonZeroU64::new(value).ok_or_else(|| "zero metadata version".into())
}

fn roles(repository: &SignedRepository, timestamp: u64, snapshot: u64) -> Result<(), Box<dyn std::error::Error>> {
    let root: Signed<Root> = serde_json::from_slice(&fs::read(repository.metadata.path().join("root.json"))?)?;
    let key = root
        .signed
        .roles
        .get(&RoleType::Timestamp)
        .and_then(|role| role.keyids.first())
        .ok_or("key")?;
    let signing = SigningKey::from_bytes(&[8; 32]);
    let snapshot_path = repository.metadata.path().join("snapshot.json");
    let mut signed: Signed<Snapshot> = serde_json::from_slice(&fs::read(&snapshot_path)?)?;
    signed.signed.version = version(snapshot)?;
    let bytes = serde_json::to_vec(&sign_role(signed.signed, key, &signing)?)?;
    fs::write(snapshot_path, &bytes)?;
    let path = repository.metadata.path().join("timestamp.json");
    let mut signed: Signed<Timestamp> = serde_json::from_slice(&fs::read(&path)?)?;
    signed.signed.version = version(timestamp)?;
    let mut description = metadata_description(&bytes)?;
    description.version = version(snapshot)?;
    signed.signed.meta.insert("snapshot.json".to_owned(), description);
    fs::write(path, serde_json::to_vec(&sign_role(signed.signed, key, &signing)?)?)?;
    Ok(())
}

#[tokio::test]
async fn partial_failure_rejects_actual_timestamp_and_snapshot_rollback() -> Result<(), Box<dyn std::error::Error>> {
    let repository = repository_with_root_rotation(8, "9998.0.0")?;
    let temporary = tempfile::tempdir()?;
    let bad_path = repository.metadata.path().join("targets.json");
    let good_targets = fs::read(&bad_path)?;
    for (name, replay_timestamp, replay_snapshot) in [("timestamp", 1, 2), ("snapshot", 3, 1)] {
        let state = temporary.path().join(name);
        drop(crate::state::initialize(&state)?);
        initialize_active_fixture(&state, temporary.path())?;
        trust_root(&state, &repository.root)?;
        roles(&repository, 2, 2)?;
        fs::write(&bad_path, b"invalid later targets")?;
        let bad_bundle = temporary.path().join(format!("bad-{name}"));
        pack_repository(
            repository.metadata.path(),
            repository.targets.path(),
            &repository.target_name,
            &bad_bundle,
        )?;
        assert!(matches!(
            verify_and_stage(&state, &bad_bundle).await,
            Err(UpdateError::Tuf)
        ));
        fs::write(&bad_path, &good_targets)?;
        roles(&repository, replay_timestamp, replay_snapshot)?;
        let replay = temporary.path().join(format!("replay-{name}"));
        pack_repository(
            repository.metadata.path(),
            repository.targets.path(),
            &repository.target_name,
            &replay,
        )?;
        assert!(
            matches!(verify_and_stage(&state, &replay).await, Err(UpdateError::Tuf)),
            "accepted {name} rollback"
        );
        roles(&repository, 4, 2)?;
        let repaired = temporary.path().join(format!("fixed-{name}"));
        pack_repository(
            repository.metadata.path(),
            repository.targets.path(),
            &repository.target_name,
            &repaired,
        )?;
        assert_eq!(verify_and_stage(&state, &repaired).await?.version, "9998.0.0");
    }
    Ok(())
}

#[test]
fn legacy_state_and_key_rotation_back_to_the_original_key_recover_after_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = repository_with_root_rotation(8, "9998.0.0")?;
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    trust_root(&state, &repository.root)?;
    let updates = updates_directory(&state, false)?;
    // Legacy v1 root state has no reset-generation field. Its reader migration
    // must preserve a valid existing anchor, not re-pin an unrelated root.
    let root_path = updates.join("root-state.json");
    let mut legacy: serde_json::Value = serde_json::from_slice(&fs::read(&root_path)?)?;
    *legacy.get_mut("schema").ok_or("schema")? = serde_json::json!("supgang.tuf-root-state/v1");
    legacy.as_object_mut().ok_or("object")?.remove("role_reset_version");
    fs::write(&root_path, serde_json::to_vec(&legacy)?)?;
    let original: Signed<Root> = serde_json::from_slice(&fs::read(&repository.root)?)?;
    let root2: Signed<Root> = serde_json::from_slice(&fs::read(repository.metadata.path().join("2.root.json"))?)?;
    let old_key = original
        .signed
        .roles
        .get(&RoleType::Root)
        .and_then(|role| role.keyids.first())
        .ok_or("old key")?;
    let new_key = root2
        .signed
        .roles
        .get(&RoleType::Root)
        .and_then(|role| role.keyids.first())
        .ok_or("new key")?;
    let mut third = original.signed.clone();
    third.version = version(3)?;
    let mut signed = sign_role(third.clone(), old_key, &SigningKey::from_bytes(&[7; 32]))?;
    signed
        .signatures
        .extend(sign_role(third, new_key, &SigningKey::from_bytes(&[8; 32]))?.signatures);
    let third_path = repository.metadata.path().join("3.root.json");
    fs::write(&third_path, serde_json::to_vec(&signed)?)?;
    fs::set_permissions(&third_path, fs::Permissions::from_mode(0o600))?;
    fs::set_permissions(
        repository.metadata.path().join("2.root.json"),
        fs::Permissions::from_mode(0o600),
    )?;
    let fourth = repository.metadata.path().join("4.root.json");
    fs::write(&fourth, b"invalid fourth root")?;
    fs::set_permissions(&fourth, fs::Permissions::from_mode(0o600))?;
    let datastore = tempfile::tempdir()?;
    fs::write(datastore.path().join("root.json"), serde_json::to_vec(&original)?)?;
    for name in ["timestamp.json", "snapshot.json"] {
        fs::copy(repository.metadata.path().join(name), datastore.path().join(name))?;
    }
    tuf_state::commit(&updates, datastore.path())?;
    let state_path = updates.join("tuf-state.json");
    // Changing just this same-length schema preserves canonical field ordering.
    let legacy_bytes = fs::read_to_string(&state_path)?.replacen("supgang.tuf-state/v2", "supgang.tuf-state/v1", 1);
    fs::write(&state_path, legacy_bytes)?;
    assert!(matches!(
        root_state::advance(&updates, repository.metadata.path()),
        Err(UpdateError::Tuf)
    ));
    let trust = root_state::load(&updates)?;
    assert_eq!(trust.root().signed.version.get(), 3);
    assert_eq!(trust.role_reset_version(), 3);
    let resumed = tempfile::tempdir()?;
    tuf_state::seed_current(&updates, resumed.path(), &trust)?;
    assert!(!resumed.path().join("timestamp.json").exists());
    assert!(!resumed.path().join("snapshot.json").exists());
    let resumed_root: Signed<Root> = serde_json::from_slice(&fs::read(resumed.path().join("root.json"))?)?;
    assert_eq!(resumed_root.signed.version.get(), 3);
    assert!(fs::read_to_string(state_path)?.contains("supgang.tuf-state/v2"));
    assert!(fs::read_to_string(root_path)?.contains("supgang.tuf-root-state/v2"));
    Ok(())
}
