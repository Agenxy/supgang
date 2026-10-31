//! Trust advancement must survive failures after every authenticated role.

use std::{fs, os::unix::fs::PermissionsExt};

use super::{initialize_active_fixture, repository_with_root_rotation};
use crate::update::{UpdateError, pack_repository, trust_root, verify_and_stage};

#[tokio::test]
async fn failed_rotated_release_never_restores_retired_authority() -> Result<(), Box<dyn std::error::Error>> {
    let legitimate = repository_with_root_rotation(8, "9998.0.0")?;
    let fork = repository_with_root_rotation(9, "9999.0.0")?;
    let temporary = tempfile::tempdir()?;
    let fork_bundle = temporary.path().join("fork.bundle");
    pack_repository(
        fork.metadata.path(),
        fork.targets.path(),
        &fork.target_name,
        &fork_bundle,
    )?;
    // Missing later roles, invalid following root, and a target whose actual
    // bytes violate signed metadata (with a freshly valid outer bundle digest).
    for failure in [
        "timestamp.json",
        "snapshot.json",
        "targets.json",
        "3.root.json",
        "target",
    ] {
        let state = temporary.path().join(format!("state-{failure}"));
        drop(crate::state::initialize(&state)?);
        initialize_active_fixture(&state, temporary.path())?;
        trust_root(&state, &legitimate.root)?;
        let path = if failure == "target" {
            legitimate.targets.path().join(&legitimate.target_name)
        } else {
            legitimate.metadata.path().join(failure)
        };
        let original = fs::read(&path).ok();
        let original_mode = path.metadata().ok().map(|metadata| metadata.permissions());
        fs::write(&path, b"not the signed bytes")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let bundle = temporary.path().join(format!("{failure}.bundle"));
        pack_repository(
            legitimate.metadata.path(),
            legitimate.targets.path(),
            &legitimate.target_name,
            &bundle,
        )?;
        assert!(verify_and_stage(&state, &bundle).await.is_err(), "accepted {failure}");
        let updates = crate::update::updates_directory(&state, false)?;
        let durable: serde_json::Value = serde_json::from_slice(&fs::read(updates.join("root-state.json"))?)?;
        assert_eq!(
            durable.pointer("/current/signed/version"),
            Some(&serde_json::json!(2)),
            "lost trust after {failure}"
        );
        assert!(
            matches!(verify_and_stage(&state, &fork_bundle).await, Err(UpdateError::Tuf)),
            "accepted fork after {failure}"
        );
        if let Some(bytes) = original {
            fs::write(&path, bytes)?;
            fs::set_permissions(&path, original_mode.ok_or("original mode")?)?;
        } else {
            fs::remove_file(&path)?;
        }
        // A good release under the retained new authority still works.
        let repaired = temporary.path().join(format!("repaired-{failure}.bundle"));
        pack_repository(
            legitimate.metadata.path(),
            legitimate.targets.path(),
            &legitimate.target_name,
            &repaired,
        )?;
        assert_eq!(verify_and_stage(&state, &repaired).await?.version, "9998.0.0");
    }
    Ok(())
}

#[tokio::test]
async fn later_role_failure_retains_authenticated_timestamp_and_snapshot() -> Result<(), Box<dyn std::error::Error>> {
    let repository = repository_with_root_rotation(8, "9998.0.0")?;
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    initialize_active_fixture(&state, temporary.path())?;
    trust_root(&state, &repository.root)?;
    fs::write(repository.metadata.path().join("targets.json"), b"invalid later role")?;
    let bundle = temporary.path().join("bundle");
    pack_repository(
        repository.metadata.path(),
        repository.targets.path(),
        &repository.target_name,
        &bundle,
    )?;
    assert!(verify_and_stage(&state, &bundle).await.is_err());
    let updates = crate::update::updates_directory(&state, false)?;
    let durable: serde_json::Value = serde_json::from_slice(&fs::read(updates.join("tuf-state.json"))?)?;
    let files = durable
        .get("files")
        .and_then(serde_json::Value::as_array)
        .ok_or("files")?;
    for name in ["root.json", "timestamp.json", "snapshot.json", "latest_known_time.json"] {
        assert!(
            files
                .iter()
                .any(|file| file.get("name") == Some(&serde_json::json!(name))),
            "lost {name}"
        );
    }
    assert!(
        !files
            .iter()
            .any(|file| file.get("name") == Some(&serde_json::json!("targets.json")))
    );
    Ok(())
}
