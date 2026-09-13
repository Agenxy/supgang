use std::path::Path;

use super::{
    StagedUpdate, UpdateError, lock::UpdateLock, materialize_bundle, remove_work_directory, verify_materialized,
};

/// Independently TUF-verifies a carried bundle and stages its target.
///
/// # Errors
///
/// Rejects unsafe storage, malformed or stale metadata, rollback, a wrong-platform
/// target, an invalid executable, or a concurrent update operation.
pub async fn verify_and_stage(state_directory: &Path, bundle: &Path) -> Result<StagedUpdate, UpdateError> {
    let lock = UpdateLock::acquire(state_directory)?;
    verify_and_stage_locked(state_directory, bundle, lock).await
}

pub async fn verify_and_stage_locked(
    state_directory: &Path,
    bundle: &Path,
    _lock: UpdateLock,
) -> Result<StagedUpdate, UpdateError> {
    if super::lifecycle::activation_pending(state_directory)? {
        return Err(UpdateError::Busy);
    }
    recover_stale_work(state_directory)?;
    let state_directory = state_directory.to_path_buf();
    let bundle = bundle.to_path_buf();
    let materialized = tokio::task::spawn_blocking(move || materialize_bundle(&state_directory, &bundle))
        .await
        .map_err(|_| UpdateError::InvalidBundle)??;
    let result = verify_materialized(&materialized).await;
    let cleanup = remove_work_directory(&materialized.work_directory);
    match (result, cleanup) {
        (Ok(staged), Ok(())) => Ok(staged),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

fn recover_stale_work(state_directory: &Path) -> Result<(), UpdateError> {
    let updates = super::updates_directory(state_directory, true)?;
    let mut removed = 0_usize;
    for entry in std::fs::read_dir(updates)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| UpdateError::InvalidBundle)?;
        let Some(random) = name.strip_prefix(".verify-") else {
            continue;
        };
        if random.len() != 32
            || !random
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(UpdateError::InvalidBundle);
        }
        if removed >= 8 {
            return Err(UpdateError::Capacity);
        }
        remove_work_directory(&entry.path())?;
        removed = removed.checked_add(1).ok_or(UpdateError::Capacity)?;
    }
    Ok(())
}
