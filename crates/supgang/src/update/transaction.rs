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
    lock: UpdateLock,
) -> Result<StagedUpdate, UpdateError> {
    run_transaction(state_directory, bundle, lock, None).await
}

pub async fn verify_incoming(
    state_directory: &Path,
    incoming: super::carriage::IncomingBundle,
    lock: UpdateLock,
) -> Result<StagedUpdate, UpdateError> {
    let path = incoming.path.clone();
    run_transaction(state_directory, &path, lock, Some(incoming)).await
}

async fn run_transaction(
    state_directory: &Path,
    bundle: &Path,
    lock: UpdateLock,
    incoming: Option<super::carriage::IncomingBundle>,
) -> Result<StagedUpdate, UpdateError> {
    let state_directory = state_directory.to_path_buf();
    let bundle = bundle.to_path_buf();
    run_owned(lock, incoming, move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(transaction(&state_directory, &bundle))
    })
    .await
}

async fn run_owned(
    lock: UpdateLock,
    incoming: Option<super::carriage::IncomingBundle>,
    operation: impl FnOnce() -> Result<StagedUpdate, UpdateError> + Send + 'static,
) -> Result<StagedUpdate, UpdateError> {
    // Cancellation of a network actor must not release a lock while its
    // blocking materializer still runs or abandon authenticated trust progress.
    // The file-only transaction owns its lock, runtime and cleanup to completion.
    tokio::task::spawn_blocking(move || {
        let _lock = lock;
        let _incoming = incoming;
        operation()
    })
    .await
    .map_err(|_| UpdateError::InvalidBundle)?
}

async fn transaction(state_directory: &Path, bundle: &Path) -> Result<StagedUpdate, UpdateError> {
    if super::lifecycle::activation_pending(state_directory)? {
        return Err(UpdateError::Busy);
    }
    recover_stale_work(state_directory)?;
    let updates = super::updates_directory(state_directory, true)?;
    super::lifecycle::prune_slots(&updates)?;
    let materialized = materialize_bundle(state_directory, bundle)?;
    let result = verify_materialized(&materialized).await;
    let cleanup =
        remove_work_directory(&materialized.work_directory).and_then(|()| super::lifecycle::prune_slots(&updates));
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

#[cfg(test)]
mod tests;
