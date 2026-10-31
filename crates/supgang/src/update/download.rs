use std::{
    fs::{self, File},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use futures_util::TryStream;
use tokio::io::AsyncWriteExt;

use super::{UpdateError, carriage::OutputGuard, create_new_owner_file, executable, sync_parent};

const COPY_BUFFER_ACCOUNTING_LIMIT: u64 = super::MAX_UPDATE_TARGET_BYTES;

pub(super) async fn stage_stream<S, B, E>(
    stream: S,
    slot: &Path,
    executable_path: &Path,
    expected_length: u64,
    expected_digest: &[u8],
    identity_authority: &Path,
) -> Result<(), UpdateError>
where
    S: TryStream<Ok = B, Error = E> + Send,
    B: AsRef<[u8]>,
{
    clean_stale_targets(slot)?;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| UpdateError::InvalidBundle)?;
    let temporary = slot.join(format!(".supgang-{}.tmp", hex::encode(random)));
    let destination = create_new_owner_file(&temporary, 0o600)?;
    let mut cleanup = OutputGuard::new(&temporary);
    let mut destination = tokio::fs::File::from_std(destination);
    let mut written = 0_u64;
    let mut stream = Box::pin(stream);
    while let Some(chunk) = std::future::poll_fn(|context| stream.as_mut().try_poll_next(context))
        .await
        .transpose()
        .map_err(|_| UpdateError::Tuf)?
    {
        let bytes = chunk.as_ref();
        written = written
            .checked_add(u64::try_from(bytes.len()).map_err(|_| UpdateError::Tuf)?)
            .ok_or(UpdateError::Tuf)?;
        if written > expected_length || written > COPY_BUFFER_ACCOUNTING_LIMIT {
            return Err(UpdateError::Tuf);
        }
        destination.write_all(bytes).await?;
    }
    if written != expected_length {
        return Err(UpdateError::Tuf);
    }
    destination.sync_all().await?;
    let destination = destination.into_std().await;
    destination.set_permissions(fs::Permissions::from_mode(0o700))?;
    destination.sync_all()?;
    drop(destination);
    executable::validate_staged(&temporary, expected_digest)?;
    executable::validate_compatible_identity(identity_authority, &temporary)?;
    fs::rename(&temporary, executable_path)?;
    sync_parent(executable_path)?;
    cleanup.commit();
    Ok(())
}

fn clean_stale_targets(slot: &Path) -> Result<(), UpdateError> {
    let mut removed = 0_usize;
    for entry in fs::read_dir(slot)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| UpdateError::InvalidBundle)?;
        let Some(random) = name
            .strip_prefix(".supgang-")
            .and_then(|value| value.strip_suffix(".tmp"))
        else {
            return Err(UpdateError::InvalidBundle);
        };
        if random.len() != 32
            || !random
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(UpdateError::InvalidBundle);
        }
        let metadata = entry.path().symlink_metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || !matches!(metadata.mode() & 0o777, 0o600 | 0o700)
            || metadata.len() > super::MAX_UPDATE_TARGET_BYTES
        {
            return Err(UpdateError::InvalidBundle);
        }
        if removed >= 8 {
            return Err(UpdateError::Capacity);
        }
        fs::remove_file(entry.path())?;
        removed = removed.checked_add(1).ok_or(UpdateError::Capacity)?;
    }
    File::open(slot)?.sync_all()?;
    Ok(())
}
