use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::{
    MAX_UPDATE_BUNDLE_BYTES, UPDATE_DIGEST_BYTES, UpdateError, create_new_owner_file, no_follow, open_owner_file,
    updates_directory,
};

const OUTBOX_DIRECTORY: &str = "outbox";
const INBOX_DIRECTORY: &str = "inbox";
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_OUTBOX_BUNDLES: usize = 4;
const MAX_STALE_INBOX_FILES: usize = 8;

pub(super) struct OutputGuard {
    path: PathBuf,
    committed: bool,
}

impl OutputGuard {
    pub(super) fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            committed: false,
        }
    }

    pub(super) const fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for OutputGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _removed = fs::remove_file(&self.path);
        }
    }
}

pub struct IncomingBundle {
    pub(crate) path: PathBuf,
    pub(crate) file: File,
}

pub fn prepare_outbound(state_directory: &Path, source: &Path) -> Result<[u8; UPDATE_DIGEST_BYTES], UpdateError> {
    let _lock = super::lock::UpdateLock::acquire(state_directory)?;
    let mut source = open_owner_file(source, 0o600, MAX_UPDATE_BUNDLE_BYTES)?;
    let length = source.metadata()?.len();
    let updates = updates_directory(state_directory, true)?;
    let outbox = super::ensure_child(&updates, OUTBOX_DIRECTORY)?;
    clean_outbox_temporary_files(&outbox)?;
    let expected_digest = super::hash_exact(&mut source, length)?;
    let target = outbox.join(format!("{}.bundle", hex::encode(expected_digest)));
    if target.symlink_metadata().is_ok() {
        let _existing = outbound_bundle(state_directory, &expected_digest)?;
        return Ok(expected_digest);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|_| UpdateError::InvalidBundle)?
        .as_secs();
    let protected = super::delivery_queue::protected_outbox_digests(&updates, now)?;
    make_outbox_room(&outbox, &protected)?;
    source.rewind()?;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| UpdateError::InvalidBundle)?;
    let temporary = outbox.join(format!(".{}.tmp", hex::encode(random)));
    let mut destination = create_new_owner_file(&temporary, 0o600)?;
    let mut cleanup = OutputGuard::new(&temporary);
    let mut hasher = Sha256::new();
    let mut remaining = length;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        let wanted =
            usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64)).map_err(|_| UpdateError::InvalidBundle)?;
        let count = source.read(buffer.get_mut(..wanted).ok_or(UpdateError::InvalidBundle)?)?;
        if count == 0 {
            return Err(UpdateError::InvalidBundle);
        }
        let bytes = buffer.get(..count).ok_or(UpdateError::InvalidBundle)?;
        destination.write_all(bytes)?;
        hasher.update(bytes);
        remaining = remaining
            .checked_sub(u64::try_from(count).map_err(|_| UpdateError::InvalidBundle)?)
            .ok_or(UpdateError::InvalidBundle)?;
    }
    destination.sync_all()?;
    let digest: [u8; UPDATE_DIGEST_BYTES] = hasher.finalize().into();
    if digest != expected_digest {
        return Err(UpdateError::InvalidBundle);
    }
    fs::rename(&temporary, &target)?;
    cleanup.commit();
    File::open(&outbox)?.sync_all()?;
    Ok(digest)
}

pub fn outbound_bundle(state_directory: &Path, digest: &[u8; UPDATE_DIGEST_BYTES]) -> Result<File, UpdateError> {
    let updates = updates_directory(state_directory, false)?;
    let outbox = super::ensure_child(&updates, OUTBOX_DIRECTORY)?;
    let path = outbox.join(format!("{}.bundle", hex::encode(digest)));
    let mut file = open_owner_file(&path, 0o600, MAX_UPDATE_BUNDLE_BYTES)?;
    let length = file.metadata()?.len();
    let actual = super::hash_exact(&mut file, length)?;
    if actual != *digest {
        return Err(UpdateError::InvalidBundle);
    }
    file.rewind()?;
    Ok(file)
}

pub fn incoming_bundle(state_directory: &Path) -> Result<IncomingBundle, UpdateError> {
    let updates = updates_directory(state_directory, true)?;
    let inbox = super::ensure_child(&updates, INBOX_DIRECTORY)?;
    clean_inbox(&inbox)?;
    for _ in 0..8 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| UpdateError::InvalidBundle)?;
        let path = inbox.join(format!(".incoming-{}.bundle", hex::encode(random)));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(no_follow()?)
            .open(&path)
        {
            Ok(file) => {
                supgang_acl::clear_inherited_acl(&file)?;
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
                return Ok(IncomingBundle { path, file });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(UpdateError::InvalidBundle)
}

fn make_outbox_room(
    directory: &Path,
    protected: &std::collections::BTreeSet<[u8; UPDATE_DIGEST_BYTES]>,
) -> Result<(), UpdateError> {
    let mut bundles = Vec::with_capacity(MAX_OUTBOX_BUNDLES);
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| UpdateError::InvalidBundle)?;
        if !valid_bundle_name(&name) {
            return Err(UpdateError::InvalidBundle);
        }
        let validated = open_owner_file(&entry.path(), 0o600, MAX_UPDATE_BUNDLE_BYTES)?;
        let digest: [u8; UPDATE_DIGEST_BYTES] = name
            .strip_suffix(".bundle")
            .and_then(|value| hex::decode(value).ok())
            .and_then(|value| value.try_into().ok())
            .ok_or(UpdateError::InvalidBundle)?;
        bundles.push((
            protected.contains(&digest),
            validated.metadata()?.modified()?,
            entry.path(),
        ));
        if bundles.len() > MAX_OUTBOX_BUNDLES {
            return Err(UpdateError::Capacity);
        }
    }
    if bundles.len() == MAX_OUTBOX_BUNDLES {
        bundles.sort();
        let oldest = bundles
            .iter()
            .find(|(is_protected, _, _)| !is_protected)
            .ok_or(UpdateError::Capacity)?;
        fs::remove_file(&oldest.2)?;
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

fn clean_outbox_temporary_files(directory: &Path) -> Result<(), UpdateError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| UpdateError::InvalidBundle)?;
        if name.starts_with('.') {
            if !valid_random_name(&name, ".", ".tmp") {
                return Err(UpdateError::InvalidBundle);
            }
            let metadata = entry.path().symlink_metadata()?;
            if !metadata.file_type().is_file()
                || metadata.uid() != rustix::process::getuid().as_raw()
                || metadata.mode() & 0o777 != 0o600
                || metadata.len() > MAX_UPDATE_BUNDLE_BYTES
            {
                return Err(UpdateError::InvalidBundle);
            }
            fs::remove_file(entry.path())?;
        }
    }
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn clean_inbox(directory: &Path) -> Result<(), UpdateError> {
    let mut removed = 0_usize;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| UpdateError::InvalidBundle)?;
        if !valid_random_name(&name, ".incoming-", ".bundle") {
            return Err(UpdateError::InvalidBundle);
        }
        let metadata = entry.path().symlink_metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() > MAX_UPDATE_BUNDLE_BYTES
        {
            return Err(UpdateError::InvalidBundle);
        }
        if removed >= MAX_STALE_INBOX_FILES {
            return Err(UpdateError::Capacity);
        }
        fs::remove_file(entry.path())?;
        removed = removed.checked_add(1).ok_or(UpdateError::Capacity)?;
    }
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn valid_bundle_name(name: &str) -> bool {
    name.strip_suffix(".bundle").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_random_name(name: &str, prefix: &str, suffix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .is_some_and(|random| {
            random.len() == 32
                && random
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}
