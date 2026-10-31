//! One-time, owner-only replacement of default-named transport certificates.

use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use super::{
    TransportIdentity, TransportStorageError, fs, no_follow_flag, sync_directory, validate_owner_file_metadata,
    write_file,
};

pub(super) fn lock(directory: &Path) -> Result<File, TransportStorageError> {
    let path = directory.join("transport.lock");
    let (file, created) = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(no_follow_flag()?)
        .open(&path)
    {
        Ok(file) => (file, true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(no_follow_flag()?)
                .open(&path)?,
            false,
        ),
        Err(error) => return Err(error.into()),
    };
    if created {
        supgang_acl::clear_inherited_acl(&file)?;
    }
    validate_owner_file_metadata(&file)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(io::Error::from)?;
    if created {
        file.sync_all()?;
        sync_directory(directory)?;
    }
    Ok(file)
}

pub(super) fn replace(
    directory: &Path,
    path: &Path,
    identity: &TransportIdentity,
) -> Result<(), TransportStorageError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let temporary = directory.join(format!(".supgang-transport-{}.tmp", hex::encode(random)));
    // Creation must succeed before cleanup may remove anything at this name.
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(no_follow_flag()?)
        .open(&temporary)?;
    let result = write_file(file, identity).and_then(|()| {
        fs::rename(&temporary, path)?;
        sync_directory(directory)?;
        Ok(())
    });
    if result.is_err() {
        let _cleanup = fs::remove_file(&temporary);
    }
    result
}
