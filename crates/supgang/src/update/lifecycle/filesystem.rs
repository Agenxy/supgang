use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use super::RECORD_BYTES;
use crate::update::{UpdateError, no_follow};

pub fn write_atomic(parent: &Path, name: &str, bytes: &[u8], mode: u32) -> Result<(), UpdateError> {
    write_atomic_bounded(parent, name, bytes, mode, RECORD_BYTES)
}

pub fn write_atomic_bounded(
    parent: &Path,
    name: &str,
    bytes: &[u8],
    mode: u32,
    maximum: usize,
) -> Result<(), UpdateError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(UpdateError::InvalidBundle);
    }
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| UpdateError::InvalidBundle)?;
    let temporary = parent.join(format!(".{name}.{}.tmp", hex::encode(random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(no_follow()?)
        .open(&temporary)?;
    supgang_acl::clear_inherited_acl(&file)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, parent.join(name))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _cleanup = fs::remove_file(&temporary);
    }
    result
}

pub(super) fn remove_file(path: &Path) -> Result<(), UpdateError> {
    match fs::remove_file(path) {
        Ok(()) => {
            File::open(path.parent().ok_or(UpdateError::InvalidBundle)?)?.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
