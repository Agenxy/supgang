//! Owner-only, bounded offline artifact files.

use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{fs::OpenOptionsExt, prelude::MetadataExt},
    path::Path,
};

use thiserror::Error;

/// An offline artifact filesystem or validation failure.
#[derive(Debug, Error)]
pub enum ArtifactError {
    /// The operating system rejected a filesystem operation.
    #[error("offline artifact filesystem operation failed")]
    Io(#[from] io::Error),
    /// The path is not a regular file.
    #[error("offline artifact must be a regular file, not a symlink or special file")]
    NotRegularFile,
    /// Another operating-system user owns the file.
    #[error("offline artifact is not owned by the current user")]
    WrongOwner,
    /// Another user can read or modify the file.
    #[error("offline artifact permissions must be 0600")]
    InsecurePermissions,
    /// The artifact exceeds the caller's protocol budget.
    #[error("offline artifact exceeds its protocol size limit")]
    Oversized,
    /// Empty artifacts are invalid.
    #[error("offline artifact is empty")]
    Empty,
    /// Refusing to replace an existing artifact prevents accidental secret loss.
    #[error("offline artifact already exists; choose a new path")]
    AlreadyExists,
}

/// Writes a new mode-0600 artifact without following a final symlink.
///
/// # Errors
///
/// Rejects empty or oversized content, existing paths, symlinks, insecure
/// metadata, and write or synchronization failures.
pub fn write_new(path: impl AsRef<Path>, bytes: &[u8], maximum: usize) -> Result<(), ArtifactError> {
    if bytes.is_empty() {
        return Err(ArtifactError::Empty);
    }
    if bytes.len() > maximum {
        return Err(ArtifactError::Oversized);
    }
    let no_follow = no_follow_flag()?;
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(no_follow)
        .open(path.as_ref())
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Err(ArtifactError::AlreadyExists),
        Err(error) => return Err(error.into()),
    };
    validate(&file)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(parent) = path.as_ref().parent().filter(|value| !value.as_os_str().is_empty()) {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Reads one owner-only artifact after checking its size before allocation.
///
/// # Errors
///
/// Rejects symlinks, special files, foreign ownership, insecure permissions,
/// empty files, oversized files, and I/O failures.
pub fn read(path: impl AsRef<Path>, maximum: usize) -> Result<Vec<u8>, ArtifactError> {
    let no_follow = no_follow_flag()?;
    let mut file = OpenOptions::new().read(true).custom_flags(no_follow).open(path)?;
    validate(&file)?;
    let length = file.metadata()?.len();
    if length == 0 {
        return Err(ArtifactError::Empty);
    }
    if length > u64::try_from(maximum).unwrap_or(u64::MAX) {
        return Err(ArtifactError::Oversized);
    }
    let capacity = usize::try_from(length).map_err(|_| ArtifactError::Oversized)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(ArtifactError::Oversized);
    }
    Ok(bytes)
}

fn validate(file: &File) -> Result<(), ArtifactError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(ArtifactError::NotRegularFile);
    }
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(ArtifactError::WrongOwner);
    }
    if metadata.mode() & 0o777 != 0o600 {
        return Err(ArtifactError::InsecurePermissions);
    }
    Ok(())
}

fn no_follow_flag() -> Result<i32, ArtifactError> {
    i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).map_err(|_| ArtifactError::NotRegularFile)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::{ArtifactError, read, write_new};

    #[test]
    fn artifact_round_trips_and_never_overwrites() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("request.sg");
        write_new(&path, b"bounded", 32)?;
        assert_eq!(read(&path, 32)?, b"bounded");
        assert!(matches!(
            write_new(&path, b"changed", 32),
            Err(ArtifactError::AlreadyExists)
        ));
        Ok(())
    }

    #[test]
    fn permissive_artifact_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("request.sg");
        write_new(&path, b"bounded", 32)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(matches!(read(&path, 32), Err(ArtifactError::InsecurePermissions)));
        Ok(())
    }
}
