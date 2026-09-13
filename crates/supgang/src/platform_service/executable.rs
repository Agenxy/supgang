//! Protected executable installation for persistent background managers.

use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use super::{ServiceError, ensure_child_directory, owner_home, validate_owner_directory};

const INSTALLED_EXECUTABLE_NAME: &str = "supgang";
const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

/// Copies the running executable through a validated file descriptor into a
/// dedicated owner-only directory and returns the persistent manager path.
pub(super) fn install_current() -> Result<PathBuf, ServiceError> {
    let target = installed_path(true)?;
    let source_path = env::current_exe()?.canonicalize()?;
    let no_follow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).map_err(|_| ServiceError::UnsafeExecutable)?;
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(no_follow)
        .open(source_path)?;
    validate_source(&source)?;
    copy_atomic(&mut source, &target)?;
    validate_installed_at(&target)?;
    Ok(target)
}

/// Revalidates the protected executable used by an existing service.
pub(super) fn validate_installed() -> Result<PathBuf, ServiceError> {
    let path = installed_path(false)?;
    validate_installed_at(&path)?;
    Ok(path)
}

fn installed_path(create: bool) -> Result<PathBuf, ServiceError> {
    let home = owner_home()?;
    #[cfg(target_os = "macos")]
    let components = ["Library", "Application Support", "org.agenxy.supgang", "bin"];
    #[cfg(not(target_os = "macos"))]
    let components = [".local", "lib", "supgang", "bin"];

    let mut directory = home;
    for component in components {
        directory = if create {
            ensure_child_directory(&directory, component)?
        } else {
            let child = directory.join(component);
            validate_owner_directory(&child)?;
            child
        };
    }
    Ok(directory.join(INSTALLED_EXECUTABLE_NAME))
}

fn validate_source(file: &File) -> Result<(), ServiceError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_EXECUTABLE_BYTES
        || supgang_acl::reject_non_owner_grants(file).is_err()
    {
        return Err(ServiceError::UnsafeExecutable);
    }
    Ok(())
}

fn validate_installed_at(path: &Path) -> Result<(), ServiceError> {
    let parent = path.parent().ok_or(ServiceError::UnsafeExecutable)?;
    validate_owner_directory(parent).map_err(|_| ServiceError::UnsafeExecutable)?;
    let no_follow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).map_err(|_| ServiceError::UnsafeExecutable)?;
    let file = OpenOptions::new().read(true).custom_flags(no_follow).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
        || metadata.len() == 0
        || metadata.len() > MAX_EXECUTABLE_BYTES
        || supgang_acl::reject_non_owner_grants(&file).is_err()
    {
        return Err(ServiceError::UnsafeExecutable);
    }
    Ok(())
}

fn copy_atomic(source: &mut File, target: &Path) -> Result<(), ServiceError> {
    let parent = target.parent().ok_or(ServiceError::UnsafeExecutable)?;
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_| ServiceError::UnsafeExecutable)?;
    let temporary = parent.join(format!(".supgang.{}.tmp", hex::encode(random)));
    let no_follow = i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits())
        .map_err(|_| ServiceError::UnsafeExecutable)?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .custom_flags(no_follow)
        .open(&temporary)?;
    supgang_acl::clear_inherited_acl(&destination)?;
    destination.set_permissions(fs::Permissions::from_mode(0o700))?;
    validate_destination(&destination)?;
    let result = copy_bounded(source, &mut destination).and_then(|()| {
        destination.sync_all()?;
        fs::rename(&temporary, target)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    });
    if result.is_err() {
        let _cleanup = fs::remove_file(&temporary);
    }
    result
}

fn validate_destination(file: &File) -> Result<(), ServiceError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(ServiceError::UnsafeExecutable);
    }
    Ok(())
}

fn copy_bounded(source: &mut File, destination: &mut File) -> Result<(), ServiceError> {
    let expected = source.metadata()?.len();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(read).map_err(|_| ServiceError::UnsafeExecutable)?)
            .ok_or(ServiceError::UnsafeExecutable)?;
        if copied > expected || copied > MAX_EXECUTABLE_BYTES {
            return Err(ServiceError::UnsafeExecutable);
        }
        let bytes = buffer.get(..read).ok_or(ServiceError::UnsafeExecutable)?;
        destination.write_all(bytes)?;
    }
    if copied != expected {
        return Err(ServiceError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "executable changed while it was copied",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::{copy_bounded, validate_installed_at};

    #[test]
    fn installed_executable_requires_exact_owner_only_mode() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let executable = temporary.path().join("supgang");
        fs::write(&executable, b"binary")?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
        validate_installed_at(&executable)?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
        assert!(validate_installed_at(&executable).is_err());
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o777))?;
        assert!(validate_installed_at(&executable).is_err());
        Ok(())
    }

    #[test]
    fn executable_copy_is_bounded_and_exact() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let source_path = temporary.path().join("source");
        let destination_path = temporary.path().join("destination");
        fs::write(&source_path, vec![7_u8; 128 * 1024])?;
        let mut source = fs::File::open(&source_path)?;
        let mut destination = fs::File::create(&destination_path)?;
        copy_bounded(&mut source, &mut destination)?;
        assert_eq!(fs::read(destination_path)?, vec![7_u8; 128 * 1024]);
        Ok(())
    }
}
