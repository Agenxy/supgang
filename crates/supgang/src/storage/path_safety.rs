//! Ancestor-chain validation for protected per-user storage.

use std::{
    env, fs,
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

use super::StorageError;

pub(super) fn normalized_absolute(path: &Path) -> Result<PathBuf, StorageError> {
    let source = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in source.components() {
        match component {
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(StorageError::UnsafeAncestor);
                }
            }
            Component::Normal(value) => normalized.push(value),
            Component::Prefix(_) => return Err(StorageError::UnsafeAncestor),
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(StorageError::UnsafeAncestor);
    }
    Ok(normalized)
}

pub(super) fn nearest_existing_ancestor(path: &Path) -> Result<PathBuf, StorageError> {
    let mut candidate = path.to_path_buf();
    loop {
        match fs::symlink_metadata(&candidate) {
            Ok(_) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !candidate.pop() {
                    return Err(StorageError::UnsafeAncestor);
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub(super) fn validate_ancestor_chain(path: &Path, final_must_be_owner: bool) -> Result<(), StorageError> {
    let current_uid = rustix::process::getuid().as_raw();
    let mut current = PathBuf::from("/");
    super::validate_ancestor_acl(&File::open(&current)?)?;
    let components = path.components().filter_map(|component| match component {
        Component::Normal(value) => Some(value),
        _ => None,
    });
    let component_count = components.clone().count();
    for (index, component) in components.enumerate() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            if metadata.uid() == 0 && index + 1 < component_count {
                continue;
            }
            return Err(StorageError::UnsafeAncestor);
        }
        if !metadata.file_type().is_dir() {
            return Err(StorageError::UnsafeAncestor);
        }
        let owner = metadata.uid();
        validate_ancestor_access(&File::open(&current)?, owner, metadata.mode(), current_uid)?;
        if final_must_be_owner && index + 1 == component_count && owner != current_uid {
            return Err(StorageError::WrongOwner);
        }
    }
    let resolved = fs::canonicalize(path)?;
    validate_resolved_chain(&resolved, final_must_be_owner, current_uid)
}

fn validate_resolved_chain(path: &Path, final_must_be_owner: bool, current_uid: u32) -> Result<(), StorageError> {
    let mut current = PathBuf::from("/");
    super::validate_ancestor_acl(&File::open(&current)?)?;
    let components = path.components().filter_map(|component| match component {
        Component::Normal(value) => Some(value),
        _ => None,
    });
    let component_count = components.clone().count();
    for (index, component) in components.enumerate() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(StorageError::UnsafeAncestor);
        }
        let owner = metadata.uid();
        validate_ancestor_access(&File::open(&current)?, owner, metadata.mode(), current_uid)?;
        if final_must_be_owner && index + 1 == component_count && owner != current_uid {
            return Err(StorageError::WrongOwner);
        }
    }
    Ok(())
}

fn validate_ancestor_access(file: &File, owner: u32, mode: u32, current_uid: u32) -> Result<(), StorageError> {
    if (owner != 0 && owner != current_uid) || mode & 0o022 != 0 {
        return Err(StorageError::UnsafeAncestor);
    }
    // Root ownership does not override ACL grants to another account.
    super::validate_ancestor_acl(file)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{validate_ancestor_access, validate_ancestor_chain, validate_resolved_chain};
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    #[test]
    fn both_ancestor_walks_reject_acl_grants_and_accept_deny_only() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let path = fs::canonicalize(temporary.path())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let uid = rustix::process::getuid().as_raw();
        for entry in ["everyone allow add_file,delete_child", "everyone deny delete"] {
            assert!(
                Command::new("/bin/chmod")
                    .args(["+a", entry])
                    .arg(&path)
                    .status()?
                    .success()
            );
            let allowed = entry.contains("deny");
            // Exercise both ownership branches with a real ACL descriptor.
            // Simulating UID 0 here avoids modifying any system-owned directory.
            for owner in [0, uid] {
                assert_eq!(
                    validate_ancestor_access(&fs::File::open(&path)?, owner, 0o755, uid).is_ok(),
                    allowed
                );
            }
            assert_eq!(validate_ancestor_chain(&path, true).is_ok(), allowed);
            assert_eq!(validate_resolved_chain(&path, true, uid).is_ok(), allowed);
            assert!(Command::new("/bin/chmod").arg("-N").arg(&path).status()?.success());
        }
        // Exercise real, root-owned platform ancestors without privilege or mutation.
        validate_ancestor_chain(std::path::Path::new("/private/var"), false)?;
        Ok(())
    }
}
