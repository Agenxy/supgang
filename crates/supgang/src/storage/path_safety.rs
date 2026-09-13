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
        if owner != 0 && owner != current_uid {
            return Err(StorageError::UnsafeAncestor);
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(StorageError::UnsafeAncestor);
        }
        if owner == current_uid {
            super::validate_descriptor_acl(&File::open(&current)?)?;
        }
        if final_must_be_owner && index + 1 == component_count && owner != current_uid {
            return Err(StorageError::WrongOwner);
        }
    }
    let resolved = fs::canonicalize(path)?;
    validate_resolved_chain(&resolved, final_must_be_owner, current_uid)
}

fn validate_resolved_chain(path: &Path, final_must_be_owner: bool, current_uid: u32) -> Result<(), StorageError> {
    let mut current = PathBuf::from("/");
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
        if owner != 0 && owner != current_uid {
            return Err(StorageError::UnsafeAncestor);
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(StorageError::UnsafeAncestor);
        }
        if owner == current_uid {
            super::validate_descriptor_acl(&File::open(&current)?)?;
        }
        if final_must_be_owner && index + 1 == component_count && owner != current_uid {
            return Err(StorageError::WrongOwner);
        }
    }
    Ok(())
}
