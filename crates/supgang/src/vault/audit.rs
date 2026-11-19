//! Bounded owner-only vault use audit, separate from LMS q reservations.

use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use super::{AUDIT_FILE_NAME, AUDIT_LOCK_FILE_NAME, Lock, MAX_AUDIT_BYTES, VaultError, temporary_path, unix_now};
use crate::{
    artifact,
    storage::{no_follow_flag, validate_owner_file_metadata},
};

/// Records a change after it is saved. Reads record first and refuse when the
/// record fails; a change already saved is not undone.
pub(super) fn audit(directory: &Path, operation: &str, name: &str, purpose: Option<&str>) {
    let _result = append_audit(directory, operation, name, purpose);
}

/// Appends one line under the audit lock. At the bound it keeps the newest
/// half of the newest 256 KiB.
pub(super) fn append_audit(
    directory: &Path,
    operation: &str,
    name: &str,
    purpose: Option<&str>,
) -> Result<(), VaultError> {
    // Agent requests must refuse a contended audit lock instead of blocking the socket loop.
    let _lock = Lock::open(directory, AUDIT_LOCK_FILE_NAME, purpose != Some("ssh-sign"))?;
    let path = directory.join(AUDIT_FILE_NAME);
    let existed = fs::symlink_metadata(&path).is_ok();
    let mut file = fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(no_follow_flag()?)
        .open(&path)?;
    if !existed {
        supgang_acl::clear_inherited_acl(&file)?;
    }
    validate_owner_file_metadata(&file)?;
    let program = purpose.map(sanitize_program);
    let line = program.map_or_else(
        || format!("{} {operation} {name}\n", unix_now()),
        |program| format!("{} {operation} {name} {program}\n", unix_now()),
    );
    let length = file.metadata()?.len();
    if length.saturating_add(line.len() as u64) <= MAX_AUDIT_BYTES {
        file.write_all(line.as_bytes())?;
        return Ok(());
    }
    file.seek(SeekFrom::Start(length.saturating_sub(MAX_AUDIT_BYTES)))?;
    let mut kept = Vec::new();
    Read::by_ref(&mut file).take(MAX_AUDIT_BYTES).read_to_end(&mut kept)?;
    let half = kept.len() / 2;
    let start = kept
        .iter()
        .skip(half)
        .position(|byte| *byte == b'\n')
        .map_or(kept.len(), |offset| half + offset + 1);
    let mut replacement = kept.get(start..).unwrap_or_default().to_vec();
    replacement.extend_from_slice(line.as_bytes());
    let temporary = temporary_path(directory)?;
    let result = (|| {
        artifact::write_new(
            &temporary,
            &replacement,
            usize::try_from(MAX_AUDIT_BYTES).unwrap_or(usize::MAX),
        )?;
        fs::rename(&temporary, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _cleanup = fs::remove_file(&temporary);
    }
    result
}

fn sanitize_program(program: &str) -> String {
    let base = program.rsplit('/').next().unwrap_or(program);
    base.chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
        .take(32)
        .collect()
}
