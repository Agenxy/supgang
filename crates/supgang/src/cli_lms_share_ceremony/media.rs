//! Removable-media I/O, preflight, and rollback for NC0 SLIP-39 share files.
//!
//! Share files are age v1 scrypt-encrypted ciphertext carried on removable
//! cross-platform media (exFAT by default so any gang machine, macOS or Linux,
//! can read them; APFS as fallback). Unlike host-local state written through
//! `crate::artifact::write_new`, Unix mode bits and extended ACLs are not a
//! security boundary on exFAT or FAT filesystems (which expose mount-default
//! modes such as 0700 and return `ENOTSUP` to ACL calls). This module keeps
//! `O_EXCL | O_NOFOLLOW`, bounded reads, full flush (`fsync`, `F_FULLFSYNC` on
//! macOS, and parent-directory `fsync`), and readback byte-equality checks,
//! while treating `0600` creation mode and ACL clearing as best effort.

use std::{
    collections::HashSet,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use super::{MEDIA_LABELS, ROLES, share_file_name};

/// Minimum free space required on each removable medium before starting.
pub(super) const MIN_MEDIA_FREE_BYTES: u64 = 64 * 1024;
const PREFLIGHT_PROBE_BYTES: &[u8] = b"supgang-nc0-media-preflight-v1\n";
const PREFLIGHT_PROBE_MAX: usize = 128;

fn is_acl_unsupported(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::Unsupported {
        return true;
    }
    let Some(errno) = rustix::io::Errno::from_io_error(error) else {
        return false;
    };
    errno == rustix::io::Errno::NOTSUP || errno == rustix::io::Errno::OPNOTSUPP
}

fn no_follow_flags() -> Result<i32, String> {
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
    i32::try_from(flags.bits()).map_err(|_| "unsupported open flags".to_owned())
}

/// Returns true when the path's final component is a macOS `._*` `AppleDouble` file.
pub fn is_appledouble_path(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.as_encoded_bytes().starts_with(b"._"))
}

pub(super) fn appledouble_path(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?;
    let mut sidecar = OsString::from("._");
    sidecar.push(name);
    Some(match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(sidecar),
        _ => PathBuf::from(sidecar),
    })
}

pub(super) fn remove_appledouble(path: &Path) {
    if let Some(sidecar) = appledouble_path(path) {
        let _ = fs::remove_file(sidecar);
    }
}

pub(super) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

fn sync_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
        sync_dir(parent)?;
    }
    Ok(())
}

fn cleanup_created_file(path: &Path) {
    let _ = fs::remove_file(path);
    remove_appledouble(path);
    let _ = sync_parent_dir(path);
}

/// Writes one encrypted share file to removable media with durability and readback verification.
///
/// The content is age-encrypted ciphertext and Unix mode bits are not a security
/// boundary on removable media (exFAT/FAT). Creation requests mode `0600` and
/// clears inherited ACLs as best effort (ignoring `ENOTSUP`), never failing on
/// mode. Durability is enforced via `O_EXCL | O_NOFOLLOW`, `fsync` plus
/// `F_FULLFSYNC` on macOS, parent-directory `fsync`, and a reopen readback
/// requiring exact byte equality.
pub(super) fn write_share_file(path: &Path, bytes: &[u8], maximum: usize) -> Result<(), String> {
    if bytes.is_empty() {
        return Err(format!("{}: share content is empty", path.display()));
    }
    if bytes.len() > maximum {
        return Err(format!("{}: share content exceeds size limit", path.display()));
    }
    if is_appledouble_path(path) {
        return Err(format!(
            "{}: refusing to write AppleDouble metadata path",
            path.display()
        ));
    }
    let flags = no_follow_flags()?;
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(flags)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(format!("{}: already exists; choose fresh media", path.display()));
        }
        Err(error) => return Err(format!("{}: could not create share file: {error}", path.display())),
    };

    // Best-effort ACL clear: POSIX filesystems clear inherited ACLs while
    // removable filesystems such as exFAT return ENOTSUP (os error 45 on macOS).
    if let Err(error) = supgang_acl::clear_inherited_acl(&file)
        && !is_acl_unsupported(&error)
    {
        drop(file);
        cleanup_created_file(path);
        return Err(format!("{}: could not clear inherited ACL: {error}", path.display()));
    }

    if let Err(error) = file.write_all(bytes) {
        drop(file);
        cleanup_created_file(path);
        return Err(format!("{}: write failed: {error}", path.display()));
    }
    if let Err(error) = file.sync_all() {
        drop(file);
        cleanup_created_file(path);
        return Err(format!("{}: fsync failed: {error}", path.display()));
    }
    #[cfg(target_os = "macos")]
    if let Err(error) = rustix::fs::fcntl_fullfsync(&file) {
        drop(file);
        cleanup_created_file(path);
        return Err(format!("{}: F_FULLFSYNC failed: {error}", path.display()));
    }
    drop(file);

    if let Err(error) = sync_parent_dir(path) {
        cleanup_created_file(path);
        return Err(format!("{}: parent directory fsync failed: {error}", path.display()));
    }

    let readback = match read_share_file(path, maximum) {
        Ok(readback) => readback,
        Err(error) => {
            cleanup_created_file(path);
            return Err(format!("{}: readback failed: {error}", path.display()));
        }
    };
    if readback.as_slice() != bytes {
        cleanup_created_file(path);
        return Err(format!("{}: readback bytes differ from written share", path.display()));
    }
    Ok(())
}

/// Reads one bounded encrypted share file from removable media.
///
/// Skips Unix owner and `0600` mode checks because removable cross-platform
/// filesystems (exFAT/FAT) do not enforce per-file POSIX ownership or mode bits,
/// and the share content is authenticated age ciphertext. Still enforces
/// `O_NOFOLLOW | O_NONBLOCK`, regular-file type, bounded allocation, and refuses
/// macOS `._*` `AppleDouble` files.
pub fn read_share_file(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    if is_appledouble_path(path) {
        return Err(format!(
            "{}: AppleDouble metadata file (._*) is not a share file",
            path.display()
        ));
    }
    let flags = no_follow_flags()?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|error| format!("{}: could not open share file: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("{}: could not inspect share file: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{}: share path must be a regular file, not a symlink or special file",
            path.display()
        ));
    }
    let length = metadata.len();
    if length == 0 {
        return Err(format!("{}: share file is empty", path.display()));
    }
    let max_u64 = u64::try_from(maximum).unwrap_or(u64::MAX);
    if length > max_u64 {
        return Err(format!("{}: share file exceeds protocol size limit", path.display()));
    }
    let capacity =
        usize::try_from(length).map_err(|_| format!("{}: share file exceeds protocol size limit", path.display()))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(max_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{}: could not read share file: {error}", path.display()))?;
    if bytes.len() > maximum {
        return Err(format!("{}: share file exceeds protocol size limit", path.display()));
    }
    if bytes.len() != capacity {
        return Err(format!("{}: share file changed while being read", path.display()));
    }
    Ok(bytes)
}

fn check_free_space(dir: &Path, label: &str) -> Result<(), String> {
    let vfs = rustix::fs::statvfs(dir)
        .map_err(|error| format!("medium {label} ({}): cannot inspect free space: {error}", dir.display()))?;
    let unit = if vfs.f_frsize > 0 { vfs.f_frsize } else { vfs.f_bsize };
    let available = vfs.f_bavail.saturating_mul(unit);
    if available < MIN_MEDIA_FREE_BYTES {
        return Err(format!(
            "medium {label} ({}): insufficient free space ({available} bytes available, need at least {MIN_MEDIA_FREE_BYTES} bytes)",
            dir.display()
        ));
    }
    Ok(())
}

/// Validates and preflights all three media directories before any randomness is drawn.
///
/// Checks existence, directory type, distinct canonical paths, distinct `st_dev`
/// (when `require_distinct_devices` is true), at least 64 KiB free space, absence
/// of existing share files (ignoring unrelated `._*` files), and executes a probe
/// write + `fsync` + `F_FULLFSYNC` + dir `fsync` + readback + delete (including
/// any `._probe` sidecar) on each medium.
pub(super) fn preflight_media(
    medium_a: &Path,
    medium_b: &Path,
    medium_c: &Path,
    require_distinct_devices: bool,
) -> Result<[PathBuf; 3], String> {
    let inputs = [medium_a, medium_b, medium_c];
    let mut seen_dirs = HashSet::with_capacity(3);
    let mut seen_devs = HashSet::with_capacity(3);

    for (dir, label) in inputs.iter().zip(MEDIA_LABELS) {
        let meta =
            fs::metadata(dir).map_err(|_| format!("medium {label} ({}): directory unavailable", dir.display()))?;
        if !meta.is_dir() {
            return Err(format!("medium {label} ({}): not a directory", dir.display()));
        }
        let canonical =
            fs::canonicalize(dir).map_err(|_| format!("medium {label} ({}): cannot canonicalize", dir.display()))?;
        if !seen_dirs.insert(canonical) {
            return Err(format!(
                "medium {label} ({}): duplicate medium directory",
                dir.display()
            ));
        }
        if require_distinct_devices && !seen_devs.insert(meta.dev()) {
            return Err(format!(
                "medium {label} ({}): shares the same storage device (st_dev) as another medium; mount three separate drives",
                dir.display()
            ));
        }
        check_free_space(dir, label)?;
        for role in ROLES {
            let target = dir.join(share_file_name(role));
            match fs::symlink_metadata(&target) {
                Ok(_) => return Err(format!("{}: already exists", target.display())),
                Err(problem) if problem.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err(format!("{}: cannot inspect destination", target.display())),
            }
        }
    }

    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());

    for (dir, label) in inputs.iter().zip(MEDIA_LABELS) {
        let probe_path = dir.join(format!("supgang-preflight-{pid}-{nanos}-{label}.tmp"));
        write_share_file(&probe_path, PREFLIGHT_PROBE_BYTES, PREFLIGHT_PROBE_MAX)
            .map_err(|error| format!("medium {label} ({}): preflight failed: {error}", dir.display()))?;
        let remove_result = fs::remove_file(&probe_path);
        remove_appledouble(&probe_path);
        let sync_result = sync_dir(dir);
        remove_result.map_err(|error| {
            format!(
                "medium {label} ({}): could not remove preflight probe: {error}",
                dir.display()
            )
        })?;
        sync_result.map_err(|error| {
            format!(
                "medium {label} ({}): could not sync directory after preflight: {error}",
                dir.display()
            )
        })?;
    }

    Ok([medium_a.to_path_buf(), medium_b.to_path_buf(), medium_c.to_path_buf()])
}

/// Removes all share files written so far (plus a failing partial target if present),
/// syncs every medium directory, and formats a clear operator error message.
pub(super) fn rollback_partial_shares(
    media: &[PathBuf; 3],
    created: &[PathBuf],
    failing_target: Option<&Path>,
    cause: &str,
) -> String {
    let mut removed = Vec::with_capacity(created.len() + 1);
    let mut failed_removals = Vec::new();

    if let Some(target) = failing_target
        && fs::symlink_metadata(target).is_ok()
    {
        match fs::remove_file(target) {
            Ok(()) => {
                remove_appledouble(target);
                removed.push(target.display().to_string());
            }
            Err(error) => failed_removals.push(format!("{} ({error})", target.display())),
        }
    }

    for path in created {
        match fs::remove_file(path) {
            Ok(()) => {
                remove_appledouble(path);
                removed.push(path.display().to_string());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                remove_appledouble(path);
            }
            Err(error) => failed_removals.push(format!("{} ({error})", path.display())),
        }
    }

    let mut sync_errors = Vec::new();
    for dir in media {
        if let Err(error) = sync_dir(dir) {
            sync_errors.push(format!("{} ({error})", dir.display()));
        }
    }

    let removed_summary = if removed.is_empty() {
        "none".to_owned()
    } else {
        removed.join(", ")
    };

    if failed_removals.is_empty() && sync_errors.is_empty() {
        format!(
            "{cause}; cleaned up share file(s): [{removed_summary}]; no share files remain, so the ceremony can be repeated on fresh media"
        )
    } else {
        format!(
            "{cause}; removed share file(s): [{removed_summary}]; cleanup warnings: failed removals [{}], sync errors [{}]; inspect media before repeating",
            failed_removals.join(", "),
            sync_errors.join(", ")
        )
    }
}
