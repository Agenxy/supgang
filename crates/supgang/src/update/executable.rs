use std::path::Path;

#[cfg(target_os = "macos")]
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

use super::{MAX_UPDATE_TARGET_BYTES, UpdateError, artifact_like_read};

pub(super) fn validate(bytes: &[u8]) -> Result<(), UpdateError> {
    #[cfg(target_os = "macos")]
    let valid = matches!(
        bytes.get(..4),
        Some([0xcf, 0xfa, 0xed, 0xfe] | [0xca, 0xfe, 0xba, 0xbe])
    );
    #[cfg(target_os = "linux")]
    let valid = bytes.get(..4) == Some(b"\x7fELF");
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let valid = false;
    if valid {
        Ok(())
    } else {
        Err(UpdateError::InvalidExecutable)
    }
}

pub(super) fn validate_staged(path: &Path, expected_digest: &[u8]) -> Result<(), UpdateError> {
    let bytes = artifact_like_read(path, MAX_UPDATE_TARGET_BYTES, 0o700)?;
    if Sha256::digest(&bytes).as_slice() != expected_digest {
        return Err(UpdateError::Tuf);
    }
    validate(&bytes)?;
    validate_platform_signature(path)
}

/// Requires `candidate` to retain the platform identity approved for
/// `authority`. TUF authorizes release bytes; this separate check preserves
/// the local operating-system policy that tracks Supgang across updates.
pub(super) fn validate_compatible_identity(authority: &Path, candidate: &Path) -> Result<(), UpdateError> {
    validate_platform_signature(authority)?;
    validate_platform_signature(candidate)?;
    validate_platform_identity(authority, candidate)
}

#[cfg(not(target_os = "macos"))]
fn validate_platform_signature(_path: &Path) -> Result<(), UpdateError> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn validate_platform_identity(_authority: &Path, _candidate: &Path) -> Result<(), UpdateError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_platform_signature(path: &Path) -> Result<(), UpdateError> {
    let output = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--verbose=2"])
        .arg(path)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(UpdateError::IncompatibleCodeIdentity)
    }
}

#[cfg(target_os = "macos")]
fn validate_platform_identity(authority: &Path, candidate: &Path) -> Result<(), UpdateError> {
    let requirement = designated_requirement(authority)?;
    let literal_requirement = format!("={requirement}");
    let output = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--test-requirement"])
        .arg(&literal_requirement)
        .arg(candidate)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(UpdateError::IncompatibleCodeIdentity)
    }
}

#[cfg(target_os = "macos")]
fn designated_requirement(path: &Path) -> Result<String, UpdateError> {
    const MAX_CODESIGN_OUTPUT: usize = 16 * 1024;
    const MAX_REQUIREMENT: usize = 4 * 1024;

    let output = Command::new("/usr/bin/codesign")
        .args(["--display", "--requirements", "-"])
        .arg(path)
        .output()?;
    if !output.status.success() || output.stdout.len().saturating_add(output.stderr.len()) > MAX_CODESIGN_OUTPUT {
        return Err(UpdateError::IncompatibleCodeIdentity);
    }
    let mut requirement = None;
    for line in output_lines(&output)? {
        let line = line.trim();
        let line = line.strip_prefix("# ").unwrap_or(line);
        let Some(value) = line.strip_prefix("designated => ") else {
            continue;
        };
        if requirement.is_some()
            || value.is_empty()
            || value.len() > MAX_REQUIREMENT
            || !value.bytes().all(|byte| byte.is_ascii_graphic() || byte == b' ')
        {
            return Err(UpdateError::IncompatibleCodeIdentity);
        }
        requirement = Some(value.to_owned());
    }
    requirement.ok_or(UpdateError::IncompatibleCodeIdentity)
}

#[cfg(target_os = "macos")]
fn output_lines(output: &Output) -> Result<impl Iterator<Item = &str>, UpdateError> {
    let stdout = std::str::from_utf8(&output.stdout).map_err(|_| UpdateError::IncompatibleCodeIdentity)?;
    let stderr = std::str::from_utf8(&output.stderr).map_err(|_| UpdateError::IncompatibleCodeIdentity)?;
    Ok(stdout.lines().chain(stderr.lines()))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    use sha2::{Digest, Sha256};

    use super::{validate_compatible_identity, validate_staged};
    use crate::update::UpdateError;

    #[test]
    fn an_exact_copy_retains_the_approved_designated_requirement() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let authority = std::env::current_exe()?;
        let candidate = temporary.path().join("supgang");
        fs::copy(&authority, &candidate)?;
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))?;
        let digest = Sha256::digest(fs::read(&candidate)?);
        validate_staged(&candidate, &digest)?;
        validate_compatible_identity(&authority, &candidate)?;
        Ok(())
    }

    #[test]
    fn a_valid_signature_with_another_identity_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let authority = std::env::current_exe()?;
        let candidate = temporary.path().join("supgang");
        fs::copy(&authority, &candidate)?;
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))?;
        let status = Command::new("/usr/bin/codesign")
            .args([
                "--force",
                "--sign",
                "-",
                "--identifier",
                "org.agenxy.supgang.incompatible-test",
                "--timestamp=none",
            ])
            .arg(&candidate)
            .status()?;
        if !status.success() {
            return Err("codesign did not create the negative-test identity".into());
        }
        let digest = Sha256::digest(fs::read(&candidate)?);
        validate_staged(&candidate, &digest)?;
        assert!(matches!(
            validate_compatible_identity(&authority, &candidate),
            Err(UpdateError::IncompatibleCodeIdentity)
        ));
        Ok(())
    }
}
