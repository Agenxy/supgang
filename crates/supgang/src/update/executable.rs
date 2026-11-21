use std::path::Path;

#[cfg(target_os = "macos")]
use std::{
    io,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

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

/// The one owner-controlled identity change accepted by an explicit service
/// install or refresh. Background update paths keep using the strict check.
pub(super) fn validate_service_identity(authority: &Path, candidate: &Path) -> Result<bool, UpdateError> {
    validate_platform_signature(authority)?;
    validate_platform_signature(candidate)?;
    if validate_platform_identity(authority, candidate).is_ok() {
        return Ok(false);
    }
    #[cfg(target_os = "macos")]
    {
        let old = designated_requirement(authority)?;
        let new = designated_requirement(candidate)?;
        if !service_transition_requirements(&old, &new) {
            return Err(UpdateError::IncompatibleCodeIdentity);
        }
        validate_literal_requirement(candidate, OWNER_RUNTIME_REQUIREMENT)?;
        Ok(true)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(UpdateError::IncompatibleCodeIdentity)
    }
}

#[cfg(target_os = "macos")]
pub(super) const OWNER_RUNTIME_REQUIREMENT: &str =
    "identifier \"org.agenxy.supgang.runtime\" and certificate root = H\"cbf3bc78f05905fec061719f5065ffcd1349f938\"";

#[cfg(target_os = "macos")]
fn service_transition_requirements(old: &str, new: &str) -> bool {
    let Some(hex) = old.strip_prefix("cdhash H\"").and_then(|value| value.strip_suffix('"')) else {
        return false;
    };
    hex.len() == 40 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) && new == OWNER_RUNTIME_REQUIREMENT
}

/// Checks an installed native helper against the running Supgang certificate.
/// The two programs have different fixed identifiers but must have the same
/// remaining designated requirement and valid signatures.
#[cfg(target_os = "macos")]
pub fn validate_secure_enclave_helper(program: &Path, helper: &Path, deadline: Instant) -> Result<(), UpdateError> {
    validate_platform_signature_until(program, deadline)?;
    validate_platform_signature_until(helper, deadline)?;
    helper_requirement_matches(
        &designated_requirement_until(program, deadline)?,
        &designated_requirement_until(helper, deadline)?,
    )
}

#[cfg(target_os = "macos")]
fn helper_requirement_matches(program: &str, helper: &str) -> Result<(), UpdateError> {
    const PROGRAM: &str = "identifier \"org.agenxy.supgang.runtime\" and ";
    const HELPER: &str = "identifier \"org.agenxy.supgang.secure-enclave\" and ";
    let program_suffix = program
        .strip_prefix(PROGRAM)
        .ok_or(UpdateError::IncompatibleCodeIdentity)?;
    let helper_suffix = helper
        .strip_prefix(HELPER)
        .ok_or(UpdateError::IncompatibleCodeIdentity)?;
    if !program_suffix.is_empty() && program_suffix == helper_suffix {
        Ok(())
    } else {
        Err(UpdateError::IncompatibleCodeIdentity)
    }
}

// Off macOS there is no platform code signature to check, so these accept
// everything. They keep the `Result` shape of their macOS twins on purpose:
// the callers above are written once for both, and clippy's `const fn` and
// `unnecessary_wraps` advice would apply only to this half.
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_const_for_fn, clippy::unnecessary_wraps)]
fn validate_platform_signature(_path: &Path) -> Result<(), UpdateError> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_const_for_fn, clippy::unnecessary_wraps)]
fn validate_platform_identity(_authority: &Path, _candidate: &Path) -> Result<(), UpdateError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_platform_signature(path: &Path) -> Result<(), UpdateError> {
    validate_platform_signature_until(path, Instant::now() + Duration::from_secs(10))
}

#[cfg(target_os = "macos")]
fn validate_platform_signature_until(path: &Path, deadline: Instant) -> Result<(), UpdateError> {
    let mut command = Command::new("/usr/bin/codesign");
    command.args(["--verify", "--strict", "--verbose=2"]).arg(path);
    let output = bounded_output(&mut command, deadline)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(UpdateError::IncompatibleCodeIdentity)
    }
}

#[cfg(target_os = "macos")]
fn validate_platform_identity(authority: &Path, candidate: &Path) -> Result<(), UpdateError> {
    let requirement = designated_requirement(authority)?;
    validate_literal_requirement(candidate, &requirement)
}

#[cfg(target_os = "macos")]
fn validate_literal_requirement(candidate: &Path, requirement: &str) -> Result<(), UpdateError> {
    let literal_requirement = format!("={requirement}");
    let mut command = Command::new("/usr/bin/codesign");
    command
        .args(["--verify", "--strict", "--test-requirement"])
        .arg(&literal_requirement)
        .arg(candidate);
    let output = bounded_output(&mut command, Instant::now() + Duration::from_secs(10))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(UpdateError::IncompatibleCodeIdentity)
    }
}

#[cfg(target_os = "macos")]
pub(super) fn designated_requirement(path: &Path) -> Result<String, UpdateError> {
    designated_requirement_until(path, Instant::now() + Duration::from_secs(10))
}

#[cfg(target_os = "macos")]
fn designated_requirement_until(path: &Path, deadline: Instant) -> Result<String, UpdateError> {
    const MAX_REQUIREMENT: usize = 4 * 1024;

    let mut command = Command::new("/usr/bin/codesign");
    command.args(["--display", "--requirements", "-"]).arg(path);
    let output = bounded_output(&mut command, deadline)?;
    if !output.status.success() {
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
fn bounded_output(command: &mut Command, deadline: Instant) -> Result<Output, UpdateError> {
    const MAX_OUTPUT: usize = 16 * 1024;
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = Running(command.spawn()?);
    let mut stdout = child.0.stdout.take().ok_or(UpdateError::IncompatibleCodeIdentity)?;
    let mut stderr = child.0.stderr.take().ok_or(UpdateError::IncompatibleCodeIdentity)?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut out_eof = false;
    let mut err_eof = false;
    loop {
        let available = MAX_OUTPUT.saturating_sub(out.len() + err.len());
        read_bounded(&mut stdout, &mut out, &mut out_eof, available)?;
        let available = MAX_OUTPUT.saturating_sub(out.len() + err.len());
        read_bounded(&mut stderr, &mut err, &mut err_eof, available)?;
        if let Some(status) = child.0.try_wait()?
            && out_eof
            && err_eof
        {
            return Ok(Output {
                status,
                stdout: out,
                stderr: err,
            });
        }
        if Instant::now() >= deadline {
            return Err(UpdateError::IncompatibleCodeIdentity);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(target_os = "macos")]
fn nonblocking(fd: &impl std::os::fd::AsFd) -> Result<(), UpdateError> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(|_| UpdateError::IncompatibleCodeIdentity)?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(|_| UpdateError::IncompatibleCodeIdentity)
}

#[cfg(target_os = "macos")]
fn read_bounded(
    stream: &mut impl io::Read,
    data: &mut Vec<u8>,
    eof: &mut bool,
    available: usize,
) -> Result<(), UpdateError> {
    if *eof {
        return Ok(());
    }
    let mut buffer = [0_u8; 1024];
    match stream.read(&mut buffer) {
        Ok(0) => *eof = true,
        Ok(count) if count <= available => {
            data.extend_from_slice(buffer.get(..count).ok_or(UpdateError::IncompatibleCodeIdentity)?);
        }
        Ok(_) => return Err(UpdateError::IncompatibleCodeIdentity),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(UpdateError::Io(error)),
    }
    Ok(())
}

#[cfg(target_os = "macos")]
struct Running(Child);

#[cfg(target_os = "macos")]
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(target_os = "macos")]
fn output_lines(output: &Output) -> Result<impl Iterator<Item = &str>, UpdateError> {
    let stdout = std::str::from_utf8(&output.stdout).map_err(|_| UpdateError::IncompatibleCodeIdentity)?;
    let stderr = std::str::from_utf8(&output.stderr).map_err(|_| UpdateError::IncompatibleCodeIdentity)?;
    Ok(stdout.lines().chain(stderr.lines()))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        process::Command,
        time::{Duration, Instant},
    };

    use sha2::{Digest, Sha256};

    use super::{
        OWNER_RUNTIME_REQUIREMENT, bounded_output, helper_requirement_matches, service_transition_requirements,
        validate_compatible_identity, validate_service_identity, validate_staged,
    };
    use crate::update::UpdateError;

    #[test]
    fn native_helper_requires_its_fixed_identifier_and_the_same_signer() {
        let program = "identifier \"org.agenxy.supgang.runtime\" and certificate root = H\"001122\"";
        let helper = "identifier \"org.agenxy.supgang.secure-enclave\" and certificate root = H\"001122\"";
        assert!(helper_requirement_matches(program, helper).is_ok());
        assert!(helper_requirement_matches(program, &helper.replace("001122", "334455")).is_err());
        assert!(helper_requirement_matches(program, &helper.replace("secure-enclave", "other")).is_err());
        assert!(helper_requirement_matches("identifier \"other\" and certificate root = H\"001122\"", helper).is_err());
        assert!(helper_requirement_matches("identifier \"org.agenxy.supgang.runtime\" and ", helper).is_err());
    }

    #[test]
    fn code_signing_subprocesses_have_a_shared_time_and_output_bound() {
        let started = Instant::now();
        assert!(bounded_output(&mut Command::new("/usr/bin/yes"), started + Duration::from_secs(2)).is_err());
        assert!(started.elapsed() < Duration::from_secs(3));

        let started = Instant::now();
        let mut sleeping = Command::new("/bin/sleep");
        sleeping.arg("5");
        assert!(bounded_output(&mut sleeping, started + Duration::from_millis(50)).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

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

    #[test]
    fn service_identity_transition_accepts_only_ad_hoc_to_pinned_owner_certificate() {
        let ad_hoc_a = "cdhash H\"0000000000000000000000000000000000000001\"";
        let ad_hoc_b = "cdhash H\"0000000000000000000000000000000000000002\"";
        let cert_b = OWNER_RUNTIME_REQUIREMENT.replace("cbf3bc78", "00000000");
        assert!(service_transition_requirements(ad_hoc_a, OWNER_RUNTIME_REQUIREMENT));
        assert!(!service_transition_requirements(OWNER_RUNTIME_REQUIREMENT, ad_hoc_a));
        assert!(!service_transition_requirements(OWNER_RUNTIME_REQUIREMENT, &cert_b));
        assert!(!service_transition_requirements(ad_hoc_a, ad_hoc_b));
        assert!(!service_transition_requirements(
            "cdhash H\"short\"",
            OWNER_RUNTIME_REQUIREMENT
        ));
    }

    #[test]
    fn service_transition_rejects_a_tampered_candidate_signature() -> Result<(), Box<dyn std::error::Error>> {
        use std::io::{Read, Seek, SeekFrom, Write};

        let temporary = tempfile::tempdir()?;
        let authority = temporary.path().join("authority");
        let candidate = temporary.path().join("candidate");
        fs::copy(std::env::current_exe()?, &authority)?;
        fs::copy(&authority, &candidate)?;
        for path in [&authority, &candidate] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            let status = Command::new("/usr/bin/codesign")
                .args([
                    "--force",
                    "--sign",
                    "-",
                    "--identifier",
                    "org.agenxy.supgang.runtime",
                    "--timestamp=none",
                ])
                .arg(path)
                .status()?;
            if !status.success() {
                return Err("codesign did not create the test identity".into());
            }
        }
        let mut file = fs::OpenOptions::new().read(true).write(true).open(&candidate)?;
        file.seek(SeekFrom::Start(4096))?;
        let mut byte = [0];
        file.read_exact(&mut byte)?;
        file.seek(SeekFrom::Start(4096))?;
        file.write_all(&[byte[0] ^ 0xff])?;
        file.sync_all()?;
        assert!(matches!(
            validate_service_identity(&authority, &candidate),
            Err(UpdateError::IncompatibleCodeIdentity)
        ));
        Ok(())
    }
}
