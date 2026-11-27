//! Owner-present NC0 LMS ceremony commands.

use std::{
    fs::OpenOptions,
    io::{self, IsTerminal, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::ExitCode,
    time::Instant,
};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    cli::render_json,
    storage::{no_follow_flag, sync_directory},
    vault::{self, ReleaseLog, SecureEnclave},
};

#[derive(Serialize)]
struct PublicOutput {
    schema: &'static str,
    status: &'static str,
    name: String,
    public_key: String,
    fingerprint: String,
}

#[derive(Serialize)]
struct SignedOutput {
    schema: &'static str,
    status: &'static str,
    name: String,
    q: u32,
    fingerprint: String,
    message_sha256: String,
    signature_sha256: String,
}

#[derive(Serialize)]
struct AdvancedOutput {
    schema: &'static str,
    status: &'static str,
    name: String,
    next_q: u32,
    fingerprint: String,
}

pub(super) fn keygen(
    state_directory: &Path,
    name: &str,
    note: &str,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<ExitCode, String> {
    owner_terminal()?;
    let started = Instant::now();
    writeln!(error, "Generating NC0 LMS root {name}; computing 1,048,576 leaves.")
        .map_err(|_| "could not show key generation progress")?;
    let identity = vault::lms_keygen(state_directory, &SecureEnclave, name, note, |done, total| {
        if done % 65_536 == 0 || done == total {
            let _ = writeln!(error, "LMS tree: {done}/{total} leaves");
        }
    })
    .map_err(|problem| problem.to_string())?;
    writeln!(
        error,
        "LMS root generation took {:.1}s.",
        started.elapsed().as_secs_f64()
    )
    .map_err(|_| "could not show key generation timing")?;
    show_public(name, &identity, json, output)
}

pub(super) fn public_key(
    state_directory: &Path,
    name: &str,
    json: bool,
    output: &mut dyn Write,
) -> Result<ExitCode, String> {
    let identity =
        vault::lms_public_key(state_directory, &SecureEnclave, name).map_err(|problem| problem.to_string())?;
    show_public(name, &identity, json, output)
}

fn show_public(
    name: &str,
    identity: &vault::LmsPublic,
    json: bool,
    output: &mut dyn Write,
) -> Result<ExitCode, String> {
    let public_key = hex::encode(identity.public_key);
    if json {
        return Ok(render_json(
            &PublicOutput {
                schema: "supgang.nc0-lms-public-key/v1",
                status: "ok",
                name: name.to_owned(),
                public_key,
                fingerprint: identity.fingerprint.clone(),
            },
            output,
            &mut Vec::new(),
        ));
    }
    writeln!(
        output,
        "Public key: {public_key}\nFingerprint: {}",
        identity.fingerprint
    )
    .map_err(|_| "could not write the LMS public key".to_owned())?;
    Ok(ExitCode::SUCCESS)
}

#[expect(clippy::too_many_arguments, reason = "one owner ceremony with its streams")]
pub(super) fn sign(
    state_directory: &Path,
    name: &str,
    input: &Path,
    target: &Path,
    first_signature: bool,
    after_q: Option<u32>,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<ExitCode, String> {
    owner_terminal()?;
    if target.exists() {
        return Err("signed package output already exists".to_owned());
    }
    let release_log = match (first_signature, after_q) {
        (true, None) => ReleaseLog::FirstSignature,
        (false, Some(q)) => ReleaseLog::After(q),
        _ => return Err("choose exactly one release-log position".to_owned()),
    };
    let package = vault::lms_package(input).map_err(|problem| problem.to_string())?;
    let preview = vault::lms_preview(state_directory, &SecureEnclave, name, release_log)
        .map_err(|problem| problem.to_string())?;
    let digest = hex::encode(package.digest());
    writeln!(
        error,
        "NC0 LMS key: {name}\nq: {}\nSignatures remaining: {}\nPackage SHA-256: {digest}\nFingerprint: {}",
        preview.q, preview.remaining, preview.identity.fingerprint
    )
    .map_err(|_| "could not show the LMS signing preview")?;
    confirm(error, &format!("SIGN {}", preview.q))?;
    let started = Instant::now();
    let signed = vault::lms_sign(
        state_directory,
        &SecureEnclave,
        name,
        &package,
        release_log,
        preview.q,
        |done, total| {
            if done % 65_536 == 0 || done == total {
                let _ = writeln!(error, "LMS path: {done}/{total} leaves");
            }
        },
    )
    .map_err(|problem| problem.to_string())?;
    write_signed_package(input, target, &package, &signed.signature)?;
    writeln!(
        error,
        "LMS signing and output took {:.1}s.",
        started.elapsed().as_secs_f64()
    )
    .map_err(|_| "could not show LMS signing timing")?;
    let signature_sha256 = hex::encode(Sha256::digest(&signed.signature));
    if json {
        return Ok(render_json(
            &SignedOutput {
                schema: "supgang.nc0-lms-signed-package/v1",
                status: "ok",
                name: name.to_owned(),
                q: signed.q,
                fingerprint: signed.identity.fingerprint,
                message_sha256: digest,
                signature_sha256,
            },
            output,
            &mut Vec::new(),
        ));
    }
    writeln!(
        output,
        "Signed NC0 package with q {}.\nFingerprint: {}\nMessage SHA-256: {digest}\nSignature SHA-256: {signature_sha256}",
        signed.q, signed.identity.fingerprint
    )
    .map_err(|_| "could not report the signed package".to_owned())?;
    Ok(ExitCode::SUCCESS)
}

fn write_signed_package(
    input: &Path,
    target: &Path,
    package: &vault::Nc0Package,
    signature: &[u8],
) -> Result<(), String> {
    let mut source = std::fs::File::open(input).map_err(|_| "could not reopen unsigned package")?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(no_follow_flag().map_err(|_| "could not secure package output")?)
        .open(target)
        .map_err(|_| "could not create signed package output")?;
    let result = (|| {
        let mut hasher = Sha256::new();
        let mut remaining = package.bytes();
        let mut buffer = [0_u8; 8192];
        while remaining > 0 {
            let count = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| "package size invalid")?;
            let read = source
                .read(buffer.get_mut(..count).ok_or("package size invalid")?)
                .map_err(|_| "could not read unsigned package")?;
            if read == 0 {
                return Err("unsigned package changed before output".to_owned());
            }
            let bytes = buffer.get(..read).ok_or("package size invalid")?;
            hasher.update(bytes);
            destination
                .write_all(bytes)
                .map_err(|_| "could not write signed package")?;
            remaining -= read as u64;
        }
        if source
            .read(&mut [0_u8; 1])
            .map_err(|_| "could not check unsigned package")?
            != 0
            || hasher.finalize().as_slice() != package.digest()
        {
            return Err("unsigned package changed before output".to_owned());
        }
        destination
            .write_all(signature)
            .map_err(|_| "could not write LMS signature")?;
        destination.sync_all().map_err(|_| "could not sync signed package")?;
        let parent = target
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        sync_directory(parent).map_err(|_| "could not sync signed package directory")?;
        Ok(())
    })();
    if result.is_err() {
        drop(destination);
        let _ = std::fs::remove_file(target);
    }
    result
}

pub(super) fn advance(
    state_directory: &Path,
    name: &str,
    to_q: u32,
    after_q: u32,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<ExitCode, String> {
    owner_terminal()?;
    writeln!(
        error,
        "Burn LMS root {name} forward to q {to_q}; external release log says q {after_q}."
    )
    .map_err(|_| "could not show LMS advance preview")?;
    confirm(error, &format!("ADVANCE {to_q}"))?;
    let identity = vault::lms_advance(state_directory, &SecureEnclave, name, to_q, after_q)
        .map_err(|problem| problem.to_string())?;
    if json {
        return Ok(render_json(
            &AdvancedOutput {
                schema: "supgang.nc0-lms-advance/v1",
                status: "ok",
                name: name.to_owned(),
                next_q: to_q,
                fingerprint: identity.fingerprint,
            },
            output,
            &mut Vec::new(),
        ));
    }
    writeln!(
        output,
        "LMS root {name} advanced to q {to_q}.\nFingerprint: {}",
        identity.fingerprint
    )
    .map_err(|_| "could not report LMS advance")?;
    Ok(ExitCode::SUCCESS)
}

fn owner_terminal() -> Result<(), String> {
    if io::stdin().is_terminal() && io::stderr().is_terminal() {
        Ok(())
    } else {
        Err("NC0 LMS ceremonies require an interactive owner terminal".to_owned())
    }
}

fn confirm(error: &mut dyn Write, expected: &str) -> Result<(), String> {
    write!(error, "Type {expected} to continue: ").map_err(|_| "could not show confirmation prompt")?;
    error.flush().map_err(|_| "could not flush confirmation prompt")?;
    let mut line = Vec::with_capacity(32);
    let mut byte = [0_u8; 1];
    while line.len() < 32 {
        let count = io::stdin().read(&mut byte).map_err(|_| "could not read confirmation")?;
        if count == 0 {
            return Err("confirmation ended without a line".to_owned());
        }
        if byte[0] == b'\n' || byte[0] == b'\r' {
            return if line == expected.as_bytes() {
                Ok(())
            } else {
                Err("confirmation did not match; no LMS state changed".to_owned())
            };
        }
        line.push(byte[0]);
    }
    Err("confirmation was too long; no LMS state changed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_output_matches_validated_input_and_refuses_changed_source() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = crate::storage::test_tempdir()?;
        let input = temporary.path().join("unsigned.nc0");
        let output = temporary.path().join("signed.nc0");
        let mut header = [0_u8; 64];
        let words: [u32; 16] = [
            0x0400_006f,
            2,
            3,
            64,
            64 + 3 + 9_164,
            3,
            0,
            9_164,
            0,
            0,
            0,
            7,
            0,
            0,
            0,
            0,
        ];
        for (slot, word) in header.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            slot.copy_from_slice(&word.to_le_bytes());
        }
        let mut unsigned = header.to_vec();
        unsigned.extend_from_slice(b"app");
        std::fs::write(&input, &unsigned)?;
        let package = vault::lms_package(&input)?;
        let signature = vec![5_u8; 9_164];
        write_signed_package(&input, &output, &package, &signature)?;
        assert_eq!(std::fs::read(&output)?, [&unsigned[..], &signature[..]].concat());
        assert!(write_signed_package(&input, &output, &package, &signature).is_err());
        std::fs::remove_file(&output)?;
        unsigned.extend_from_slice(b"changed");
        std::fs::write(&input, unsigned)?;
        assert!(write_signed_package(&input, &output, &package, &signature).is_err());
        assert!(!output.exists());
        Ok(())
    }
}
