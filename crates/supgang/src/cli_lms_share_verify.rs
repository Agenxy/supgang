//! Read-only verification of two age-encrypted SLIP-39 NC0 share files.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    age_scrypt,
    cli::render_error,
    cli_lms_escrow::{hidden_passphrase, prepare_owner_terminal},
    cli_lms_share_ceremony::media,
    slip39,
    vault::{self, LmsPublic, MASTER_LEN, RootRole},
};

#[derive(Serialize)]
struct VerifyOutput<'a> {
    schema: &'static str,
    status: &'static str,
    role: &'static str,
    name: &'static str,
    public_key: String,
    lms_identifier: String,
    root_t1: String,
    fingerprint: &'a str,
    shares: &'a [VerifiedShareReceipt],
}

#[derive(Serialize)]
struct VerifiedShareReceipt {
    path: String,
    sha256: String,
}

type DecryptFn = fn(&[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str>;

fn validate_expected_fingerprint(expected: &str) -> Result<&str, String> {
    if expected.len() == 64
        && expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(expected)
    } else {
        Err("--expect-fingerprint must be exactly 64 lowercase hexadecimal characters".to_owned())
    }
}

fn check_share_filename(role: RootRole, path: &Path) -> Result<(), String> {
    if media::is_appledouble_path(path) {
        return Err(format!(
            "{}: AppleDouble metadata file (._*) is not a share file",
            path.display()
        ));
    }
    let other_role = match role {
        RootRole::Primary => RootRole::Recovery.as_str(),
        RootRole::Recovery => RootRole::Primary.as_str(),
    };
    if let Some(name) = path.file_name().and_then(|value| value.to_str())
        && name.to_ascii_lowercase().contains(other_role)
    {
        return Err(format!(
            "{}: share filename names role {other_role}, but verifying role {}",
            path.display(),
            role.as_str()
        ));
    }
    Ok(())
}

fn validate_share_paths(role: RootRole, paths: &[PathBuf]) -> Result<(&Path, &Path), String> {
    if paths.len() != 2 {
        return Err("provide exactly two distinct --share files".to_owned());
    }
    let first = paths.first().ok_or("missing first share path")?;
    let second = paths.get(1).ok_or("missing second share path")?;
    check_share_filename(role, first)?;
    check_share_filename(role, second)?;
    let first_canon = fs::canonicalize(first).map_err(|_| format!("{}: share file unavailable", first.display()))?;
    let second_canon = fs::canonicalize(second).map_err(|_| format!("{}: share file unavailable", second.display()))?;
    if first_canon == second_canon {
        return Err("provide two distinct --share files from different media".to_owned());
    }
    Ok((first.as_path(), second.as_path()))
}

fn verify_expected_fingerprint(role: RootRole, identity: &LmsPublic, expected: Option<&str>) -> Result<(), String> {
    if let Some(expected_hex) = expected
        && identity.fingerprint != expected_hex
    {
        return Err(format!(
            "derived {} fingerprint {} does not match expected fingerprint {expected_hex}",
            role.as_str(),
            identity.fingerprint
        ));
    }
    Ok(())
}

fn decrypt_reason(problem: &str) -> &'static str {
    match problem {
        "age passphrase or file authentication failed" => "bad passphrase or share file authentication",
        "age header authentication failed" | "age payload authentication failed" => "share file authentication failed",
        _ => "malformed or unsupported share file",
    }
}

fn recombine_and_derive<F>(
    role: RootRole,
    first_blob: &[u8],
    first_pass: &[u8],
    second_blob: &[u8],
    second_pass: &[u8],
    decrypt: DecryptFn,
    derive_public: F,
) -> Result<LmsPublic, String>
where
    F: FnOnce(&[u8], RootRole) -> Result<LmsPublic, String>,
{
    let first_raw = decrypt(first_blob, first_pass).map_err(|problem| decrypt_reason(problem).to_owned())?;
    let second_raw = decrypt(second_blob, second_pass).map_err(|problem| decrypt_reason(problem).to_owned())?;

    let first_mnemonic =
        Zeroizing::new(String::from_utf8(first_raw.to_vec()).map_err(|_| "share 1 is not valid UTF-8".to_owned())?);
    let second_mnemonic =
        Zeroizing::new(String::from_utf8(second_raw.to_vec()).map_err(|_| "share 2 is not valid UTF-8".to_owned())?);
    drop(first_raw);
    drop(second_raw);

    let mut master = slip39::combine_mnemonics(&[first_mnemonic.as_str(), second_mnemonic.as_str()], b"")
        .map_err(|err| err.to_string())?;
    drop(first_mnemonic);
    drop(second_mnemonic);
    if master.len() != MASTER_LEN {
        master.zeroize();
        return Err("recombined SLIP-39 master secret is not 32 bytes".to_owned());
    }
    let identity = derive_public(master.as_slice(), role)?;
    master.zeroize();
    Ok(identity)
}

fn render_output(
    role: RootRole,
    identity: &LmsPublic,
    shares: &[VerifiedShareReceipt],
    json: bool,
    output: &mut dyn Write,
) -> Result<(), String> {
    let public_key = hex::encode(identity.public_key);
    let lms_identifier = hex::encode(identity.public_key.get(8..24).ok_or("short LMS public key")?);
    let root_t1 = hex::encode(identity.public_key.get(24..56).ok_or("short LMS public key")?);
    if json {
        let response = VerifyOutput {
            schema: "supgang.nc0-lms-share-verify/v1",
            status: "ok",
            role: role.as_str(),
            name: role.root_name(),
            public_key,
            lms_identifier,
            root_t1,
            fingerprint: &identity.fingerprint,
            shares,
        };
        serde_json::to_writer(&mut *output, &response).map_err(|_| "could not write JSON result")?;
        writeln!(output).map_err(|_| "could not finish JSON result")?;
    } else {
        writeln!(
            output,
            "Role: {}\nName: {}\nPublic key: {public_key}\nLMS I: {lms_identifier}\nRoot T[1]: {root_t1}\nFingerprint: {}",
            role.as_str(),
            role.root_name(),
            identity.fingerprint
        )
        .map_err(|_| "could not write public receipt")?;
        for share in shares {
            writeln!(output, "Share file SHA-256: {}  {}", share.sha256, share.path)
                .map_err(|_| "could not write share file digest")?;
        }
    }
    Ok(())
}

fn verify(
    role_arg: &str,
    share_paths: &[PathBuf],
    expect_fingerprint: Option<&str>,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<(), String> {
    prepare_owner_terminal()?;
    let role = RootRole::parse(role_arg).map_err(|problem| problem.to_string())?;
    let expected = expect_fingerprint.map(validate_expected_fingerprint).transpose()?;
    let (first_path, second_path) = validate_share_paths(role, share_paths)?;

    let first_blob = Zeroizing::new(media::read_share_file(first_path, age_scrypt::MAX_FILE)?);
    let second_blob = Zeroizing::new(media::read_share_file(second_path, age_scrypt::MAX_FILE)?);
    let share_receipts = [
        VerifiedShareReceipt {
            path: first_path.display().to_string(),
            sha256: hex::encode(Sha256::digest(first_blob.as_slice())),
        },
        VerifiedShareReceipt {
            path: second_path.display().to_string(),
            sha256: hex::encode(Sha256::digest(second_blob.as_slice())),
        },
    ];

    let prompt_1 = format!("Passphrase for share 1 ({}) (hidden): ", first_path.display());
    let first_pass = hidden_passphrase(&prompt_1, error)?;
    let prompt_2 = format!("Passphrase for share 2 ({}) (hidden): ", second_path.display());
    let second_pass = hidden_passphrase(&prompt_2, error)?;

    writeln!(
        error,
        "Recombining shares and verifying {} (role {}); computing 1,048,576 leaves.",
        role.root_name(),
        role.as_str()
    )
    .map_err(|_| "could not show LMS progress")?;
    let started = Instant::now();
    let identity = recombine_and_derive(
        role,
        &first_blob,
        &first_pass,
        &second_blob,
        &second_pass,
        age_scrypt::decrypt,
        |master, root_role| {
            vault::derive_lms_public(master, root_role, |done, total| {
                if done % 65_536 == 0 || done == total {
                    let _ = writeln!(error, "Verify {}: {done}/{total}", root_role.as_str());
                }
            })
            .map_err(|problem| problem.to_string())
        },
    )?;
    drop(first_pass);
    drop(second_pass);
    verify_expected_fingerprint(role, &identity, expected)?;
    writeln!(
        error,
        "Share verification took {:.1}s.",
        started.elapsed().as_secs_f64()
    )
    .map_err(|_| "could not show verification timing")?;

    render_output(role, &identity, &share_receipts, json, output)
}

pub fn run(
    role: &str,
    shares: &[PathBuf],
    expect_fingerprint: Option<&str>,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    match verify(role, shares, expect_fingerprint, json, output, error) {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => render_error(json, &problem, output, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_path_validation_requires_two_distinct_files_and_refuses_cross_role_names()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = crate::storage::test_tempdir()?;
        let a = dir.path().join("a.share.age");
        let b = dir.path().join("b.share.age");
        let c = dir.path().join("c.share.age");
        let primary_file = dir.path().join("nc0-product-primary.share.age");
        let recovery_file = dir.path().join("nc0-product-recovery.share.age");
        let appledouble = dir.path().join("._nc0-product-primary.share.age");
        for path in [&a, &b, &c, &primary_file, &recovery_file, &appledouble] {
            fs::write(path, b"1")?;
        }
        assert!(validate_share_paths(RootRole::Primary, &[a.clone(), b.clone()]).is_ok());
        assert!(validate_share_paths(RootRole::Primary, &[primary_file.clone(), b.clone()]).is_ok());
        assert!(validate_share_paths(RootRole::Recovery, &[recovery_file.clone(), b.clone()]).is_ok());
        assert!(validate_share_paths(RootRole::Primary, std::slice::from_ref(&a)).is_err());
        assert!(validate_share_paths(RootRole::Primary, &[a.clone(), b.clone(), c]).is_err());
        assert!(validate_share_paths(RootRole::Primary, &[a.clone(), a]).is_err());

        // Opposite-role filenames must be refused before prompting.
        let err = validate_share_paths(RootRole::Recovery, &[primary_file, b.clone()])
            .err()
            .ok_or("expected primary filename under recovery role to fail")?;
        assert!(err.contains("names role primary"));
        let err = validate_share_paths(RootRole::Primary, &[b.clone(), recovery_file])
            .err()
            .ok_or("expected recovery filename under primary role to fail")?;
        assert!(err.contains("names role recovery"));

        // AppleDouble `._*` files must be refused.
        assert!(validate_share_paths(RootRole::Primary, &[appledouble, b]).is_err());
        Ok(())
    }

    #[test]
    fn expected_fingerprint_validation_and_comparison_enforce_exact_match() -> Result<(), Box<dyn std::error::Error>> {
        let master = [0x33_u8; MASTER_LEN];
        let identity = vault::derive_public_h5_for_test(&master, RootRole::Primary)?;
        let expected = identity.fingerprint.as_str();

        assert_eq!(validate_expected_fingerprint(expected)?, expected);
        assert!(validate_expected_fingerprint("short").is_err());
        assert!(validate_expected_fingerprint(&expected.to_ascii_uppercase()).is_err());
        assert!(validate_expected_fingerprint(&"g".repeat(64)).is_err());

        verify_expected_fingerprint(RootRole::Primary, &identity, None)?;
        verify_expected_fingerprint(RootRole::Primary, &identity, Some(expected))?;
        let wrong = "0".repeat(64);
        let err = verify_expected_fingerprint(RootRole::Primary, &identity, Some(&wrong))
            .err()
            .ok_or("expected fingerprint mismatch error")?;
        assert!(err.contains("does not match expected fingerprint"));
        Ok(())
    }

    #[test]
    fn recombine_and_derive_verifies_valid_shares_and_refuses_faults() -> Result<(), Box<dyn std::error::Error>> {
        let master = [0x33_u8; MASTER_LEN];
        let other_master = [0x44_u8; MASTER_LEN];
        let expected = vault::derive_public_h5_for_test(&master, RootRole::Primary)?;
        let shares = slip39::split_2_of_3(&master)?;
        let other_shares = slip39::split_2_of_3(&other_master)?;

        let pass_1 = b"alpha bravo charlie delta echo foxtrot golf";
        let pass_2 = b"hotel india juliet kilo lima mike november";
        let s0 = shares.first().ok_or("missing share 0")?;
        let s1 = shares.get(1).ok_or("missing share 1")?;
        let o1 = other_shares.get(1).ok_or("missing other share 1")?;
        let blob_1 = age_scrypt::encrypt_test_factor18(format!("{}\n", s0.as_str()).as_bytes(), pass_1)?;
        let blob_2 = age_scrypt::encrypt_test_factor18(format!("{}\n", s1.as_str()).as_bytes(), pass_2)?;
        let blob_other = age_scrypt::encrypt_test_factor18(format!("{}\n", o1.as_str()).as_bytes(), pass_2)?;

        let derived = recombine_and_derive(
            RootRole::Primary,
            &blob_1,
            pass_1,
            &blob_2,
            pass_2,
            age_scrypt::decrypt,
            |m, r| vault::derive_public_h5_for_test(m, r).map_err(|err| err.to_string()),
        )?;
        assert_eq!(derived, expected);

        assert!(
            recombine_and_derive(
                RootRole::Primary,
                &blob_1,
                b"wrong",
                &blob_2,
                pass_2,
                age_scrypt::decrypt,
                |m, r| vault::derive_public_h5_for_test(m, r).map_err(|err| err.to_string()),
            )
            .is_err()
        );

        assert!(
            recombine_and_derive(
                RootRole::Primary,
                &blob_1,
                pass_1,
                &blob_1,
                pass_1,
                age_scrypt::decrypt,
                |m, r| vault::derive_public_h5_for_test(m, r).map_err(|err| err.to_string()),
            )
            .is_err()
        );

        assert!(
            recombine_and_derive(
                RootRole::Primary,
                &blob_1,
                pass_1,
                &blob_other,
                pass_2,
                age_scrypt::decrypt,
                |m, r| vault::derive_public_h5_for_test(m, r).map_err(|err| err.to_string()),
            )
            .is_err()
        );

        let as_recovery = recombine_and_derive(
            RootRole::Recovery,
            &blob_1,
            pass_1,
            &blob_2,
            pass_2,
            age_scrypt::decrypt,
            |m, r| vault::derive_public_h5_for_test(m, r).map_err(|err| err.to_string()),
        )?;
        assert_ne!(as_recovery, expected);
        Ok(())
    }
}
