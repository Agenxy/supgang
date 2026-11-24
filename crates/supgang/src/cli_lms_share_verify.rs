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
    age_scrypt, artifact,
    cli::render_error,
    cli_lms_escrow::{hidden_passphrase, prepare_owner_terminal},
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

fn validate_share_paths(paths: &[PathBuf]) -> Result<(&Path, &Path), String> {
    if paths.len() != 2 {
        return Err("provide exactly two distinct --share files".to_owned());
    }
    let first = paths.first().ok_or("missing first share path")?;
    let second = paths.get(1).ok_or("missing second share path")?;
    let first_canon = fs::canonicalize(first).map_err(|_| format!("{}: share file unavailable", first.display()))?;
    let second_canon = fs::canonicalize(second).map_err(|_| format!("{}: share file unavailable", second.display()))?;
    if first_canon == second_canon {
        return Err("provide two distinct --share files from different media".to_owned());
    }
    Ok((first.as_path(), second.as_path()))
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
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<(), String> {
    prepare_owner_terminal()?;
    let role = RootRole::parse(role_arg).map_err(|problem| problem.to_string())?;
    let (first_path, second_path) = validate_share_paths(share_paths)?;

    let first_blob = Zeroizing::new(
        artifact::read(first_path, age_scrypt::MAX_FILE)
            .map_err(|_| format!("{}: could not read a bounded share file", first_path.display()))?,
    );
    let second_blob = Zeroizing::new(
        artifact::read(second_path, age_scrypt::MAX_FILE)
            .map_err(|_| format!("{}: could not read a bounded share file", second_path.display()))?,
    );
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
    writeln!(
        error,
        "Share verification took {:.1}s.",
        started.elapsed().as_secs_f64()
    )
    .map_err(|_| "could not show verification timing")?;

    render_output(role, &identity, &share_receipts, json, output)
}

pub fn run(role: &str, shares: &[PathBuf], json: bool, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    match verify(role, shares, json, output, error) {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => render_error(json, &problem, output, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_path_validation_requires_two_distinct_files() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let a = dir.path().join("a.share.age");
        let b = dir.path().join("b.share.age");
        let c = dir.path().join("c.share.age");
        fs::write(&a, b"1")?;
        fs::write(&b, b"2")?;
        fs::write(&c, b"3")?;
        assert!(validate_share_paths(&[a.clone(), b.clone()]).is_ok());
        assert!(validate_share_paths(std::slice::from_ref(&a)).is_err());
        assert!(validate_share_paths(&[a.clone(), b, c]).is_err());
        assert!(validate_share_paths(&[a.clone(), a]).is_err());
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

        // Wrong passphrase refuses.
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

        // Duplicate share refuses.
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

        // Mismatched root shares refuse.
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

        // Role separation: verifying same shares as recovery produces a different public key.
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
