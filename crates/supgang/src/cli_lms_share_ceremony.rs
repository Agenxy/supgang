//! Owner-present, network-free NC0 SLIP-39 2-of-3 product-root share ceremony.

use std::{
    collections::HashSet,
    fs,
    io::{self, Write},
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
    cli_lms_escrow::{clear_generated_display, hidden_passphrase, prepare_owner_terminal},
    eff_passphrase, offline_route, slip39,
    vault::{self, EscrowPublic, LmsPublic, MASTER_LEN, RootRole},
};

/// Encrypted share file name for `nc0-product-primary` on each medium.
pub const PRIMARY_SHARE_FILE: &str = "nc0-product-primary.share.age";
/// Encrypted share file name for `nc0-product-recovery` on each medium.
pub const RECOVERY_SHARE_FILE: &str = "nc0-product-recovery.share.age";

const MEDIA_LABELS: [&str; 3] = ["A", "B", "C"];
const VERIFY_PAIRS: [(usize, usize, &str); 3] = [(0, 1, "A+B"), (0, 2, "A+C"), (1, 2, "B+C")];
const ROLES: [RootRole; 2] = [RootRole::Primary, RootRole::Recovery];

#[derive(Serialize)]
struct CeremonyOutput<'a> {
    schema: &'static str,
    status: &'static str,
    roots: &'a [RootReceipt],
    files: &'a [ShareFileReceipt],
}

#[derive(Serialize)]
struct RootReceipt {
    role: &'static str,
    name: &'static str,
    public_key: String,
    lms_identifier: String,
    root_t1: String,
    fingerprint: String,
    known_answer_signature_sha256: String,
    next_q: u32,
    pairs_verified: [&'static str; 3],
}

#[derive(Serialize)]
struct ShareFileReceipt {
    medium: &'static str,
    role: &'static str,
    path: String,
    sha256: String,
}

type EncryptFn = fn(&[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str>;
type DecryptFn = fn(&[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str>;
type MediaBlobs = [[Zeroizing<Vec<u8>>; 2]; 3];

const fn share_file_name(role: RootRole) -> &'static str {
    match role {
        RootRole::Primary => PRIMARY_SHARE_FILE,
        RootRole::Recovery => RECOVERY_SHARE_FILE,
    }
}

fn validate_media_dirs(medium_a: &Path, medium_b: &Path, medium_c: &Path) -> Result<[PathBuf; 3], String> {
    let inputs = [medium_a, medium_b, medium_c];
    let mut seen = HashSet::with_capacity(3);
    for (dir, label) in inputs.iter().zip(MEDIA_LABELS) {
        let meta =
            fs::metadata(dir).map_err(|_| format!("medium {label} ({}): directory unavailable", dir.display()))?;
        if !meta.is_dir() {
            return Err(format!("medium {label} ({}): not a directory", dir.display()));
        }
        let canonical =
            fs::canonicalize(dir).map_err(|_| format!("medium {label} ({}): cannot canonicalize", dir.display()))?;
        if !seen.insert(canonical) {
            return Err(format!(
                "medium {label} ({}): duplicate medium directory",
                dir.display()
            ));
        }
        for role in ROLES {
            let target = dir.join(share_file_name(role));
            match fs::symlink_metadata(&target) {
                Ok(_) => return Err(format!("{}: already exists", target.display())),
                Err(problem) if problem.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err(format!("{}: cannot inspect destination", target.display())),
            }
        }
    }
    Ok([medium_a.to_path_buf(), medium_b.to_path_buf(), medium_c.to_path_buf()])
}

fn confirm_medium_passphrase(label: &str, error: &mut dyn Write) -> Result<Zeroizing<Vec<u8>>, String> {
    let generated = eff_passphrase::generate().map_err(str::to_owned)?;
    write!(
        error,
        "Medium {label} generated seven-word EFF passphrase (shown once): "
    )
    .map_err(|_| "could not show generated passphrase")?;
    error
        .write_all(&generated)
        .map_err(|_| "could not show generated passphrase")?;
    writeln!(error).map_err(|_| "could not finish generated passphrase display")?;
    let prompt = format!("Type the Medium {label} passphrase back (hidden): ");
    let typed = hidden_passphrase(&prompt, error);
    clear_generated_display(error)?;
    let typed = typed?;
    if generated.as_slice() != typed.as_slice() {
        return Err(format!(
            "Medium {label} typed passphrase differs; no share files were written"
        ));
    }
    Ok(generated)
}

fn write_encrypted_shares(
    media: &[PathBuf; 3],
    primary_shares: &[Zeroizing<String>; 3],
    recovery_shares: &[Zeroizing<String>; 3],
    passphrases: &[Zeroizing<Vec<u8>>; 3],
    encrypt: EncryptFn,
) -> Result<[[PathBuf; 2]; 3], String> {
    let mut paths: Vec<[PathBuf; 2]> = Vec::with_capacity(3);
    for medium_idx in 0..3 {
        let dir = media.get(medium_idx).ok_or("missing medium directory")?;
        let passphrase = passphrases.get(medium_idx).ok_or("missing medium passphrase")?;
        let primary_share = primary_shares.get(medium_idx).ok_or("missing primary share")?;
        let recovery_share = recovery_shares.get(medium_idx).ok_or("missing recovery share")?;

        let primary_path = dir.join(PRIMARY_SHARE_FILE);
        let mut primary_text = Zeroizing::new(format!("{}\n", primary_share.as_str()));
        let primary_ct = encrypt(primary_text.as_bytes(), passphrase).map_err(str::to_owned)?;
        primary_text.zeroize();
        artifact::write_new(&primary_path, &primary_ct, age_scrypt::MAX_FILE)
            .map_err(|problem| format!("{}: {problem}", primary_path.display()))?;

        let recovery_path = dir.join(RECOVERY_SHARE_FILE);
        let mut recovery_text = Zeroizing::new(format!("{}\n", recovery_share.as_str()));
        let recovery_ct = encrypt(recovery_text.as_bytes(), passphrase).map_err(str::to_owned)?;
        recovery_text.zeroize();
        artifact::write_new(&recovery_path, &recovery_ct, age_scrypt::MAX_FILE)
            .map_err(|problem| format!("{}: {problem}", recovery_path.display()))?;

        paths.push([primary_path, recovery_path]);
    }
    paths.try_into().map_err(|_| "internal media path error".to_owned())
}

fn read_all_files(paths: &[[PathBuf; 2]; 3]) -> Result<(MediaBlobs, Vec<ShareFileReceipt>), String> {
    let mut blobs: Vec<[Zeroizing<Vec<u8>>; 2]> = Vec::with_capacity(3);
    let mut receipts = Vec::with_capacity(6);
    for (medium_idx, pair) in paths.iter().enumerate() {
        let label = *MEDIA_LABELS.get(medium_idx).ok_or("missing medium label")?;
        let primary_path = pair.first().ok_or("missing primary path")?;
        let recovery_path = pair.get(1).ok_or("missing recovery path")?;

        let primary_bytes = Zeroizing::new(
            artifact::read(primary_path, age_scrypt::MAX_FILE)
                .map_err(|problem| format!("{}: {problem}", primary_path.display()))?,
        );
        receipts.push(ShareFileReceipt {
            medium: label,
            role: RootRole::Primary.as_str(),
            path: primary_path.display().to_string(),
            sha256: hex::encode(Sha256::digest(primary_bytes.as_slice())),
        });

        let recovery_bytes = Zeroizing::new(
            artifact::read(recovery_path, age_scrypt::MAX_FILE)
                .map_err(|problem| format!("{}: {problem}", recovery_path.display()))?,
        );
        receipts.push(ShareFileReceipt {
            medium: label,
            role: RootRole::Recovery.as_str(),
            path: recovery_path.display().to_string(),
            sha256: hex::encode(Sha256::digest(recovery_bytes.as_slice())),
        });

        blobs.push([primary_bytes, recovery_bytes]);
    }
    let blobs: [[Zeroizing<Vec<u8>>; 2]; 3] = blobs.try_into().map_err(|_| "internal blob count error".to_owned())?;
    Ok((blobs, receipts))
}

fn decrypt_mnemonic(ciphertext: &[u8], passphrase: &[u8], decrypt: DecryptFn) -> Result<Zeroizing<String>, String> {
    let raw = decrypt(ciphertext, passphrase).map_err(str::to_owned)?;
    let text = String::from_utf8(raw.to_vec()).map_err(|_| "decrypted share is not valid UTF-8".to_owned())?;
    Ok(Zeroizing::new(text))
}

fn verify_all_pairs<F>(
    blobs: &MediaBlobs,
    verify_passphrases: &[Zeroizing<Vec<u8>>; 3],
    expected_roots: &[&LmsPublic; 2],
    decrypt: DecryptFn,
    mut derive_public: F,
    error: &mut dyn Write,
) -> Result<(), String>
where
    F: FnMut(&[u8], RootRole, &str, &mut dyn Write) -> Result<LmsPublic, String>,
{
    for (left_idx, right_idx, pair_label) in VERIFY_PAIRS {
        let left_pass = verify_passphrases.get(left_idx).ok_or("missing left passphrase")?;
        let right_pass = verify_passphrases.get(right_idx).ok_or("missing right passphrase")?;
        let left_media = blobs.get(left_idx).ok_or("missing left media blobs")?;
        let right_media = blobs.get(right_idx).ok_or("missing right media blobs")?;

        for (role_idx, &role) in ROLES.iter().enumerate() {
            let left_blob = left_media.get(role_idx).ok_or("missing left share blob")?;
            let right_blob = right_media.get(role_idx).ok_or("missing right share blob")?;
            let left_mnemonic = decrypt_mnemonic(left_blob, left_pass, decrypt)
                .map_err(|err| format!("pair {pair_label} ({}) left share: {err}", role.as_str()))?;
            let right_mnemonic = decrypt_mnemonic(right_blob, right_pass, decrypt)
                .map_err(|err| format!("pair {pair_label} ({}) right share: {err}", role.as_str()))?;

            let mut recovered = slip39::combine_mnemonics(&[left_mnemonic.as_str(), right_mnemonic.as_str()], b"")
                .map_err(|err| format!("pair {pair_label} ({}): {err}", role.as_str()))?;
            drop(left_mnemonic);
            drop(right_mnemonic);
            if recovered.len() != MASTER_LEN {
                recovered.zeroize();
                return Err(format!(
                    "pair {pair_label} ({}): recovered master is not 32 bytes",
                    role.as_str()
                ));
            }
            let rebuilt = derive_public(recovered.as_slice(), role, pair_label, error)?;
            recovered.zeroize();
            drop(recovered);

            let expected = *expected_roots.get(role_idx).ok_or("missing expected root")?;
            if rebuilt != *expected {
                return Err(format!(
                    "pair {pair_label} ({}): rebuilt public key does not match generated root",
                    role.as_str()
                ));
            }
        }
    }
    Ok(())
}

fn build_root_receipt(role: RootRole, escrow: &EscrowPublic) -> Result<RootReceipt, String> {
    let public_key = hex::encode(escrow.identity.public_key);
    let lms_identifier = hex::encode(escrow.identity.public_key.get(8..24).ok_or("short LMS public key")?);
    let root_t1 = hex::encode(escrow.identity.public_key.get(24..56).ok_or("short LMS public key")?);
    Ok(RootReceipt {
        role: role.as_str(),
        name: role.root_name(),
        public_key,
        lms_identifier,
        root_t1,
        fingerprint: escrow.identity.fingerprint.clone(),
        known_answer_signature_sha256: escrow.signature_sha256.clone(),
        next_q: escrow.next_q,
        pairs_verified: ["A+B", "A+C", "B+C"],
    })
}

fn render_output(
    roots: &[RootReceipt],
    files: &[ShareFileReceipt],
    json: bool,
    output: &mut dyn Write,
) -> Result<(), String> {
    if json {
        let response = CeremonyOutput {
            schema: "supgang.nc0-lms-share-ceremony/v1",
            status: "ok",
            roots,
            files,
        };
        serde_json::to_writer(&mut *output, &response).map_err(|_| "could not write JSON result")?;
        writeln!(output).map_err(|_| "could not finish JSON result")?;
    } else {
        for root in roots {
            writeln!(
                output,
                "Root: {} (role {})\nPublic key: {}\nLMS I: {}\nRoot T[1]: {}\nFingerprint: {}\nKnown-answer signature SHA-256: {}\nNext q: {}\nVerified pairs: {}",
                root.name,
                root.role,
                root.public_key,
                root.lms_identifier,
                root.root_t1,
                root.fingerprint,
                root.known_answer_signature_sha256,
                root.next_q,
                root.pairs_verified.join(", ")
            )
            .map_err(|_| "could not write public receipt")?;
        }
        for file in files {
            writeln!(
                output,
                "Share file SHA-256 [Medium {} {}]: {}  {}",
                file.medium, file.role, file.sha256, file.path
            )
            .map_err(|_| "could not write share file digest")?;
        }
    }
    Ok(())
}

fn ceremony(
    medium_a: &Path,
    medium_b: &Path,
    medium_c: &Path,
    i_confirm_offline: bool,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<(), String> {
    prepare_owner_terminal()?;
    let media = validate_media_dirs(medium_a, medium_b, medium_c)?;
    if i_confirm_offline {
        writeln!(
            error,
            "WARNING: test-only offline override; a default route may be present."
        )
        .map_err(|_| "could not show offline override warning")?;
    } else if offline_route::has_default_route()? {
        return Err("default route is present; disconnect network before generating NC0 LMS roots".to_owned());
    }

    let mut primary_master = Zeroizing::new([0_u8; MASTER_LEN]);
    let mut recovery_master = Zeroizing::new([0_u8; MASTER_LEN]);
    getrandom::fill(primary_master.as_mut()).map_err(|_| "could not obtain operating-system randomness")?;
    getrandom::fill(recovery_master.as_mut()).map_err(|_| "could not obtain operating-system randomness")?;

    let started = Instant::now();
    writeln!(
        error,
        "Generating {} (role primary); computing 1,048,576 leaves.",
        RootRole::Primary.root_name()
    )
    .map_err(|_| "could not show LMS progress")?;
    let primary_public = vault::derive_lms_known_answer(primary_master.as_ref(), RootRole::Primary, |done, total| {
        if done % 65_536 == 0 || done == total {
            let _ = writeln!(error, "Primary LMS tree: {done}/{total}");
        }
    })
    .map_err(|problem| problem.to_string())?;

    writeln!(
        error,
        "Generating {} (role recovery); computing 1,048,576 leaves.",
        RootRole::Recovery.root_name()
    )
    .map_err(|_| "could not show LMS progress")?;
    let recovery_public =
        vault::derive_lms_known_answer(recovery_master.as_ref(), RootRole::Recovery, |done, total| {
            if done % 65_536 == 0 || done == total {
                let _ = writeln!(error, "Recovery LMS tree: {done}/{total}");
            }
        })
        .map_err(|problem| problem.to_string())?;
    writeln!(
        error,
        "Both NC0 roots and q=0 known-answer signatures took {:.1}s.",
        started.elapsed().as_secs_f64()
    )
    .map_err(|_| "could not show LMS timing")?;

    let primary_shares = slip39::split_2_of_3(primary_master.as_ref()).map_err(|err| err.to_string())?;
    let recovery_shares = slip39::split_2_of_3(recovery_master.as_ref()).map_err(|err| err.to_string())?;

    // Wipe both masters before writing or verification.
    primary_master.zeroize();
    recovery_master.zeroize();
    drop(primary_master);
    drop(recovery_master);

    let pass_a = confirm_medium_passphrase("A", error)?;
    let pass_b = confirm_medium_passphrase("B", error)?;
    let pass_c = confirm_medium_passphrase("C", error)?;
    let passphrases = [pass_a, pass_b, pass_c];

    let paths = write_encrypted_shares(
        &media,
        &primary_shares,
        &recovery_shares,
        &passphrases,
        age_scrypt::encrypt,
    )?;
    drop(primary_shares);
    drop(recovery_shares);
    drop(passphrases);

    let verify_a = hidden_passphrase("Re-enter Medium A passphrase to verify (hidden): ", error)?;
    let verify_b = hidden_passphrase("Re-enter Medium B passphrase to verify (hidden): ", error)?;
    let verify_c = hidden_passphrase("Re-enter Medium C passphrase to verify (hidden): ", error)?;
    let verify_passphrases = [verify_a, verify_b, verify_c];

    let (blobs, file_receipts) = read_all_files(&paths)?;
    let verify_started = Instant::now();
    verify_all_pairs(
        &blobs,
        &verify_passphrases,
        &[&primary_public.identity, &recovery_public.identity],
        age_scrypt::decrypt,
        |master, role, pair_label, err_out| {
            vault::derive_lms_public(master, role, |done, total| {
                if done % 65_536 == 0 || done == total {
                    let _ = writeln!(err_out, "Verify {pair_label} ({}): {done}/{total}", role.as_str());
                }
            })
            .map_err(|problem| problem.to_string())
        },
        error,
    )?;
    drop(verify_passphrases);
    writeln!(
        error,
        "All 6 pair/root rebuild verifications passed in {:.1}s.",
        verify_started.elapsed().as_secs_f64()
    )
    .map_err(|_| "could not show verification timing")?;

    let roots = [
        build_root_receipt(RootRole::Primary, &primary_public)?,
        build_root_receipt(RootRole::Recovery, &recovery_public)?,
    ];
    render_output(&roots, &file_receipts, json, output)
}

pub fn run(
    medium_a: &Path,
    medium_b: &Path,
    medium_c: &Path,
    i_confirm_offline: bool,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    match ceremony(medium_a, medium_b, medium_c, i_confirm_offline, json, output, error) {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => render_error(json, &problem, output, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_validation_requires_three_distinct_directories_without_existing_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir_a = tempfile::tempdir()?;
        let dir_b = tempfile::tempdir()?;
        let dir_c = tempfile::tempdir()?;
        assert!(validate_media_dirs(dir_a.path(), dir_b.path(), dir_c.path()).is_ok());
        assert!(validate_media_dirs(dir_a.path(), dir_a.path(), dir_c.path()).is_err());
        assert!(validate_media_dirs(dir_a.path(), dir_b.path(), dir_b.path()).is_err());

        let existing = dir_b.path().join(RECOVERY_SHARE_FILE);
        fs::write(&existing, b"already-here")?;
        assert!(validate_media_dirs(dir_a.path(), dir_b.path(), dir_c.path()).is_err());
        Ok(())
    }

    #[test]
    fn six_file_write_wipe_and_all_three_pair_rebuilds_verify_and_detect_tampering()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir_a = tempfile::tempdir()?;
        let dir_b = tempfile::tempdir()?;
        let dir_c = tempfile::tempdir()?;
        let media = validate_media_dirs(dir_a.path(), dir_b.path(), dir_c.path())?;

        let mut primary_master = Zeroizing::new([0x11_u8; MASTER_LEN]);
        let mut recovery_master = Zeroizing::new([0x22_u8; MASTER_LEN]);
        let expected_primary = vault::derive_public_h5_for_test(primary_master.as_ref(), RootRole::Primary)?;
        let expected_recovery = vault::derive_public_h5_for_test(recovery_master.as_ref(), RootRole::Recovery)?;

        let primary_shares = slip39::split_2_of_3(primary_master.as_ref())?;
        let recovery_shares = slip39::split_2_of_3(recovery_master.as_ref())?;
        primary_master.zeroize();
        recovery_master.zeroize();
        drop(primary_master);
        drop(recovery_master);

        let passphrases = [
            Zeroizing::new(b"alpha bravo charlie delta echo foxtrot golf".to_vec()),
            Zeroizing::new(b"hotel india juliet kilo lima mike november".to_vec()),
            Zeroizing::new(b"oscar papa quebec romeo sierra tango uniform".to_vec()),
        ];

        let paths = write_encrypted_shares(
            &media,
            &primary_shares,
            &recovery_shares,
            &passphrases,
            age_scrypt::encrypt_test_factor18,
        )?;
        let (blobs, receipts) = read_all_files(&paths)?;
        assert_eq!(receipts.len(), 6);

        let mut stderr = Vec::new();
        verify_all_pairs(
            &blobs,
            &passphrases,
            &[&expected_primary, &expected_recovery],
            age_scrypt::decrypt,
            |master, role, _, _| vault::derive_public_h5_for_test(master, role).map_err(|err| err.to_string()),
            &mut stderr,
        )?;

        // Wrong passphrase on Medium B must fail.
        let mut bad_passes = passphrases.clone();
        *bad_passes.get_mut(1).ok_or("missing pass B")? = Zeroizing::new(b"wrong passphrase".to_vec());
        assert!(
            verify_all_pairs(
                &blobs,
                &bad_passes,
                &[&expected_primary, &expected_recovery],
                age_scrypt::decrypt,
                |master, role, _, _| vault::derive_public_h5_for_test(master, role).map_err(|err| err.to_string()),
                &mut stderr,
            )
            .is_err()
        );

        // Swapped/tampered expected public key must fail.
        let mut wrong_primary = expected_primary.clone();
        *wrong_primary.public_key.last_mut().ok_or("short key")? ^= 1;
        assert!(
            verify_all_pairs(
                &blobs,
                &passphrases,
                &[&wrong_primary, &expected_recovery],
                age_scrypt::decrypt,
                |master, role, _, _| vault::derive_public_h5_for_test(master, role).map_err(|err| err.to_string()),
                &mut stderr,
            )
            .is_err()
        );

        // Tampered ciphertext byte on Medium C must fail.
        let mut tampered_blobs = blobs;
        let last = tampered_blobs
            .get_mut(2)
            .and_then(|pair| pair.get_mut(1))
            .and_then(|blob| blob.last_mut())
            .ok_or("missing blob")?;
        *last ^= 1;
        assert!(
            verify_all_pairs(
                &tampered_blobs,
                &passphrases,
                &[&expected_primary, &expected_recovery],
                age_scrypt::decrypt,
                |master, role, _, _| vault::derive_public_h5_for_test(master, role).map_err(|err| err.to_string()),
                &mut stderr,
            )
            .is_err()
        );
        Ok(())
    }
}
