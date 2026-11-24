//! Owner-present, network-free NC0 SLIP-39 2-of-3 product-root share ceremony.

pub mod media;
#[cfg(test)]
mod tests;

use std::{
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
const MAX_CONFIRM_ATTEMPTS: usize = 3;
const MAX_VERIFY_ATTEMPTS: usize = 3;
const VERIFY_ABORT_MESSAGE: &str = "files are written; verify them with lms-share-verify; do not rerun on these media";

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

fn confirm_medium_passphrase_with<F>(
    label: &str,
    generated: Zeroizing<Vec<u8>>,
    mut prompt_fn: F,
    error: &mut dyn Write,
) -> Result<Zeroizing<Vec<u8>>, String>
where
    F: FnMut(&str, &mut dyn Write) -> Result<Zeroizing<Vec<u8>>, String>,
{
    let prompt = format!("Type the Medium {label} passphrase back (hidden): ");
    for attempt in 1..=MAX_CONFIRM_ATTEMPTS {
        if attempt == 1 {
            write!(
                error,
                "Medium {label} generated seven-word EFF passphrase (shown once): "
            )
            .map_err(|_| "could not show generated passphrase")?;
        } else {
            write!(
                error,
                "Medium {label} seven-word EFF passphrase (re-displayed, attempt {attempt} of {MAX_CONFIRM_ATTEMPTS}): "
            )
            .map_err(|_| "could not show generated passphrase")?;
        }
        error
            .write_all(&generated)
            .map_err(|_| "could not show generated passphrase")?;
        writeln!(error).map_err(|_| "could not finish generated passphrase display")?;
        let typed = prompt_fn(&prompt, error);
        clear_generated_display(error)?;
        let typed = typed?;
        if generated.as_slice() == typed.as_slice() {
            return Ok(generated);
        }
        drop(typed);
        if attempt < MAX_CONFIRM_ATTEMPTS {
            let remaining = MAX_CONFIRM_ATTEMPTS - attempt;
            writeln!(
                error,
                "Medium {label} typed passphrase differs; re-displaying the same passphrase ({remaining} attempt(s) left)."
            )
            .map_err(|_| "could not show passphrase retry notice")?;
        }
    }
    Err(format!(
        "Medium {label} typed passphrase failed {MAX_CONFIRM_ATTEMPTS} times; no share files were written"
    ))
}

fn confirm_medium_passphrase(label: &str, error: &mut dyn Write) -> Result<Zeroizing<Vec<u8>>, String> {
    let generated = eff_passphrase::generate().map_err(str::to_owned)?;
    confirm_medium_passphrase_with(label, generated, hidden_passphrase, error)
}

fn write_encrypted_shares_with<W>(
    media_dirs: &[PathBuf; 3],
    primary_shares: &[Zeroizing<String>; 3],
    recovery_shares: &[Zeroizing<String>; 3],
    passphrases: &[Zeroizing<Vec<u8>>; 3],
    encrypt: EncryptFn,
    mut writer: W,
) -> Result<[[PathBuf; 2]; 3], String>
where
    W: FnMut(&Path, &[u8], usize) -> Result<(), String>,
{
    let mut paths: Vec<[PathBuf; 2]> = Vec::with_capacity(3);
    let mut created: Vec<PathBuf> = Vec::with_capacity(6);
    for medium_idx in 0..3 {
        let dir = media_dirs.get(medium_idx).ok_or("missing medium directory")?;
        let passphrase = passphrases.get(medium_idx).ok_or("missing medium passphrase")?;
        let primary_share = primary_shares.get(medium_idx).ok_or("missing primary share")?;
        let recovery_share = recovery_shares.get(medium_idx).ok_or("missing recovery share")?;

        let primary_path = dir.join(PRIMARY_SHARE_FILE);
        let mut primary_text = Zeroizing::new(format!("{}\n", primary_share.as_str()));
        let primary_ct = match encrypt(primary_text.as_bytes(), passphrase) {
            Ok(ct) => ct,
            Err(cause) => {
                primary_text.zeroize();
                return Err(media::rollback_partial_shares(media_dirs, &created, cause));
            }
        };
        primary_text.zeroize();
        if let Err(cause) = writer(&primary_path, &primary_ct, age_scrypt::MAX_FILE) {
            return Err(media::rollback_partial_shares(media_dirs, &created, &cause));
        }
        created.push(primary_path.clone());

        let recovery_path = dir.join(RECOVERY_SHARE_FILE);
        let mut recovery_text = Zeroizing::new(format!("{}\n", recovery_share.as_str()));
        let recovery_ct = match encrypt(recovery_text.as_bytes(), passphrase) {
            Ok(ct) => ct,
            Err(cause) => {
                recovery_text.zeroize();
                return Err(media::rollback_partial_shares(media_dirs, &created, cause));
            }
        };
        recovery_text.zeroize();
        if let Err(cause) = writer(&recovery_path, &recovery_ct, age_scrypt::MAX_FILE) {
            return Err(media::rollback_partial_shares(media_dirs, &created, &cause));
        }
        created.push(recovery_path.clone());

        paths.push([primary_path, recovery_path]);
    }
    paths.try_into().map_err(|_| "internal media path error".to_owned())
}

fn write_encrypted_shares(
    media_dirs: &[PathBuf; 3],
    primary_shares: &[Zeroizing<String>; 3],
    recovery_shares: &[Zeroizing<String>; 3],
    passphrases: &[Zeroizing<Vec<u8>>; 3],
    encrypt: EncryptFn,
) -> Result<[[PathBuf; 2]; 3], String> {
    write_encrypted_shares_with(
        media_dirs,
        primary_shares,
        recovery_shares,
        passphrases,
        encrypt,
        media::write_share_file,
    )
}

fn read_all_files(paths: &[[PathBuf; 2]; 3]) -> Result<(MediaBlobs, Vec<ShareFileReceipt>), String> {
    let mut blobs: Vec<[Zeroizing<Vec<u8>>; 2]> = Vec::with_capacity(3);
    let mut receipts = Vec::with_capacity(6);
    for (medium_idx, pair) in paths.iter().enumerate() {
        let label = *MEDIA_LABELS.get(medium_idx).ok_or("missing medium label")?;
        let primary_path = pair.first().ok_or("missing primary path")?;
        let recovery_path = pair.get(1).ok_or("missing recovery path")?;

        let primary_bytes = Zeroizing::new(media::read_share_file(primary_path, age_scrypt::MAX_FILE)?);
        receipts.push(ShareFileReceipt {
            medium: label,
            role: RootRole::Primary.as_str(),
            path: primary_path.display().to_string(),
            sha256: hex::encode(Sha256::digest(primary_bytes.as_slice())),
        });

        let recovery_bytes = Zeroizing::new(media::read_share_file(recovery_path, age_scrypt::MAX_FILE)?);
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

fn prompt_verified_medium_passphrase<F>(
    label: &str,
    primary_blob: &[u8],
    decrypt: DecryptFn,
    mut prompt_fn: F,
    error: &mut dyn Write,
) -> Result<Zeroizing<Vec<u8>>, String>
where
    F: FnMut(&str, &mut dyn Write) -> Result<Zeroizing<Vec<u8>>, String>,
{
    let prompt = format!("Re-enter Medium {label} passphrase to verify (hidden): ");
    for attempt in 1..=MAX_VERIFY_ATTEMPTS {
        let candidate = prompt_fn(&prompt, error).map_err(|err| format!("{err}; {VERIFY_ABORT_MESSAGE}"))?;
        if decrypt(primary_blob, &candidate).is_ok() {
            return Ok(candidate);
        }
        drop(candidate);
        if attempt < MAX_VERIFY_ATTEMPTS {
            let remaining = MAX_VERIFY_ATTEMPTS - attempt;
            let _ = writeln!(
                error,
                "Medium {label} passphrase did not decrypt its primary share; try again ({remaining} attempt(s) left)."
            );
        }
    }
    Err(format!(
        "Medium {label} passphrase failed {MAX_VERIFY_ATTEMPTS} times; {VERIFY_ABORT_MESSAGE}"
    ))
}

/// Exercise the production medium verification retry prompt against one encrypted file.
pub fn run_verify_prompt_probe(label: &str, path: &Path, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    let result = (|| -> Result<(), String> {
        prepare_owner_terminal()?;
        let blob = Zeroizing::new(media::read_share_file(path, age_scrypt::MAX_FILE)?);
        let verified = prompt_verified_medium_passphrase(label, &blob, age_scrypt::decrypt, hidden_passphrase, error)?;
        drop(verified);
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => render_error(false, &problem, output, error),
    }
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

fn check_offline_guard(i_confirm_offline: bool, error: &mut dyn Write) -> Result<(), String> {
    if i_confirm_offline {
        writeln!(
            error,
            "WARNING: test-only offline override; a default route may be present."
        )
        .map_err(|_| "could not show offline override warning")?;
    } else if offline_route::has_default_route()? {
        return Err("default route is present; disconnect network before generating NC0 LMS roots".to_owned());
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
    check_offline_guard(i_confirm_offline, error)?;
    let media_dirs = media::preflight_media(medium_a, medium_b, medium_c, true)?;

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
        &media_dirs,
        &primary_shares,
        &recovery_shares,
        &passphrases,
        age_scrypt::encrypt,
    )?;
    drop(primary_shares);
    drop(recovery_shares);
    drop(passphrases);

    let (blobs, file_receipts) = read_all_files(&paths).map_err(|err| format!("{err}; {VERIFY_ABORT_MESSAGE}"))?;
    let primary_a = blobs
        .first()
        .and_then(|pair| pair.first())
        .ok_or_else(|| format!("missing Medium A primary blob; {VERIFY_ABORT_MESSAGE}"))?;
    let primary_b = blobs
        .get(1)
        .and_then(|pair| pair.first())
        .ok_or_else(|| format!("missing Medium B primary blob; {VERIFY_ABORT_MESSAGE}"))?;
    let primary_c = blobs
        .get(2)
        .and_then(|pair| pair.first())
        .ok_or_else(|| format!("missing Medium C primary blob; {VERIFY_ABORT_MESSAGE}"))?;

    let verify_a = prompt_verified_medium_passphrase("A", primary_a, age_scrypt::decrypt, hidden_passphrase, error)?;
    let verify_b = prompt_verified_medium_passphrase("B", primary_b, age_scrypt::decrypt, hidden_passphrase, error)?;
    let verify_c = prompt_verified_medium_passphrase("C", primary_c, age_scrypt::decrypt, hidden_passphrase, error)?;
    let verify_passphrases = [verify_a, verify_b, verify_c];

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
    )
    .map_err(|err| format!("{err}; {VERIFY_ABORT_MESSAGE}"))?;
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
