//! Read-only verification of an existing passphrase-encrypted NC0 LMS escrow file.

use std::{io::Write, path::Path, process::ExitCode};

use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    age_scrypt, artifact,
    cli::render_error,
    cli_lms_escrow::{hidden_passphrase, prepare_owner_terminal},
    vault,
};

#[derive(Serialize)]
struct PublicOutput<'a> {
    schema: &'static str,
    status: &'static str,
    name: &'a str,
    public_key: String,
    fingerprint: &'a str,
    known_answer_signature_sha256: &'a str,
    next_q: u32,
    file_sha256: &'a str,
}

fn decrypt_reason(problem: &str) -> &'static str {
    match problem {
        "age passphrase or file authentication failed" => "bad passphrase or escrow file authentication",
        "age header authentication failed" | "age payload authentication failed" => "escrow file authentication failed",
        _ => "malformed or unsupported escrow file",
    }
}

type Decoder = fn(&[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str>;

fn verify_bytes(
    name: &str,
    file: &[u8],
    passphrase: &[u8],
    decode: Decoder,
    progress: impl FnMut(u32, u32),
) -> Result<vault::EscrowPublic, String> {
    let plaintext = decode(file, passphrase).map_err(|problem| decrypt_reason(problem).to_owned())?;
    vault::verify_escrow_public(&plaintext, name, None, progress)
        .map_err(|_| "escrow name, known answer, or root mismatch".to_owned())
}

fn verify(name: &str, path: &Path, json: bool, output: &mut dyn Write, error: &mut dyn Write) -> Result<(), String> {
    prepare_owner_terminal()?;
    vault::validate_name(name).map_err(|problem| problem.to_string())?;
    let file = Zeroizing::new(
        artifact::read(path, age_scrypt::MAX_FILE)
            .map_err(|_| format!("{}: could not read a bounded escrow file", path.display()))?,
    );
    let file_sha256 = hex::encode(Sha256::digest(file.as_slice()));
    let passphrase = hidden_passphrase("Escrow passphrase (hidden): ", error)?;
    let receipt = verify_bytes(name, &file, &passphrase, age_scrypt::decrypt, |done, total| {
        if done % 65_536 == 0 || done == total {
            let _ = writeln!(error, "Verify {}: {done}/{total}", path.display());
        }
    })
    .map_err(|problem| format!("{}: {problem}", path.display()))?;
    let public_key = hex::encode(receipt.identity.public_key);
    if json {
        let response = PublicOutput {
            schema: "supgang.nc0-lms-escrow-verify/v1",
            status: "ok",
            name,
            public_key,
            fingerprint: &receipt.identity.fingerprint,
            known_answer_signature_sha256: &receipt.signature_sha256,
            next_q: receipt.next_q,
            file_sha256: &file_sha256,
        };
        serde_json::to_writer(&mut *output, &response).map_err(|_| "could not write JSON result")?;
        writeln!(output).map_err(|_| "could not finish JSON result")?;
    } else {
        writeln!(
            output,
            "Public key: {public_key}\nFingerprint: {}\nKnown-answer signature SHA-256: {}\nNext q: {}\nFile SHA-256: {file_sha256}",
            receipt.identity.fingerprint, receipt.signature_sha256, receipt.next_q
        )
        .map_err(|_| "could not write public receipt")?;
    }
    Ok(())
}

pub fn run(name: &str, path: &Path, json: bool, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    match verify(name, path, json, output, error) {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => render_error(json, &problem, output, error),
    }
}

#[cfg(test)]
mod tests {
    use super::verify_bytes;
    use crate::{age_scrypt, artifact, vault};

    fn cctv_ciphertext(vector: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let source = hex::decode(vector.trim())?;
        let split = source
            .windows(2)
            .position(|bytes| bytes == b"\n\n")
            .ok_or("CCTV metadata separator missing")?;
        Ok(source.get(split + 2..).ok_or("CCTV ciphertext missing")?.to_vec())
    }

    #[test]
    fn cctv_scrypt_failures_refuse_through_verifier_path() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (
                include_str!("../tests/fixtures/cctv-scrypt_no_match.hex"),
                b"wrong".as_slice(),
            ),
            (
                include_str!("../tests/fixtures/cctv-scrypt_bad_tag.hex"),
                b"password".as_slice(),
            ),
            (
                include_str!("../tests/fixtures/cctv-scrypt_work_factor_23.hex"),
                b"password".as_slice(),
            ),
            (
                include_str!("../tests/fixtures/cctv-scrypt_not_canonical_salt.hex"),
                b"password".as_slice(),
            ),
            (
                include_str!("../tests/fixtures/cctv-scrypt_extra_argument.hex"),
                b"password".as_slice(),
            ),
            (
                include_str!("../tests/fixtures/cctv-scrypt_double.hex"),
                b"password".as_slice(),
            ),
        ];
        for (vector, passphrase) in cases {
            let file = cctv_ciphertext(vector)?;
            assert!(verify_bytes("test-root", &file, passphrase, age_scrypt::decrypt_cctv, |_, _| {}).is_err());
        }
        let mut bad_mac = cctv_ciphertext(include_str!("../tests/fixtures/cctv-scrypt.hex"))?;
        let offset = bad_mac
            .windows(4)
            .position(|bytes| bytes == b"--- ")
            .ok_or("CCTV header MAC missing")?;
        let first = bad_mac.get_mut(offset + 4).ok_or("CCTV header MAC empty")?;
        *first = if *first == b'A' { b'B' } else { b'A' };
        assert_eq!(
            verify_bytes("test-root", &bad_mac, b"password", age_scrypt::decrypt_cctv, |_, _| {})
                .err()
                .as_deref(),
            Some("escrow file authentication failed")
        );
        Ok(())
    }

    #[test]
    fn ceremony_file_verifies_and_wrong_inputs_refuse() -> Result<(), Box<dyn std::error::Error>> {
        let name = "test-escrow-verify";
        let passphrase = b"test-only-escrow-verify-passphrase-2026-long";
        let key = vault::generate_escrow(name, |_, _| {})?;
        let file = age_scrypt::encrypt_test_factor18(key.record(), passphrase)?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("escrow.age");
        artifact::write_new(&path, &file, age_scrypt::MAX_FILE)?;
        let on_disk = artifact::read(&path, age_scrypt::MAX_FILE)?;
        let receipt = verify_bytes(name, &on_disk, passphrase, age_scrypt::decrypt, |_, _| {})?;
        assert_eq!(receipt.identity, key.public().identity);
        assert_eq!(receipt.signature_sha256, key.public().signature_sha256);
        assert_eq!(receipt.next_q, 1);
        assert!(
            verify_bytes(
                name,
                &on_disk,
                b"wrong-test-only-passphrase",
                age_scrypt::decrypt,
                |_, _| {}
            )
            .is_err()
        );
        let mut flipped = on_disk.clone();
        *flipped.last_mut().ok_or("empty escrow file")? ^= 1;
        assert!(verify_bytes(name, &flipped, passphrase, age_scrypt::decrypt, |_, _| {}).is_err());
        assert!(verify_bytes("wrong-name", &on_disk, passphrase, age_scrypt::decrypt, |_, _| {}).is_err());
        Ok(())
    }
}
