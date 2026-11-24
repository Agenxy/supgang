//! Owner-present, network-free NC0 LMS escrow ceremony.

use std::{
    collections::HashSet,
    fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{age_scrypt, artifact, cli::render_error, eff_passphrase, offline_route, vault};

const MAX_PASSPHRASE: usize = 256;
const MIN_FILES: usize = 2;
const MAX_FILES: usize = 4;

#[derive(Serialize)]
struct PublicOutput<'a> {
    schema: &'static str,
    status: &'static str,
    name: &'a str,
    public_key: String,
    fingerprint: &'a str,
    known_answer_signature_sha256: &'a str,
    next_q: u32,
    escrow_files_verified: usize,
    escrow_files: &'a [EscrowFileReceipt],
}

#[derive(Serialize)]
struct EscrowFileReceipt {
    path: String,
    sha256: String,
}

struct HiddenTerminal {
    saved: rustix::termios::Termios,
}

impl HiddenTerminal {
    fn enter() -> Result<Self, String> {
        use rustix::termios::{LocalModes, OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr};
        let stdin = io::stdin();
        let saved = tcgetattr(&stdin).map_err(|_| "could not read terminal settings")?;
        let mut hidden = saved.clone();
        hidden
            .local_modes
            .remove(LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG | LocalModes::IEXTEN);
        hidden.special_codes[SpecialCodeIndex::VMIN] = 1;
        hidden.special_codes[SpecialCodeIndex::VTIME] = 0;
        tcsetattr(&stdin, OptionalActions::Flush, &hidden).map_err(|_| "could not hide terminal input")?;
        Ok(Self { saved })
    }
}

impl Drop for HiddenTerminal {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(io::stdin(), rustix::termios::OptionalActions::Now, &self.saved);
    }
}

pub fn hidden_passphrase(prompt: &str, error: &mut dyn Write) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut secret = Zeroizing::new(Vec::with_capacity(MAX_PASSPHRASE + 1));
    let read = {
        // Hide input before publishing the prompt: a fast response can otherwise
        // echo or be discarded by tcsetattr(Flush) between prompt and mode change.
        let _terminal = HiddenTerminal::enter()?;
        write!(error, "{prompt}").map_err(|_| "could not show passphrase prompt")?;
        error.flush().map_err(|_| "could not flush passphrase prompt")?;
        let stdin = io::stdin();
        let mut byte = Zeroizing::new([0_u8; 1]);
        loop {
            let count = rustix::io::read(&stdin, byte.as_mut()).map_err(|_| "could not read passphrase")?;
            if count != 1 {
                break Err("passphrase input ended".to_owned());
            }
            match *byte.first().ok_or("could not read passphrase byte")? {
                b'\r' | b'\n' => break Ok(()),
                0x03 | 0x04 => break Err("escrow ceremony cancelled".to_owned()),
                0x08 | 0x7f => {
                    secret.pop();
                }
                value if secret.len() < MAX_PASSPHRASE => secret.push(value),
                _ => break Err("passphrase exceeds 256 bytes".to_owned()),
            }
        }
    };
    let _ = writeln!(error);
    read?;
    Ok(secret)
}

fn manual_passphrase_is_strong(secret: &[u8]) -> bool {
    if secret.len() >= 40 {
        return true;
    }
    secret.len() >= 24
        && secret
            .split(u8::is_ascii_whitespace)
            .filter(|word| !word.is_empty())
            .take(7)
            .count()
            >= 7
}

fn clear_generated_display(error: &mut dyn Write) -> Result<(), String> {
    // Move home, clear the visible screen, then clear scrollback. ED2 can
    // push visible lines into scrollback, so ED3 must come last.
    error
        .write_all(b"\x1b[H\x1b[2J\x1b[3J")
        .map_err(|_| "could not request terminal screen and scrollback clear")?;
    writeln!(error, "Passphrase display and scrollback clear requested.")
        .map_err(|_| "could not show terminal clear notice")?;
    error
        .flush()
        .map_err(|_| "could not flush terminal clear notice".to_owned())
}

fn validate_destinations(paths: &[PathBuf]) -> Result<(), String> {
    if !(MIN_FILES..=MAX_FILES).contains(&paths.len()) {
        return Err("provide two to four distinct --to files".to_owned());
    }
    let mut seen = HashSet::with_capacity(MAX_FILES);
    for path in paths {
        let file = path
            .file_name()
            .ok_or_else(|| format!("{}: missing file name", path.display()))?;
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let canonical_parent =
            fs::canonicalize(parent).map_err(|_| format!("{}: parent directory unavailable", path.display()))?;
        let canonical = canonical_parent.join(file);
        if !seen.insert(canonical) {
            return Err(format!("{}: duplicate destination", path.display()));
        }
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(format!("{}: already exists", path.display())),
            Err(problem) if problem.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(format!("{}: cannot inspect destination", path.display())),
        }
    }
    Ok(())
}

pub fn prepare_owner_terminal() -> Result<(), String> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err("offline LMS escrow requires an interactive owner terminal".to_owned());
    }
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| "could not disable core dumps".to_owned())
}

fn ceremony(
    name: &str,
    paths: &[PathBuf],
    generate_passphrase: bool,
    i_confirm_offline: bool,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<(), String> {
    prepare_owner_terminal()?;
    validate_destinations(paths)?;
    vault::validate_name(name).map_err(|problem| problem.to_string())?;
    if i_confirm_offline {
        writeln!(
            error,
            "WARNING: test-only offline override; a default route may be present."
        )
        .map_err(|_| "could not show offline override warning")?;
    } else if offline_route::has_default_route()? {
        return Err("default route is present; disconnect network before generating an LMS root".to_owned());
    }
    writeln!(error, "Generating offline LMS root {name}; computing 1,048,576 leaves.")
        .map_err(|_| "could not show LMS progress")?;
    let started = Instant::now();
    let key = vault::generate_escrow(name, |done, total| {
        if done % 65_536 == 0 || done == total {
            let _ = writeln!(error, "LMS tree: {done}/{total}");
        }
    })
    .map_err(|problem| problem.to_string())?;
    writeln!(
        error,
        "LMS tree and known answer took {:.1}s.",
        started.elapsed().as_secs_f64()
    )
    .map_err(|_| "could not show LMS timing")?;
    let passphrase = if generate_passphrase {
        let generated = eff_passphrase::generate().map_err(str::to_owned)?;
        error
            .write_all(b"Generated seven-word EFF passphrase (shown once): ")
            .map_err(|_| "could not show generated passphrase")?;
        error
            .write_all(&generated)
            .map_err(|_| "could not show generated passphrase")?;
        writeln!(error).map_err(|_| "could not finish generated passphrase display")?;
        let typed = hidden_passphrase("Type the displayed passphrase back (hidden): ", error);
        clear_generated_display(error)?;
        let typed = typed?;
        if generated.as_slice() != typed.as_slice() {
            return Err("typed passphrase differs; no escrow files were written".to_owned());
        }
        generated
    } else {
        let entered = hidden_passphrase("Escrow passphrase (hidden): ", error)?;
        if !manual_passphrase_is_strong(&entered) {
            return Err("passphrase must have seven words totaling at least 24 bytes, or 40 bytes".to_owned());
        }
        let confirmation = hidden_passphrase("Repeat escrow passphrase (hidden): ", error)?;
        if entered.as_slice() != confirmation.as_slice() {
            return Err("passphrases differ; no escrow files were written".to_owned());
        }
        entered
    };
    for path in paths {
        let encrypted = age_scrypt::encrypt(key.record(), &passphrase).map_err(str::to_owned)?;
        artifact::write_new(path, &encrypted, age_scrypt::MAX_FILE)
            .map_err(|problem| format!("{}: {problem}", path.display()))?;
    }
    drop(passphrase);
    let verification_passphrase = hidden_passphrase("Re-enter passphrase to verify every file (hidden): ", error)?;
    let mut escrow_files = Vec::with_capacity(MAX_FILES);
    for path in paths {
        let file = Zeroizing::new(
            artifact::read(path, age_scrypt::MAX_FILE).map_err(|problem| format!("{}: {problem}", path.display()))?,
        );
        let sha256 = hex::encode(Sha256::digest(file.as_slice()));
        let plaintext = age_scrypt::decrypt(&file, &verification_passphrase)
            .map_err(|problem| format!("{}: {problem}", path.display()))?;
        vault::verify_escrow(&plaintext, name, key.public(), |done, total| {
            if done % 65_536 == 0 || done == total {
                let _ = writeln!(error, "Verify {}: {done}/{total}", path.display());
            }
        })
        .map_err(|problem| format!("{}: {problem}", path.display()))?;
        escrow_files.push(EscrowFileReceipt {
            path: path.display().to_string(),
            sha256,
        });
    }
    let receipt = key.public();
    let public_key = hex::encode(receipt.identity.public_key);
    if json {
        let response = PublicOutput {
            schema: "supgang.nc0-lms-public-key/v1",
            status: "ok",
            name,
            public_key,
            fingerprint: &receipt.identity.fingerprint,
            known_answer_signature_sha256: &receipt.signature_sha256,
            next_q: receipt.next_q,
            escrow_files_verified: paths.len(),
            escrow_files: &escrow_files,
        };
        serde_json::to_writer(&mut *output, &response).map_err(|_| "could not write JSON result")?;
        writeln!(output).map_err(|_| "could not finish JSON result")?;
    } else {
        writeln!(output, "Public key: {public_key}\nFingerprint: {}\nKnown-answer signature SHA-256: {}\nNext q: {}\nVerified escrow files: {}", receipt.identity.fingerprint, receipt.signature_sha256, receipt.next_q, paths.len())
            .map_err(|_| "could not write public receipt")?;
        for file in &escrow_files {
            writeln!(output, "Escrow file SHA-256: {}  {}", file.sha256, file.path)
                .map_err(|_| "could not write escrow file digest")?;
        }
    }
    Ok(())
}

pub fn run(
    name: &str,
    paths: &[PathBuf],
    generate_passphrase: bool,
    i_confirm_offline: bool,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    match ceremony(name, paths, generate_passphrase, i_confirm_offline, json, output, error) {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => render_error(json, &problem, output, error),
    }
}

#[cfg(test)]
mod tests {
    use super::{manual_passphrase_is_strong, validate_destinations};

    #[test]
    fn manual_passphrase_floor_accepts_seven_words_or_forty_bytes() {
        assert!(manual_passphrase_is_strong(b"one two three four five six seven"));
        assert!(manual_passphrase_is_strong(b"1234567890123456789012345678901234567890"));
        assert!(!manual_passphrase_is_strong(b"one two three four five six"));
        assert!(!manual_passphrase_is_strong(b"a b c d e f g"));
        assert!(!manual_passphrase_is_strong(b"123456789012345678901234567890123456789"));
    }

    #[test]
    fn escrow_destinations_must_be_new_distinct_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let first = directory.path().join("first.age");
        let second = directory.path().join("second.age");
        assert!(validate_destinations(&[first.clone(), second.clone()]).is_ok());
        assert!(validate_destinations(std::slice::from_ref(&first)).is_err());
        assert!(validate_destinations(&[first.clone(), first.clone()]).is_err());
        std::fs::write(&first, b"existing")?;
        assert!(validate_destinations(&[first, second]).is_err());
        Ok(())
    }
}
