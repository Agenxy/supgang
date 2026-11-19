use std::fs;
use std::process::Command;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use p256::{PublicKey, SecretKey, elliptic_curve::sec1::ToSec1Point};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    AUDIT_FILE_NAME, Enclave, MAX_AUDIT_BYTES, MAX_SECRET_BYTES, VAULT_FILE_NAME, VaultError, add, append_audit,
    decode, keygen, list, public_key, remove, reveal, save, sign, validate_context, validate_name,
};
use crate::{
    device_key::custody::{CustodyKind, SealedKey},
    state,
};

/// A file-held stand-in for the enclave; production refuses this kind.
pub(crate) struct Software;

impl Enclave for Software {
    fn generate(&self) -> Result<(SealedKey, [u8; 33]), VaultError> {
        let secret = loop {
            let mut scalar = [0_u8; 32];
            getrandom::fill(&mut scalar).map_err(std::io::Error::other)?;
            if let Ok(secret) = SecretKey::from_slice(&scalar) {
                break secret;
            }
        };
        let public: [u8; 33] = secret
            .public_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| VaultError::Corrupt)?;
        let sealed = SealedKey {
            kind: CustodyKind::File,
            bytes: secret.to_bytes().to_vec(),
        };
        Ok((sealed, public))
    }
    fn agree(&self, sealed: &SealedKey, peer: &[u8; 33]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let secret = SecretKey::from_slice(&sealed.bytes).map_err(|_| VaultError::Corrupt)?;
        let peer = PublicKey::from_sec1_bytes(peer).map_err(|_| VaultError::Corrupt)?;
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        let mut raw = Zeroizing::new([0_u8; 32]);
        raw.copy_from_slice(shared.raw_secret_bytes());
        Ok(raw)
    }
}

pub(crate) fn state_directory() -> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("state");
    drop(state::initialize(&path)?);
    Ok((temporary, path))
}

#[test]
fn secrets_round_trip_and_list_never_shows_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let initial = list(&path)?;
    assert!(initial.is_empty(), "{initial:?}");
    add(&path, &Software, "github", "gh for agents", b"ghp_example", false)?;
    add(&path, &Software, "anthropic", "", b"sk-ant-example", false)?;
    let names: Vec<_> = list(&path)?
        .into_iter()
        .map(|summary| (summary.name, summary.bytes))
        .collect();
    assert_eq!(names, [("anthropic".to_owned(), 14), ("github".to_owned(), 11)]);
    assert_eq!(
        reveal(&path, &Software, "github", Some("/usr/bin/gh"))?.as_slice(),
        b"ghp_example"
    );
    let stored = fs::read(path.join(VAULT_FILE_NAME))?;
    assert!(!stored.windows(11).any(|window| window == b"ghp_example"));
    let log = fs::read_to_string(path.join(AUDIT_FILE_NAME))?;
    assert!(log.contains(" add github\n"), "{log}");
    assert!(log.contains(" read github gh\n"), "{log}");
    Ok(())
}

#[test]
fn names_replacement_and_bounds_are_enforced() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    for bad in ["", "GitHub", "-lead", "a b", "a/b", &"x".repeat(65)] {
        assert!(matches!(validate_name(bad), Err(VaultError::InvalidName)), "{bad:?}");
    }
    add(&path, &Software, "token", "", b"one", false)?;
    assert!(matches!(
        add(&path, &Software, "token", "", b"two", false),
        Err(VaultError::AlreadyExists(_))
    ));
    add(&path, &Software, "token", "", b"two", true)?;
    assert_eq!(reveal(&path, &Software, "token", None)?.as_slice(), b"two");
    assert!(matches!(
        add(&path, &Software, "empty", "", b"", false),
        Err(VaultError::InvalidSecret)
    ));
    let oversized = vec![1_u8; MAX_SECRET_BYTES + 1];
    assert!(matches!(
        add(&path, &Software, "big", "", &oversized, false),
        Err(VaultError::InvalidSecret)
    ));
    assert!(matches!(
        add(&path, &Software, "note", "line\nbreak", b"x", false),
        Err(VaultError::InvalidNote)
    ));
    remove(&path, "token")?;
    assert!(matches!(
        reveal(&path, &Software, "token", None),
        Err(VaultError::NotFound(_))
    ));
    assert!(matches!(remove(&path, "token"), Err(VaultError::NotFound(_))));
    Ok(())
}

#[test]
fn altered_or_moved_ciphertext_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    add(&path, &Software, "alpha", "", b"first secret", false)?;
    add(&path, &Software, "bravo", "", b"other secret", false)?;
    let file = path.join(VAULT_FILE_NAME);
    let original = fs::read(&file)?;
    let mut flipped = original.clone();
    let last = flipped.len() - 1;
    *flipped.get_mut(last).ok_or("empty vault")? ^= 1;
    fs::write(&file, &flipped)?;
    assert!(matches!(
        reveal(&path, &Software, "bravo", None),
        Err(VaultError::Corrupt)
    ));
    // Renaming an entry keeps the CBOR valid, but its key and AAD bind the name.
    let renamed: Vec<u8> = {
        let mut bytes = original.clone();
        let at = bytes
            .windows(5)
            .position(|window| window == b"bravo")
            .ok_or("no entry")?;
        bytes.get_mut(at..at + 5).ok_or("short")?.copy_from_slice(b"brave");
        bytes
    };
    fs::write(&file, &renamed)?;
    assert!(matches!(
        reveal(&path, &Software, "brave", None),
        Err(VaultError::Corrupt)
    ));
    let mut trailing = original;
    trailing.push(0);
    assert!(matches!(decode(&trailing), Err(VaultError::Corrupt)));
    Ok(())
}

#[test]
fn a_permissive_or_linked_vault_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let (temporary, path) = state_directory()?;
    add(&path, &Software, "token", "", b"value", false)?;
    let file = path.join(VAULT_FILE_NAME);
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644))?;
    assert!(list(&path).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
    let elsewhere = temporary.path().join("elsewhere");
    fs::rename(&file, &elsewhere)?;
    std::os::unix::fs::symlink(&elsewhere, &file)?;
    assert!(list(&path).is_err());
    Ok(())
}

#[test]
fn an_edited_note_fails_authentication() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    add(&path, &Software, "token", "for gh", b"value", false)?;
    let file = path.join(VAULT_FILE_NAME);
    let mut bytes = fs::read(&file)?;
    let at = bytes
        .windows(6)
        .position(|window| window == b"for gh")
        .ok_or("no note")?;
    bytes.get_mut(at..at + 6).ok_or("short")?.copy_from_slice(b"for me");
    fs::write(&file, &bytes)?;
    assert!(matches!(
        reveal(&path, &Software, "token", None),
        Err(VaultError::Corrupt)
    ));
    Ok(())
}

#[test]
fn a_read_that_cannot_be_recorded_releases_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    add(&path, &Software, "token", "", b"value", false)?;
    fs::remove_file(path.join(AUDIT_FILE_NAME))?;
    fs::create_dir(path.join(AUDIT_FILE_NAME))?;
    assert!(matches!(
        reveal(&path, &Software, "token", None),
        Err(VaultError::Audit)
    ));
    Ok(())
}

#[test]
fn signing_entries_are_sealed_and_never_exported() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let identity = keygen(&path, &Software, "launcher", "Agenxy")?;
    assert_eq!(identity, public_key(&path, &Software, "launcher")?);
    let summary = list(&path)?.pop().ok_or("missing signing entry")?;
    assert_eq!(summary.kind, "signing-ed25519");
    assert_eq!(summary.fingerprint.as_deref(), Some(identity.fingerprint.as_str()));
    assert!(matches!(
        reveal(&path, &Software, "launcher", Some("get")),
        Err(VaultError::SigningKeyNotExportable)
    ));
    assert!(matches!(
        reveal(&path, &Software, "launcher", Some("run")),
        Err(VaultError::SigningKeyNotExportable)
    ));
    assert!(matches!(
        keygen(&path, &Software, "launcher", ""),
        Err(VaultError::AlreadyExists(_))
    ));
    Ok(())
}

#[test]
fn get_and_run_commands_refuse_signing_entries() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    keygen(&path, &Software, "launcher", "")?;
    let mut output = Vec::new();
    let mut error = Vec::new();
    let status = crate::cli_vault::run(
        &path,
        crate::cli_args::VaultCommand::Get {
            name: "launcher".to_owned(),
        },
        false,
        &mut output,
        &mut error,
    );
    assert_ne!(status, std::process::ExitCode::SUCCESS);
    assert_eq!(output, Vec::<u8>::new());
    assert!(String::from_utf8(error)?.contains("cannot be exported"));
    let mut output = Vec::new();
    let mut error = Vec::new();
    let status = crate::cli_vault::run(
        &path,
        crate::cli_args::VaultCommand::Run {
            env: vec!["KEY=launcher".to_owned()],
            command: vec![std::ffi::OsString::from("/bin/true")],
        },
        false,
        &mut output,
        &mut error,
    );
    assert_ne!(status, std::process::ExitCode::SUCCESS);
    assert_eq!(output, Vec::<u8>::new());
    assert!(String::from_utf8(error)?.contains("cannot be exported"));
    Ok(())
}

#[test]
fn edited_signing_public_key_fails_authentication() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let identity = keygen(&path, &Software, "launcher", "")?;
    let file = path.join(VAULT_FILE_NAME);
    let mut stored = fs::read(&file)?;
    let index = stored
        .windows(identity.public_key.len())
        .position(|window| window == identity.public_key)
        .ok_or("public key not found")?;
    *stored.get_mut(index).ok_or("missing public key byte")? ^= 1;
    fs::write(&file, stored)?;
    assert!(matches!(
        public_key(&path, &Software, "launcher"),
        Err(VaultError::Corrupt)
    ));
    assert!(matches!(
        sign(&path, &Software, "launcher", "agenxy-launcher.install", &[0; 32]),
        Err(VaultError::Corrupt)
    ));
    Ok(())
}

#[test]
fn canonical_downgrades_cannot_export_a_signing_seed() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    keygen(&path, &Software, "launcher", "")?;
    let file = path.join(VAULT_FILE_NAME);
    let original = fs::read(&file)?;

    for version in [2_u8, 1] {
        let mut document = decode(&original)?;
        document.version = version;
        if version == 2 {
            let entry = document.entries.get_mut(0).ok_or("missing signing entry")?;
            entry.kind = super::Kind::Secret;
            entry.signing_public = None;
        }
        let downgraded = super::format::encode(&document)?;
        // The hostile document is canonical, so only authentication can stop export.
        assert!(decode(&downgraded).is_ok());
        fs::write(&file, &downgraded)?;
        assert!(matches!(
            reveal(&path, &Software, "launcher", Some("get")),
            Err(VaultError::Corrupt)
        ));
    }
    Ok(())
}

#[test]
fn ssh_kind_is_isolated_from_export_and_context_signing() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let ssh = super::ssh_keygen(&path, &Software, "ssh-login", "login")?;
    let signing = keygen(&path, &Software, "artifact", "")?;
    assert_eq!(ssh, super::ssh_public_key(&path, &Software, "ssh-login")?);
    let entries = list(&path)?;
    let ssh_entry = entries
        .iter()
        .find(|entry| entry.name == "ssh-login")
        .ok_or("missing SSH key")?;
    assert_eq!(ssh_entry.kind, "ssh-ed25519");
    assert_eq!(ssh_entry.fingerprint.as_deref(), Some(ssh.fingerprint.as_str()));
    assert!(matches!(
        reveal(&path, &Software, "ssh-login", Some("get")),
        Err(VaultError::SshKeyNotExportable)
    ));
    assert!(matches!(
        reveal(&path, &Software, "ssh-login", Some("run")),
        Err(VaultError::SshKeyNotExportable)
    ));
    assert!(matches!(
        public_key(&path, &Software, "ssh-login"),
        Err(VaultError::NotSigningKey)
    ));
    assert!(matches!(
        sign(&path, &Software, "ssh-login", "artifact", &[0; 32]),
        Err(VaultError::NotSigningKey)
    ));
    assert!(matches!(
        super::ssh_public_key(&path, &Software, "artifact"),
        Err(VaultError::NotSshKey)
    ));
    assert!(matches!(
        super::ssh_sign(&path, &Software, "artifact", b"data"),
        Err(VaultError::NotSshKey)
    ));
    assert_eq!(public_key(&path, &Software, "artifact")?, signing);
    let signed = super::ssh_sign(&path, &Software, "ssh-login", b"SSH challenge")?;
    let verifying = VerifyingKey::from_bytes(&ssh.public_key)?;
    verifying.verify(b"SSH challenge", &Signature::from_bytes(&signed.signature))?;
    assert!(matches!(
        super::ssh_sign(&path, &Software, "ssh-login", &vec![0; 256 * 1024 + 1]),
        Err(VaultError::SshDataTooLarge)
    ));
    let audit = fs::read_to_string(path.join(AUDIT_FILE_NAME))?;
    assert!(audit.contains(" read ssh-login ssh-sign\n"));
    Ok(())
}

#[test]
fn get_and_run_commands_refuse_ssh_entries() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    super::ssh_keygen(&path, &Software, "ssh-login", "")?;
    for command in [
        crate::cli_args::VaultCommand::Get {
            name: "ssh-login".to_owned(),
        },
        crate::cli_args::VaultCommand::Run {
            env: vec!["KEY=ssh-login".to_owned()],
            command: vec![std::ffi::OsString::from("/bin/true")],
        },
    ] {
        let mut output = Vec::new();
        let mut error = Vec::new();
        let status = crate::cli_vault::run(&path, command, false, &mut output, &mut error);
        assert_ne!(status, std::process::ExitCode::SUCCESS);
        assert!(output.is_empty());
        assert!(String::from_utf8(error)?.contains("cannot be exported"));
    }
    Ok(())
}

#[test]
fn ssh_kind_downgrades_and_cross_kind_edits_fail_authentication() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    super::ssh_keygen(&path, &Software, "ssh-login", "")?;
    let file = path.join(VAULT_FILE_NAME);
    let original = fs::read(&file)?;
    for version in [2_u8, 1] {
        let mut document = decode(&original)?;
        document.version = version;
        if version == 2 {
            let entry = document.entries.get_mut(0).ok_or("missing SSH key")?;
            entry.kind = super::Kind::Secret;
            entry.signing_public = None;
        }
        let hostile = super::format::encode(&document)?;
        assert!(decode(&hostile).is_ok());
        fs::write(&file, hostile.as_slice())?;
        assert!(matches!(
            reveal(&path, &Software, "ssh-login", Some("get")),
            Err(VaultError::Corrupt)
        ));
    }
    let mut document = decode(&original)?;
    document.entries.get_mut(0).ok_or("missing SSH key")?.kind = super::Kind::SigningEd25519;
    let hostile = super::format::encode(&document)?;
    fs::write(&file, hostile.as_slice())?;
    assert!(matches!(
        sign(&path, &Software, "ssh-login", "artifact", &[0; 32]),
        Err(VaultError::Corrupt)
    ));
    Ok(())
}

#[test]
fn ssh_fingerprint_matches_ssh_keygen_when_available() -> Result<(), Box<dyn std::error::Error>> {
    if Command::new("ssh-keygen").arg("-V").output().is_err() {
        eprintln!("ssh-keygen unavailable; external fingerprint comparison skipped");
        return Ok(());
    }
    let (_temporary, path) = state_directory()?;
    let public = super::ssh_keygen(&path, &Software, "ssh-login", "")?;
    let file = path.join("ssh-login.pub");
    fs::write(&file, format!("{}\n", public.line))?;
    let output = Command::new("ssh-keygen").arg("-lf").arg(&file).output()?;
    assert!(output.status.success(), "ssh-keygen -lf refused Supgang's public line");
    let result = String::from_utf8(output.stdout)?;
    assert_eq!(result.split_whitespace().nth(1), Some(public.fingerprint.as_str()));
    Ok(())
}

#[test]
fn signing_context_and_digest_are_bound() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let identity = keygen(&path, &Software, "launcher", "")?;
    let digest = Sha256::digest(b"{}");
    let digest: [u8; 32] = digest.into();
    let signed = sign(&path, &Software, "launcher", "agenxy-launcher.install", &digest)?;
    assert_eq!(signed.identity, identity);
    let verifying = VerifyingKey::from_bytes(&identity.public_key)?;
    let signature = Signature::from_bytes(&signed.signature);
    verifying.verify(&super::framed_message("agenxy-launcher.install", &digest), &signature)?;
    assert!(
        verifying
            .verify(&super::framed_message("other.install", &digest), &signature)
            .is_err()
    );
    let other = Sha256::digest(b"{\"changed\":true}");
    assert!(
        verifying
            .verify(
                &super::framed_message("agenxy-launcher.install", &other.into()),
                &signature
            )
            .is_err()
    );
    for bad in ["", "Upper", "has space", "a/b", &"x".repeat(65)] {
        assert!(validate_context(bad).is_err());
    }
    Ok(())
}

#[test]
fn failed_signing_audit_releases_no_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    keygen(&path, &Software, "launcher", "")?;
    fs::remove_file(path.join(AUDIT_FILE_NAME))?;
    fs::create_dir(path.join(AUDIT_FILE_NAME))?;
    assert!(matches!(
        sign(&path, &Software, "launcher", "agenxy-launcher.install", &[0; 32]),
        Err(VaultError::Audit)
    ));
    Ok(())
}

#[test]
fn version_one_secret_survives_signing_upgrade() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    add(&path, &Software, "token", "old entry", b"old value", false)?;
    let directory = crate::storage::validate_directory(&path)?;
    let mut document = super::load(&directory)?.ok_or("missing vault")?;
    document.version = 1;
    save(&directory, &document)?;
    assert_eq!(reveal(&path, &Software, "token", None)?.as_slice(), b"old value");
    keygen(&path, &Software, "launcher", "")?;
    assert_eq!(reveal(&path, &Software, "token", None)?.as_slice(), b"old value");
    Ok(())
}

#[test]
fn published_signing_vector_matches_implementation() -> Result<(), Box<dyn std::error::Error>> {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/vectors/sign-v1/agenxy-launcher-install.json"
    ))?;
    let artifact = hex::decode(
        vector
            .get("artifact_hex")
            .ok_or("artifact_hex")?
            .as_str()
            .ok_or("artifact")?,
    )?;
    assert_eq!(artifact, b"{\"test\":\"supgang-sign/v1\"}");
    let seed = [0x42_u8; 32]; // Public, fixed test seed; production always uses OS randomness.
    let key = SigningKey::from_bytes(&seed);
    let public = key.verifying_key().to_bytes();
    let digest: [u8; 32] = hex::decode(
        vector
            .get("message_sha256")
            .ok_or("message_sha256")?
            .as_str()
            .ok_or("digest")?,
    )?
    .try_into()
    .map_err(|_| "digest length")?;
    assert_eq!(digest.as_slice(), Sha256::digest(&artifact).as_slice());
    let context = vector.get("context").ok_or("context")?.as_str().ok_or("context")?;
    let framed = super::framed_message(context, &digest);
    assert_eq!(
        vector.get("prefix").ok_or("prefix")?.as_str(),
        Some(hex::encode(super::SIGN_DOMAIN).as_str())
    );
    assert_eq!(
        vector.get("framed_message").ok_or("framed_message")?.as_str(),
        Some(hex::encode(&framed).as_str())
    );
    assert_eq!(
        vector.get("public_key").ok_or("public_key")?.as_str(),
        Some(hex::encode(public).as_str())
    );
    assert_eq!(
        vector.get("signature").ok_or("signature")?.as_str(),
        Some(hex::encode(key.sign(&framed).to_bytes()).as_str())
    );
    assert_eq!(
        vector.get("fingerprint").ok_or("fingerprint")?.as_str(),
        Some(super::fingerprint(&public).as_str())
    );
    Ok(())
}

#[test]
fn the_audit_log_stays_bounded_and_keeps_the_newest_lines() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    let directory = crate::storage::validate_directory(&path)?;
    let log = path.join(AUDIT_FILE_NAME);
    let mut previous = 0;
    let mut truncated_at = None;
    for count in 0..20_000_u32 {
        append_audit(&directory, "read", "token", Some(&format!("program{count}")))?;
        let length = fs::metadata(&log)?.len();
        assert!(length <= MAX_AUDIT_BYTES, "{length}");
        if length < previous {
            truncated_at = Some(count);
            break;
        }
        previous = length;
    }
    let last = truncated_at.ok_or("the log never reached its bound")?;
    let text = fs::read_to_string(&log)?;
    assert!(
        text.ends_with(&format!(" read token program{last}\n")),
        "newest line lost"
    );
    assert!(!text.contains(" read token program0\n"), "oldest line kept");
    assert!(text.lines().all(|line| line.split(' ').count() == 4), "torn line");
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires the sibling Swift helper and a real Secure Enclave"]
fn real_enclave_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, path) = state_directory()?;
    add(&path, &super::SecureEnclave, "token", "", b"enclave value", false)?;
    assert_eq!(
        reveal(&path, &super::SecureEnclave, "token", None)?.as_slice(),
        b"enclave value"
    );
    Ok(())
}
