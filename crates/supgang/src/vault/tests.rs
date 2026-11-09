use std::fs;

use p256::{PublicKey, SecretKey, elliptic_curve::sec1::ToSec1Point};
use zeroize::Zeroizing;

use super::{
    AUDIT_FILE_NAME, Enclave, MAX_AUDIT_BYTES, MAX_SECRET_BYTES, VAULT_FILE_NAME, VaultError, add, append_audit,
    decode, list, remove, reveal, validate_name,
};
use crate::{
    device_key::custody::{CustodyKind, SealedKey},
    state,
};

/// A file-held stand-in for the enclave; production refuses this kind.
struct Software;

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

fn state_directory() -> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
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
