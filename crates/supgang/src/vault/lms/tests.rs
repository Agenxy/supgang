use std::{fs, path::PathBuf};

use super::*;
use crate::vault::tests::{Software, state_directory};

fn fixture() -> Result<(tempfile::TempDir, PathBuf, LmsPublic), Box<dyn std::error::Error>> {
    let (temporary, directory) = state_directory()?;
    let (key, public) = Software.generate()?;
    let id = [9_u8; 16];
    let lms_public = lms_rfc::public_key(&id, &[3_u8; 32]);
    let mut private = [7_u8; 48];
    private.get_mut(32..).ok_or("short private")?.copy_from_slice(&id);
    let mut document = Document {
        version: VERSION,
        key,
        public,
        entries: vec![seal_entry(
            &public,
            "nc0",
            "test root",
            1,
            &private,
            SealMetadata {
                kind: Kind::LmsSha256H20W1,
                signing_public: None,
                lms_public: Some(lms_public),
                lms_next_q: Some(0),
                remote_creator: None,
            },
            None,
        )?],
    };
    create_journal(&directory, "nc0", &lms_public, &document.key)?;
    save(&directory, &document)?;
    document.entries.clear();
    Ok((temporary, directory, identity(lms_public)))
}

#[test]
fn v3_remains_readable_and_aad_rejects_q_edit() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, directory, expected) = fixture()?;
    assert_eq!(public_key(&directory, &Software, "nc0")?, expected);
    let mut document = load(&directory)?.ok_or("missing vault")?;
    assert_eq!(document.version, VERSION);
    assert_eq!(document.entries.first().ok_or("no entry")?.lms_next_q, Some(0));
    document.version = 3;
    fs::write(
        directory.join(super::super::VAULT_FILE_NAME),
        super::super::encode(&document)?.as_slice(),
    )?;
    assert_eq!(public_key(&directory, &Software, "nc0")?, expected);
    assert_eq!(load(&directory)?.ok_or("missing v3 vault")?.version, 3);
    document.entries.first_mut().ok_or("no entry")?.lms_next_q = Some(1);
    fs::write(
        directory.join(super::super::VAULT_FILE_NAME),
        super::super::encode(&document)?.as_slice(),
    )?;
    assert!(matches!(
        public_key(&directory, &Software, "nc0"),
        Err(VaultError::Corrupt)
    ));
    Ok(())
}

#[test]
fn external_log_mismatch_and_forward_only_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, directory, expected) = fixture()?;
    assert_eq!(preview(&directory, &Software, "nc0", ReleaseLog::FirstSignature)?.q, 0);
    assert!(matches!(
        preview(&directory, &Software, "nc0", ReleaseLog::After(0)),
        Err(VaultError::LmsReleaseLog)
    ));
    assert!(matches!(
        advance(&directory, &Software, "nc0", 0, 0),
        Err(VaultError::LmsAdvanceRefused)
    ));
    assert_eq!(advance(&directory, &Software, "nc0", 2, 0)?, expected);
    assert_eq!(preview(&directory, &Software, "nc0", ReleaseLog::After(1))?.q, 2);
    assert!(matches!(
        preview(&directory, &Software, "nc0", ReleaseLog::FirstSignature),
        Err(VaultError::LmsReleaseLog)
    ));
    let document = load(&directory)?.ok_or("missing vault")?;
    let head = read_journal(&directory, "nc0", &expected.public_key)?;
    append_journal(&directory, "nc0", &expected.public_key, &head, 3, &document.key)?;
    assert!(matches!(
        preview(&directory, &Software, "nc0", ReleaseLog::After(1)),
        Err(VaultError::LmsStateMismatch)
    ));
    assert!(matches!(
        advance(&directory, &Software, "nc0", 3, 1),
        Err(VaultError::LmsAdvanceRefused)
    ));
    advance(&directory, &Software, "nc0", 4, 2)?;
    assert_eq!(preview(&directory, &Software, "nc0", ReleaseLog::After(3))?.q, 4);
    Ok(())
}

#[test]
fn reservation_is_durable_before_signature_computation() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, directory, expected) = fixture()?;
    let (_, _lock) = Lock::acquire(&directory)?;
    let (_private, q) = reserve_locked(&directory, &Software, "nc0", ReleaseLog::FirstSignature, 0)?;
    assert_eq!(q, 0);
    let document = load(&directory)?.ok_or("missing vault")?;
    assert_eq!(document.entries.first().ok_or("no entry")?.lms_next_q, Some(1));
    assert_eq!(read_journal(&directory, "nc0", &expected.public_key)?.next_q, 1);
    assert_eq!(preview(&directory, &Software, "nc0", ReleaseLog::After(0))?.q, 1);
    assert!(matches!(
        reserve_locked(&directory, &Software, "nc0", ReleaseLog::After(0), 0),
        Err(VaultError::LmsStateMismatch)
    ));
    Ok(())
}

#[test]
fn failed_keygen_save_cleans_pristine_journal_and_retry_replaces_it() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, directory) = state_directory()?;
    let (key, _) = Software.generate()?;
    let first_public = lms_rfc::public_key(&[1_u8; 16], &[2_u8; 32]);
    let later_public = lms_rfc::public_key(&[3_u8; 16], &[4_u8; 32]);
    create_journal(&directory, "nc0", &first_public, &key)?;
    assert!(matches!(
        save_or_cleanup(
            &directory,
            "nc0",
            &first_public,
            Err(io::Error::other("injected save failure").into())
        ),
        Err(VaultError::Io(_))
    ));
    assert!(!journal_path(&directory, "nc0").exists());
    create_journal(&directory, "nc0", &first_public, &key)?;
    recover_pristine_orphan(&directory, "nc0")?;
    create_journal(&directory, "nc0", &later_public, &key)?;
    assert_eq!(read_journal(&directory, "nc0", &later_public)?.next_q, 0);
    let audit = fs::read_to_string(directory.join(super::super::AUDIT_FILE_NAME))?;
    assert!(audit.contains("replace-pristine-lms-orphan nc0"));
    Ok(())
}

#[test]
fn committed_save_error_retains_journal_and_nonpristine_orphan_refuses() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, directory, identity) = fixture()?;
    assert!(matches!(
        save_or_cleanup(
            &directory,
            "nc0",
            &identity.public_key,
            Err(io::Error::other("post-commit failure").into())
        ),
        Err(VaultError::Io(_))
    ));
    assert_eq!(read_journal(&directory, "nc0", &identity.public_key)?.next_q, 0);
    let document = load(&directory)?.ok_or("missing vault")?;
    let head = read_journal(&directory, "nc0", &identity.public_key)?;
    append_journal(&directory, "nc0", &identity.public_key, &head, 1, &document.key)?;
    fs::remove_file(directory.join(super::super::VAULT_FILE_NAME))?;
    assert!(matches!(
        recover_pristine_orphan(&directory, "nc0"),
        Err(VaultError::Corrupt)
    ));
    assert_eq!(read_journal(&directory, "nc0", &identity.public_key)?.next_q, 1);
    Ok(())
}

#[test]
fn unreadable_journal_exhaustion_and_export_refusal() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, directory, expected) = fixture()?;
    assert!(matches!(
        super::super::reveal(&directory, &Software, "nc0", Some("get")),
        Err(VaultError::LmsKeyNotExportable)
    ));
    assert!(matches!(
        super::super::remove(&directory, "nc0"),
        Err(VaultError::LmsRootRetained)
    ));
    advance(&directory, &Software, "nc0", MAX_Q, 0)?;
    assert!(matches!(
        preview(&directory, &Software, "nc0", ReleaseLog::After(MAX_Q - 1)),
        Err(VaultError::LmsExhausted)
    ));
    let journal = journal_path(&directory, "nc0");
    fs::write(&journal, b"broken")?;
    assert!(read_journal(&directory, "nc0", &expected.public_key).is_err());
    assert!(advance(&directory, &Software, "nc0", MAX_Q, 0).is_err());
    Ok(())
}

#[test]
fn nc0_package_bounds_and_fields() -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, _) = state_directory()?;
    let path = temporary.path().join("unsigned.nc0");
    let payload = b"app";
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
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(payload);
    fs::write(&path, &bytes)?;
    let parsed = package(&path)?;
    let expected_digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(parsed.digest(), expected_digest);
    assert_eq!(parsed.bytes(), 67);
    *bytes.get_mut(24).ok_or("short header")? = 2;
    fs::write(&path, &bytes)?;
    assert!(matches!(package(&path), Err(VaultError::InvalidNc0Package)));
    Ok(())
}
