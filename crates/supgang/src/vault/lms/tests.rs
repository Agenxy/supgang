use std::{fs, path::PathBuf};

use super::*;
use crate::device_key::custody::{CustodyError, UnavailableReason};
use crate::vault::{
    PUBLIC_BYTES,
    tests::{Software, state_directory},
};

struct DeclinePresence {
    presence_key: SealedKey,
}

impl Enclave for DeclinePresence {
    fn generate(&self) -> Result<(SealedKey, [u8; PUBLIC_BYTES]), VaultError> {
        Software.generate()
    }
    fn generate_presence(&self) -> Result<(SealedKey, [u8; PUBLIC_BYTES]), VaultError> {
        Software.generate_presence()
    }
    fn agree(&self, sealed: &SealedKey, peer: &[u8; PUBLIC_BYTES]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        if sealed == &self.presence_key {
            return Err(CustodyError::Unavailable(UnavailableReason::OwnerDeclinedPresence).into());
        }
        Software.agree(sealed, peer)
    }
    fn agree_presence(
        &self,
        sealed: &SealedKey,
        peer: &[u8; PUBLIC_BYTES],
        reason: &str,
    ) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        assert_eq!(reason, "Approve Supgang LMS nc0 q=0 sha256=0000000000000000");
        self.agree(sealed, peer)
    }
}

fn fixture() -> Result<(tempfile::TempDir, PathBuf, LmsPublic), Box<dyn std::error::Error>> {
    let (temporary, directory) = state_directory()?;
    let (key, public) = Software.generate()?;
    let id = [9_u8; 16];
    let lms_public = lms_rfc::public_key(&id, &[3_u8; 32]);
    let mut private = [7_u8; 48];
    private.get_mut(32..).ok_or("short private")?.copy_from_slice(&id);
    let wrap = seal_presence(&Software, "nc0", "test root", 1, &lms_public, &private)?;
    let mut entry = seal_entry(
        &public,
        "nc0",
        "test root",
        1,
        &[1_u8],
        SealMetadata {
            kind: Kind::LmsSha256H20W1,
            signing_public: None,
            lms_public: Some(lms_public),
            lms_next_q: Some(0),
            remote_creator: None,
            presence_digest: Some(wrap.digest()),
        },
        None,
    )?;
    entry.lms_presence = Some(wrap);
    let mut document = Document {
        version: VERSION,
        key,
        public,
        entries: vec![entry],
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
    let id: [u8; 16] = expected.public_key[8..24].try_into()?;
    let mut private = [7_u8; 48];
    private[32..].copy_from_slice(&id);
    *document.entries.get_mut(0).ok_or("missing entry")? = seal_entry(
        &document.public,
        "nc0",
        "test root",
        1,
        &private,
        SealMetadata {
            kind: Kind::LmsSha256H20W1,
            signing_public: None,
            lms_public: Some(expected.public_key),
            lms_next_q: Some(0),
            remote_creator: None,
            presence_digest: None,
        },
        None,
    )?;
    document.version = 3;
    fs::write(
        directory.join(super::super::VAULT_FILE_NAME),
        super::super::encode(&document)?.as_slice(),
    )?;
    assert_eq!(public_key(&directory, &Software, "nc0")?, expected);
    assert_eq!(load(&directory)?.ok_or("missing v3 vault")?.version, 3);
    let before = fs::read(journal_path(&directory, "nc0"))?;
    assert!(matches!(
        sign(
            &directory,
            &Software,
            "nc0",
            &Nc0Package {
                digest: [0_u8; 32],
                bytes: 65
            },
            ReleaseLog::FirstSignature,
            0,
            |_, _| {}
        ),
        Err(VaultError::LmsPresenceRequired)
    ));
    assert_eq!(fs::read(journal_path(&directory, "nc0"))?, before);
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
fn presence_refusal_precedes_q_reservation() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, directory, expected) = fixture()?;
    let document = load(&directory)?.ok_or("missing vault")?;
    let entry = document.entries.first().ok_or("missing entry")?;
    let presence_key = entry.lms_presence.as_ref().ok_or("missing wrap")?.key.clone();
    let enclave = DeclinePresence { presence_key };
    assert_eq!(preview(&directory, &enclave, "nc0", ReleaseLog::FirstSignature)?.q, 0);
    let vault_before = fs::read(directory.join(super::super::VAULT_FILE_NAME))?;
    let journal_before = fs::read(journal_path(&directory, "nc0"))?;
    assert!(matches!(
        sign(
            &directory,
            &enclave,
            "nc0",
            &Nc0Package {
                digest: [0_u8; 32],
                bytes: 65
            },
            ReleaseLog::FirstSignature,
            0,
            |_, _| {}
        ),
        Err(VaultError::Enclave(CustodyError::Unavailable(
            UnavailableReason::OwnerDeclinedPresence
        )))
    ));
    assert_eq!(fs::read(directory.join(super::super::VAULT_FILE_NAME))?, vault_before);
    assert_eq!(fs::read(journal_path(&directory, "nc0"))?, journal_before);
    assert_eq!(read_journal(&directory, "nc0", &expected.public_key)?.next_q, 0);
    Ok(())
}

#[test]
fn presence_wrap_tamper_and_stripping_refuse() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, directory, _) = fixture()?;
    let original = load(&directory)?.ok_or("missing vault")?;
    let mut document = original.clone();
    let wrap = document
        .entries
        .first_mut()
        .ok_or("missing entry")?
        .lms_presence
        .as_mut()
        .ok_or("missing wrap")?;
    *wrap.ciphertext.get_mut(0).ok_or("empty ciphertext")? ^= 1;
    save(&directory, &document)?;
    assert!(matches!(
        preview(&directory, &Software, "nc0", ReleaseLog::FirstSignature),
        Err(VaultError::Corrupt)
    ));

    let mut downgraded = original.clone();
    downgraded.version = 5;
    assert!(super::super::encode(&downgraded).is_err());

    let mut stripped = original;
    stripped.entries.first_mut().ok_or("missing entry")?.lms_presence = None;
    stripped.version = 5;
    assert!(super::super::encode(&stripped).is_err());
    stripped.version = VERSION;
    assert!(super::super::encode(&stripped).is_err());
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
    let (_private, q) = reserve_locked(&directory, &Software, "nc0", [0_u8; 32], ReleaseLog::FirstSignature, 0)?;
    assert_eq!(q, 0);
    let document = load(&directory)?.ok_or("missing vault")?;
    assert_eq!(document.entries.first().ok_or("no entry")?.lms_next_q, Some(1));
    assert_eq!(read_journal(&directory, "nc0", &expected.public_key)?.next_q, 1);
    assert_eq!(preview(&directory, &Software, "nc0", ReleaseLog::After(0))?.q, 1);
    assert!(matches!(
        reserve_locked(&directory, &Software, "nc0", [0_u8; 32], ReleaseLog::After(0), 0),
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

#[test]
fn restore_q_advances_to_next_unused_2_pow_16_block_and_refuses_exhaustion() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(RESTORE_Q_BLOCK, 65_536);
    assert_eq!(next_restore_q(0)?, 65_536);
    assert_eq!(next_restore_q(1)?, 65_536);
    assert_eq!(next_restore_q(65_535)?, 65_536);
    assert_eq!(next_restore_q(65_536)?, 131_072);
    assert_eq!(next_restore_q(131_071)?, 131_072);
    assert_eq!(next_restore_q(917_504)?, 983_040);
    assert_eq!(next_restore_q(983_039)?, 983_040);
    // Block 15 (983_040..1_048_575) has no subsequent unused 2^16 block below 2^20.
    assert!(matches!(next_restore_q(983_040), Err(VaultError::LmsExhausted)));
    assert!(matches!(next_restore_q(MAX_Q - 1), Err(VaultError::LmsExhausted)));
    assert!(matches!(next_restore_q(MAX_Q), Err(VaultError::LmsExhausted)));
    assert!(matches!(next_restore_q(u32::MAX), Err(VaultError::LmsExhausted)));
    Ok(())
}
