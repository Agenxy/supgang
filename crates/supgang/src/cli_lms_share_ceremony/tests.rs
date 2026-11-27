use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use zeroize::{Zeroize, Zeroizing};

use super::{
    PRIMARY_SHARE_FILE, RECOVERY_SHARE_FILE, VERIFY_ABORT_MESSAGE, confirm_medium_passphrase_with, media,
    prompt_verified_medium_passphrase, read_all_files, verify_all_pairs, write_encrypted_shares,
    write_encrypted_shares_with,
};
use crate::{
    age_scrypt, slip39,
    vault::{self, MASTER_LEN, RootRole},
};

#[test]
fn media_preflight_checks_distinct_dirs_st_dev_existing_files_and_cleans_probes()
-> Result<(), Box<dyn std::error::Error>> {
    let dir_a = crate::storage::test_tempdir()?;
    let dir_b = crate::storage::test_tempdir()?;
    let dir_c = crate::storage::test_tempdir()?;

    // Three tempdirs on the same host volume share st_dev -> refused when distinct devices are required.
    let same_dev_err = media::preflight_media(dir_a.path(), dir_b.path(), dir_c.path(), true)
        .err()
        .ok_or("expected same st_dev refusal")?;
    assert!(same_dev_err.contains("same storage device (st_dev)"));

    // With distinct-device requirement relaxed for single-disk unit tests, preflight succeeds
    // and leaves zero probe files behind (while ignoring unrelated `._*` AppleDouble files).
    fs::write(dir_a.path().join("._unrelated"), b"appledouble")?;
    media::preflight_media(dir_a.path(), dir_b.path(), dir_c.path(), false)?;
    assert_eq!(fs::read_dir(dir_b.path())?.count(), 0);
    assert_eq!(fs::read_dir(dir_c.path())?.count(), 0);

    // Duplicate directories are refused.
    assert!(media::preflight_media(dir_a.path(), dir_a.path(), dir_c.path(), false).is_err());
    assert!(media::preflight_media(dir_a.path(), dir_b.path(), dir_b.path(), false).is_err());

    // Pre-existing share file is refused.
    let existing = dir_b.path().join(RECOVERY_SHARE_FILE);
    fs::write(&existing, b"already-here")?;
    assert!(media::preflight_media(dir_a.path(), dir_b.path(), dir_c.path(), false).is_err());
    Ok(())
}

#[test]
fn removable_media_writer_and_reader_handle_exfat_modes_and_refuse_faults() -> Result<(), Box<dyn std::error::Error>> {
    let dir = crate::storage::test_tempdir()?;
    let path = dir.path().join(PRIMARY_SHARE_FILE);
    media::write_share_file(&path, b"age-ciphertext-bytes", 128)?;
    assert_eq!(media::read_share_file(&path, 128)?, b"age-ciphertext-bytes");

    // O_EXCL refuses overwrite.
    assert!(media::write_share_file(&path, b"overwrite", 128).is_err());

    // Mode 0700 (as mounted on exFAT) is accepted on read.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    assert_eq!(media::read_share_file(&path, 128)?, b"age-ciphertext-bytes");

    // AppleDouble `._*` files are refused.
    let appledouble = dir.path().join("._nc0-product-primary.share.age");
    fs::write(&appledouble, b"appledouble")?;
    assert!(media::read_share_file(&appledouble, 128).is_err());
    assert!(media::write_share_file(&dir.path().join("._new.share.age"), b"x", 128).is_err());

    // Oversized and empty are refused.
    assert!(media::read_share_file(&path, 4).is_err());
    let empty = dir.path().join("empty.share.age");
    fs::write(&empty, b"")?;
    assert!(media::read_share_file(&empty, 128).is_err());

    // FIFO is refused without blocking.
    let pipe = dir.path().join("pipe.share.age");
    let status = Command::new("mkfifo").arg(&pipe).status()?;
    assert!(status.success());
    assert!(media::read_share_file(&pipe, 128).is_err());
    Ok(())
}

#[test]
fn partial_write_failure_cleans_all_created_share_files() -> Result<(), Box<dyn std::error::Error>> {
    let dir_a = crate::storage::test_tempdir()?;
    let dir_b = crate::storage::test_tempdir()?;
    let dir_c = crate::storage::test_tempdir()?;
    let media_dirs = [
        dir_a.path().to_path_buf(),
        dir_b.path().to_path_buf(),
        dir_c.path().to_path_buf(),
    ];

    let primary_shares = slip39::split_2_of_3(&[0x55_u8; MASTER_LEN])?;
    let recovery_shares = slip39::split_2_of_3(&[0x66_u8; MASTER_LEN])?;
    let passphrases = [
        Zeroizing::new(b"alpha bravo charlie delta echo foxtrot golf".to_vec()),
        Zeroizing::new(b"hotel india juliet kilo lima mike november".to_vec()),
        Zeroizing::new(b"oscar papa quebec romeo sierra tango uniform".to_vec()),
    ];

    let mut writes = 0_usize;
    let err = write_encrypted_shares_with(
        &media_dirs,
        &primary_shares,
        &recovery_shares,
        &passphrases,
        age_scrypt::encrypt_test_factor18,
        |path: &Path, bytes: &[u8], maximum: usize| {
            writes += 1;
            if writes == 4 {
                return Err(format!("{}: simulated I/O failure on share #4", path.display()));
            }
            media::write_share_file(path, bytes, maximum)
        },
    )
    .err()
    .ok_or("expected failure on share #4")?;

    assert!(err.contains("simulated I/O failure on share #4"));
    assert!(err.contains("no share files created by this run remain"));
    assert!(err.contains(PRIMARY_SHARE_FILE));
    assert!(err.contains(RECOVERY_SHARE_FILE));

    for dir in &media_dirs {
        let entries: Vec<PathBuf> = fs::read_dir(dir)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<_, _>>()?;
        assert!(
            entries.is_empty(),
            "expected clean directory {}, found {entries:?}",
            dir.display()
        );
    }
    Ok(())
}

#[test]
fn rollback_preserves_preexisting_target_planted_after_preflight_and_removes_earlier_files()
-> Result<(), Box<dyn std::error::Error>> {
    let dir_a = crate::storage::test_tempdir()?;
    let dir_b = crate::storage::test_tempdir()?;
    let dir_c = crate::storage::test_tempdir()?;
    let media_dirs = media::preflight_media(dir_a.path(), dir_b.path(), dir_c.path(), false)?;

    // Plant a pre-existing file at the 6th destination after preflight succeeds.
    let planted = dir_c.path().join(RECOVERY_SHARE_FILE);
    let sentinel = b"pre-existing-owner-file-do-not-delete";
    fs::write(&planted, sentinel)?;

    let primary_shares = slip39::split_2_of_3(&[0x55_u8; MASTER_LEN])?;
    let recovery_shares = slip39::split_2_of_3(&[0x66_u8; MASTER_LEN])?;
    let passphrases = [
        Zeroizing::new(b"alpha bravo charlie delta echo foxtrot golf".to_vec()),
        Zeroizing::new(b"hotel india juliet kilo lima mike november".to_vec()),
        Zeroizing::new(b"oscar papa quebec romeo sierra tango uniform".to_vec()),
    ];

    let err = write_encrypted_shares(
        &media_dirs,
        &primary_shares,
        &recovery_shares,
        &passphrases,
        age_scrypt::encrypt_test_factor18,
    )
    .err()
    .ok_or("expected AlreadyExists refusal on planted file")?;

    assert!(err.contains("already exists"), "unexpected error: {err}");
    assert!(
        err.contains("no share files created by this run remain"),
        "unexpected error: {err}"
    );
    // The planted file must not be deleted and must not be listed in cleaned-up files.
    assert_eq!(fs::read(&planted)?, sentinel);
    let cleaned_section = err
        .split("cleaned up share file(s) created by this run: [")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .ok_or("missing cleaned-up list in error")?;
    assert!(
        !cleaned_section.contains(&planted.display().to_string()),
        "planted file was falsely listed as cleaned up: {cleaned_section}"
    );

    // Every earlier file created by this run (5 files) must have been removed.
    assert!(!dir_a.path().join(PRIMARY_SHARE_FILE).exists());
    assert!(!dir_a.path().join(RECOVERY_SHARE_FILE).exists());
    assert!(!dir_b.path().join(PRIMARY_SHARE_FILE).exists());
    assert!(!dir_b.path().join(RECOVERY_SHARE_FILE).exists());
    assert!(!dir_c.path().join(PRIMARY_SHARE_FILE).exists());
    Ok(())
}

#[test]
fn first_typeback_allows_three_attempts_redisplays_same_phrase_and_clears_each_time()
-> Result<(), Box<dyn std::error::Error>> {
    let phrase = b"alpha bravo charlie delta echo foxtrot golf";
    let clear_seq = "\x1b[H\x1b[2J\x1b[3J";

    // One wrong entry then right entry succeeds on attempt 2, showing same phrase and clearing twice.
    let mut attempts = [b"typo-one".as_slice(), phrase.as_slice()].into_iter();
    let mut stderr = Vec::new();
    let accepted = confirm_medium_passphrase_with(
        "A",
        Zeroizing::new(phrase.to_vec()),
        |_, _| Ok(Zeroizing::new(attempts.next().ok_or("exhausted")?.to_vec())),
        &mut stderr,
    )?;
    assert_eq!(accepted.as_slice(), phrase);
    let log = String::from_utf8(stderr)?;
    assert_eq!(log.matches(clear_seq).count(), 2);
    assert_eq!(log.matches("alpha bravo charlie delta echo foxtrot golf").count(), 2);
    assert!(log.contains("re-displaying the same passphrase (2 attempt(s) left)"));

    // Two wrong entries then right entry succeeds on attempt 3 with 3 screen clears.
    let mut attempts = [b"typo-1".as_slice(), b"typo-2".as_slice(), phrase.as_slice()].into_iter();
    let mut stderr = Vec::new();
    let accepted = confirm_medium_passphrase_with(
        "B",
        Zeroizing::new(phrase.to_vec()),
        |_, _| Ok(Zeroizing::new(attempts.next().ok_or("exhausted")?.to_vec())),
        &mut stderr,
    )?;
    assert_eq!(accepted.as_slice(), phrase);
    let log = String::from_utf8(stderr)?;
    assert_eq!(log.matches(clear_seq).count(), 3);
    assert!(log.contains("re-displaying the same passphrase (1 attempt(s) left)"));

    // Three wrong entries aborts with no-files-written guarantee and 3 screen clears.
    let mut attempts = [b"w1".as_slice(), b"w2".as_slice(), b"w3".as_slice()].into_iter();
    let mut stderr = Vec::new();
    let err = confirm_medium_passphrase_with(
        "C",
        Zeroizing::new(phrase.to_vec()),
        |_, _| Ok(Zeroizing::new(attempts.next().ok_or("exhausted")?.to_vec())),
        &mut stderr,
    )
    .err()
    .ok_or("expected 3rd mismatch to abort")?;
    assert!(err.contains("no share files were written"));
    let log = String::from_utf8(stderr)?;
    assert_eq!(log.matches(clear_seq).count(), 3);

    // Cancelled prompt still clears the terminal immediately.
    let mut stderr = Vec::new();
    let err = confirm_medium_passphrase_with(
        "A",
        Zeroizing::new(phrase.to_vec()),
        |_, _| Err("escrow ceremony cancelled".to_owned()),
        &mut stderr,
    )
    .err()
    .ok_or("expected cancel to abort")?;
    assert!(err.contains("cancelled"));
    assert_eq!(String::from_utf8(stderr)?.matches(clear_seq).count(), 1);
    Ok(())
}

#[test]
fn six_file_write_wipe_and_all_three_pair_rebuilds_verify_and_detect_tampering()
-> Result<(), Box<dyn std::error::Error>> {
    let dir_a = crate::storage::test_tempdir()?;
    let dir_b = crate::storage::test_tempdir()?;
    let dir_c = crate::storage::test_tempdir()?;
    let media_dirs = media::preflight_media(dir_a.path(), dir_b.path(), dir_c.path(), false)?;

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
        &media_dirs,
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

#[test]
fn verify_passphrase_retry_allows_up_to_three_attempts_then_reports_post_write_guidance()
-> Result<(), Box<dyn std::error::Error>> {
    let good = b"alpha bravo charlie delta echo foxtrot golf";
    let blob = age_scrypt::encrypt_test_factor18(b"test-only share text\n", good)?;

    let mut attempts = [b"wrong-one".as_slice(), good.as_slice()].into_iter();
    let mut stderr = Vec::new();
    let recovered = prompt_verified_medium_passphrase(
        "A",
        &blob,
        age_scrypt::decrypt,
        |_, _| Ok(Zeroizing::new(attempts.next().ok_or("exhausted")?.to_vec())),
        &mut stderr,
    )?;
    assert_eq!(recovered.as_slice(), good);
    assert!(String::from_utf8(stderr)?.contains("try again (2 attempt(s) left)"));

    let mut attempts = [b"wrong-1".as_slice(), b"wrong-2".as_slice(), good.as_slice()].into_iter();
    let mut stderr = Vec::new();
    let recovered = prompt_verified_medium_passphrase(
        "B",
        &blob,
        age_scrypt::decrypt,
        |_, _| Ok(Zeroizing::new(attempts.next().ok_or("exhausted")?.to_vec())),
        &mut stderr,
    )?;
    assert_eq!(recovered.as_slice(), good);
    assert!(String::from_utf8(stderr)?.contains("try again (1 attempt(s) left)"));

    let mut attempts = [b"w1".as_slice(), b"w2".as_slice(), b"w3".as_slice()].into_iter();
    let mut stderr = Vec::new();
    let err = prompt_verified_medium_passphrase(
        "C",
        &blob,
        age_scrypt::decrypt,
        |_, _| Ok(Zeroizing::new(attempts.next().ok_or("exhausted")?.to_vec())),
        &mut stderr,
    )
    .err()
    .ok_or("expected 3rd failure to abort")?;
    assert!(err.contains(VERIFY_ABORT_MESSAGE));
    Ok(())
}

#[cfg(target_os = "macos")]
struct MountedExfatImage {
    device: String,
    mountpoint: PathBuf,
}

#[cfg(target_os = "macos")]
impl MountedExfatImage {
    fn create(root: &Path, name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let image = root.join(format!("{name}.dmg"));
        let mountpoint = root.join(format!("mnt-{name}"));
        fs::create_dir(&mountpoint)?;
        let create = Command::new("hdiutil")
            .args([
                "create", "-size", "4m", "-fs", "ExFAT", "-layout", "NONE", "-volname", name, "-ov",
            ])
            .arg(&image)
            .output()?;
        if !create.status.success() {
            return Err(format!("hdiutil create failed: {}", String::from_utf8_lossy(&create.stderr)).into());
        }
        let attach = Command::new("hdiutil")
            .args(["attach", "-nobrowse", "-mountpoint"])
            .arg(&mountpoint)
            .arg(&image)
            .output()?;
        if !attach.status.success() {
            return Err(format!("hdiutil attach failed: {}", String::from_utf8_lossy(&attach.stderr)).into());
        }
        let stdout = String::from_utf8(attach.stdout)?;
        let device = stdout
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().next())
            .ok_or("could not parse attached disk device")?
            .to_owned();
        Ok(Self { device, mountpoint })
    }
}

#[cfg(target_os = "macos")]
impl Drop for MountedExfatImage {
    fn drop(&mut self) {
        let _ = Command::new("hdiutil")
            .args(["detach", "-force", &self.device])
            .output();
    }
}

#[cfg(target_os = "macos")]
#[test]
fn exfat_hdiutil_images_preflight_write_and_verify_all_pairs() -> Result<(), Box<dyn std::error::Error>> {
    let scratch = crate::storage::test_tempdir()?;
    let img_a = MountedExfatImage::create(scratch.path(), "SGEXFATA")?;
    let img_b = MountedExfatImage::create(scratch.path(), "SGEXFATB")?;
    let img_c = MountedExfatImage::create(scratch.path(), "SGEXFATC")?;

    // Two subdirectories on the same exFAT device must be refused by st_dev check.
    let sub_a = img_a.mountpoint.join("sub");
    fs::create_dir(&sub_a)?;
    let same_dev = media::preflight_media(&img_a.mountpoint, &sub_a, &img_c.mountpoint, true)
        .err()
        .ok_or("expected same st_dev refusal on exFAT subdirs")?;
    assert!(same_dev.contains("same storage device (st_dev)"));
    fs::remove_dir(&sub_a)?;

    // Preflight across 3 distinct exFAT images succeeds and leaves no probe or `._` probe files.
    let media_dirs = media::preflight_media(&img_a.mountpoint, &img_b.mountpoint, &img_c.mountpoint, true)?;
    for dir in &media_dirs {
        for entry in fs::read_dir(dir)? {
            let name = entry?.file_name();
            let lossy = name.to_string_lossy();
            assert!(
                !lossy.contains("supgang-preflight"),
                "leftover preflight file on exFAT: {lossy}"
            );
        }
    }

    let mut primary_master = Zeroizing::new([0x71_u8; MASTER_LEN]);
    let mut recovery_master = Zeroizing::new([0x82_u8; MASTER_LEN]);
    let expected_primary = vault::derive_public_h5_for_test(primary_master.as_ref(), RootRole::Primary)?;
    let expected_recovery = vault::derive_public_h5_for_test(recovery_master.as_ref(), RootRole::Recovery)?;
    let primary_shares = slip39::split_2_of_3(primary_master.as_ref())?;
    let recovery_shares = slip39::split_2_of_3(recovery_master.as_ref())?;
    primary_master.zeroize();
    recovery_master.zeroize();

    let passphrases = [
        Zeroizing::new(b"alpha bravo charlie delta echo foxtrot golf".to_vec()),
        Zeroizing::new(b"hotel india juliet kilo lima mike november".to_vec()),
        Zeroizing::new(b"oscar papa quebec romeo sierra tango uniform".to_vec()),
    ];

    let paths = write_encrypted_shares(
        &media_dirs,
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
    Ok(())
}
