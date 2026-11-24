//! The escrow command must refuse a process without an owner terminal before creating files.

use std::{
    path::PathBuf,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
use supgang_core as _;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!("supgang-lms-nonterminal-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn escrow_refuses_nonterminal_input_without_writing_files() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TestDirectory::new()?;
    let first = directory.0.join("first.age");
    let second = directory.0.join("second.age");
    let output = Command::new(env!("CARGO_BIN_EXE_supgang"))
        .args([
            "lms-keygen",
            "--escrow-only",
            "nonterminal-test",
            "--to",
            first.to_str().ok_or("non-UTF-8 test path")?,
            "--to",
            second.to_str().ok_or("non-UTF-8 test path")?,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8(output.stderr)?.contains("interactive owner terminal"));
    assert!(!first.exists());
    assert!(!second.exists());
    Ok(())
}

#[test]
fn escrow_verify_refuses_nonterminal_input() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TestDirectory::new()?;
    let file = directory.0.join("missing.age");
    let output = Command::new(env!("CARGO_BIN_EXE_supgang"))
        .args([
            "lms-escrow-verify",
            "test-root",
            "--from",
            file.to_str().ok_or("non-UTF-8 test path")?,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8(output.stderr)?.contains("interactive owner terminal"));
    Ok(())
}

#[test]
fn derive_public_refuses_nonterminal_input_and_state_dir() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_supgang"))
        .args(["lms-derive-public", "primary"])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8(output.stderr)?.contains("interactive owner terminal"));

    let directory = TestDirectory::new()?;
    let output = Command::new(env!("CARGO_BIN_EXE_supgang"))
        .args([
            "--state-dir",
            directory.0.to_str().ok_or("non-UTF-8 test path")?,
            "lms-derive-public",
            "recovery",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8(output.stderr)?.contains("takes no peer or state directory"));
    Ok(())
}

#[test]
fn share_ceremony_and_verify_refuse_nonterminal_and_state_dir() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TestDirectory::new()?;
    let a = directory.0.join("a");
    let b = directory.0.join("b");
    let c = directory.0.join("c");
    std::fs::create_dir(&a)?;
    std::fs::create_dir(&b)?;
    std::fs::create_dir(&c)?;

    let output = Command::new(env!("CARGO_BIN_EXE_supgang"))
        .args([
            "lms-share-ceremony",
            "--medium-a",
            a.to_str().ok_or("non-UTF-8 path")?,
            "--medium-b",
            b.to_str().ok_or("non-UTF-8 path")?,
            "--medium-c",
            c.to_str().ok_or("non-UTF-8 path")?,
            "--i-confirm-offline",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8(output.stderr)?.contains("interactive owner terminal"));
    assert!(!a.join("nc0-product-primary.share.age").exists());
    assert!(!b.join("nc0-product-primary.share.age").exists());
    assert!(!c.join("nc0-product-primary.share.age").exists());

    let output = Command::new(env!("CARGO_BIN_EXE_supgang"))
        .args([
            "--state-dir",
            directory.0.to_str().ok_or("non-UTF-8 path")?,
            "lms-share-verify",
            "primary",
            "--share",
            a.to_str().ok_or("non-UTF-8 path")?,
            "--share",
            b.to_str().ok_or("non-UTF-8 path")?,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8(output.stderr)?.contains("takes no peer or state directory"));

    let output = Command::new(env!("CARGO_BIN_EXE_supgang"))
        .args([
            "lms-share-verify",
            "primary",
            "--share",
            a.to_str().ok_or("non-UTF-8 path")?,
            "--share",
            b.to_str().ok_or("non-UTF-8 path")?,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8(output.stderr)?.contains("interactive owner terminal"));
    Ok(())
}
