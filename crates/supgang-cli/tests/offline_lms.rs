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
