//! Non-Rust regression suites and verification of registry-style packages.

use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

pub fn run(root: &Path, output: &mut dyn Write, error: &mut dyn Write) -> Result<(), String> {
    writeln!(output, "Running owner-setup and gateway-probe regression tests.").map_err(|error| error.to_string())?;
    // These suites have no third-party Python dependencies and do not perform
    // privileged setup or touch live services. The script pins its Python floor.
    let status = Command::new("uv")
        .args(["run", "--offline", "--script", "tools/check.py"])
        .current_dir(root)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err("owner-setup or gateway-probe tests failed".to_owned());
    }
    // Cargo's temporary registry resolves this exact package set without
    // publishing or silently building against workspace path dependencies.
    super::run_cargo(
        root,
        &[
            "package",
            "--locked",
            "--allow-dirty",
            "--package",
            "supgang-acl",
            "--package",
            "supgang-core",
            "--package",
            "supgang",
        ],
        output,
        error,
    )
}
