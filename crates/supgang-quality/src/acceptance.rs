//! Non-Rust regression suites and verification of registry-style packages.

use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

/// The Python floor the checked script declares, read from its own PEP 723 metadata.
///
/// Reading it here rather than repeating it keeps the diagnostic honest when the script
/// raises its floor.
fn declared_python_floor(script: &Path) -> Option<String> {
    let text = std::fs::read_to_string(script).ok()?;
    text.lines()
        .map(str::trim_start)
        .find_map(|line| line.strip_prefix("# requires-python = "))
        .map(|value| value.trim().trim_matches('"').to_owned())
}

/// Refuse with a remedy when no interpreter meeting the script's floor is present.
///
/// The suite runs `uv` offline so it cannot acquire third-party dependencies, and that
/// also forbids uv from downloading an interpreter. macOS ships Python 3.9, below every
/// floor this repository uses, so on a machine with nothing else installed uv reports
/// being offline and a contributor reads it as a network fault. Say what is missing and
/// the one command that supplies it.
fn require_python_interpreter(root: &Path, script: &Path) -> Result<(), String> {
    let Some(floor) = declared_python_floor(&root.join(script)) else {
        return Err(format!(
            "{} declares no requires-python, so its interpreter floor cannot be checked",
            script.display()
        ));
    };
    let found = Command::new("uv")
        .args(["python", "find", &floor, "--offline"])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| error.to_string())?;
    if found.success() {
        return Ok(());
    }
    Err(format!(
        "no Python {floor} is installed, which {} requires. This is not a network \
         fault: the suite runs uv offline so it cannot fetch one. Install it with \
         `uv python install {floor}` and run the gate again.",
        script.display()
    ))
}

pub fn run(root: &Path, output: &mut dyn Write, error: &mut dyn Write) -> Result<(), String> {
    writeln!(output, "Running owner-setup and gateway-probe regression tests.").map_err(|error| error.to_string())?;
    // These suites have no third-party Python dependencies and do not perform
    // privileged setup or touch live services. The script pins its Python floor.
    let script = Path::new("tools/check.py");
    require_python_interpreter(root, script)?;
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

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    /// A scratch directory named for this test, removed by the caller.
    fn scratch(name: &str) -> Result<PathBuf, String> {
        let directory = std::env::temp_dir().join(format!("supgang-acceptance-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        Ok(directory)
    }

    fn remove(directory: &Path) -> Result<(), String> {
        std::fs::remove_dir_all(directory).map_err(|error| error.to_string())
    }

    #[test]
    fn python_floor_is_read_from_the_script_rather_than_repeated() -> Result<(), String> {
        let directory = scratch("floor")?;
        let script = directory.join("check.py");
        std::fs::write(
            &script,
            concat!(
                "#!/usr/bin/env -S uv run --script\n",
                "# /// script\n",
                "# requires-python = \">=3.12\"\n",
                "# dependencies = []\n",
                "# ///\n",
            ),
        )
        .map_err(|error| error.to_string())?;
        let floor = super::declared_python_floor(&script);
        remove(&directory)?;
        if floor.as_deref() == Some(">=3.12") {
            Ok(())
        } else {
            Err(format!("expected the declared floor, read {floor:?}"))
        }
    }

    #[test]
    fn a_script_without_a_declared_floor_is_reported_rather_than_assumed() -> Result<(), String> {
        let directory = scratch("nofloor")?;
        std::fs::write(directory.join("check.py"), b"print('no metadata block')\n")
            .map_err(|error| error.to_string())?;
        let outcome = super::require_python_interpreter(&directory, Path::new("check.py"));
        remove(&directory)?;
        match outcome {
            Ok(()) => Err("a script with no declared floor must be refused".to_owned()),
            Err(refusal) if refusal.contains("declares no requires-python") => Ok(()),
            Err(refusal) => Err(format!("refusal must name the cause: {refusal}")),
        }
    }

    #[test]
    fn the_repository_script_declares_the_floor_the_gate_checks() -> Result<(), String> {
        let root = crate::workspace_root()?;
        let floor = super::declared_python_floor(&root.join("tools/check.py"));
        if floor.is_some() {
            Ok(())
        } else {
            Err("tools/check.py must declare requires-python for the gate to \
                 report a floor a contributor can act on"
                .to_owned())
        }
    }
}
