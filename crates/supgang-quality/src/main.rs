//! Typed, shell-free repository quality gates.

use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

const EXIT_FAILURE: u8 = 1;
const MAX_SOURCE_LINES: usize = 700;
const MAX_TEXT_BYTES: u64 = 256 * 1024;

fn main() -> ExitCode {
    let mut output = io::stdout().lock();
    let mut error = io::stderr().lock();
    match execute(env::args_os().nth(1).as_deref(), &mut output, &mut error) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let _write_result = writeln!(error, "quality gate failed: {message}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

fn execute(mode: Option<&OsStr>, output: &mut dyn Write, error: &mut dyn Write) -> Result<(), String> {
    let root = workspace_root()?;
    match mode.and_then(OsStr::to_str) {
        Some("all") => {
            policy(&root)?;
            run_cargo(&root, &["fmt", "--all", "--", "--check"], output, error)?;
            run_cargo(
                &root,
                &["check", "--workspace", "--all-targets", "--locked"],
                output,
                error,
            )?;
            run_cargo(
                &root,
                &[
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--all-features",
                    "--locked",
                    "--",
                    "-D",
                    "warnings",
                ],
                output,
                error,
            )?;
            run_cargo(
                &root,
                &["test", "--workspace", "--all-targets", "--locked"],
                output,
                error,
            )?;
            run_cargo_with_env(
                &root,
                &["doc", "--workspace", "--no-deps", "--locked"],
                &[("RUSTDOCFLAGS", "-D warnings")],
                output,
                error,
            )?;
            writeln!(output, "Supgang quality gates passed.").map_err(|write_error| write_error.to_string())?;
            Ok(())
        }
        Some("quick") => {
            policy(&root)?;
            run_cargo(
                &root,
                &["check", "--workspace", "--all-targets", "--locked"],
                output,
                error,
            )
        }
        Some("policy") => {
            policy(&root)?;
            writeln!(output, "Supgang repository policy passed.").map_err(|write_error| write_error.to_string())
        }
        _ => Err("usage: cargo run --locked --package supgang-quality -- all|quick|policy".to_owned()),
    }
}

fn run_cargo(root: &Path, arguments: &[&str], output: &mut dyn Write, error: &mut dyn Write) -> Result<(), String> {
    run_cargo_with_env(root, arguments, &[], output, error)
}

fn run_cargo_with_env(
    root: &Path,
    arguments: &[&str],
    environment: &[(&str, &str)],
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<(), String> {
    writeln!(output, "Running: cargo {}", arguments.join(" ")).map_err(|write_error| write_error.to_string())?;
    let status = Command::new("cargo")
        .args(arguments)
        .envs(environment.iter().copied())
        .current_dir(root)
        .stdin(Stdio::null())
        .status()
        .map_err(|command_error| format!("could not start cargo: {command_error}"))?;
    if status.success() {
        Ok(())
    } else {
        let _write_result = writeln!(error, "cargo {} returned {status}", arguments.join(" "));
        Err(format!("cargo {} did not pass", arguments.join(" ")))
    }
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "could not locate the workspace root".to_owned())
}

fn policy(root: &Path) -> Result<(), String> {
    for required in [
        "AGENTS.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        ".github/workflows/ci.yml",
        "Cargo.lock",
        "Cargo.toml",
        "crates/supgang/LICENSE",
        "crates/supgang-cli/LICENSE",
        "deny.toml",
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "docs/architecture/0001-sovereign-address-plane.md",
        "docs/security/dependency-exceptions.md",
        "docs/security/threat-model.md",
    ] {
        if !root.join(required).is_file() {
            return Err(format!("required repository file is missing: {required}"));
        }
    }
    let license = fs::read_to_string(root.join("LICENSE")).map_err(|read_error| read_error.to_string())?;
    if !license.starts_with(
        "                                 Apache License\n                           Version 2.0, January 2004",
    ) {
        return Err("LICENSE is not the canonical Apache License 2.0 text".to_owned());
    }
    inspect_tree(root, root)?;
    inspect_workspace_dependencies(root)?;
    inspect_package_identity(root)?;
    inspect_duplicate_dependencies(root)?;
    inspect_dependency_policy(root)?;
    inspect_ci(root)?;
    Ok(())
}

fn inspect_tree(root: &Path, directory: &Path) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|read_error| format!("could not inspect {}: {read_error}", display(root, directory)))?;
    for entry in entries {
        let entry = entry.map_err(|read_error| read_error.to_string())?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|read_error| read_error.to_string())?;
        if file_type.is_symlink() {
            return Err(format!(
                "repository symlink requires explicit review: {}",
                display(root, &path)
            ));
        }
        if file_type.is_dir() {
            if matches!(entry.file_name().to_str(), Some(".git" | "target")) {
                continue;
            }
            inspect_tree(root, &path)?;
        } else if file_type.is_file() {
            inspect_file(root, &path)?;
        } else {
            return Err(format!(
                "special filesystem entry is not allowed: {}",
                display(root, &path)
            ));
        }
    }
    Ok(())
}

fn inspect_file(root: &Path, path: &Path) -> Result<(), String> {
    if matches!(path.extension().and_then(OsStr::to_str), Some("sh" | "bash" | "zsh")) {
        return Err(format!("shell program is not allowed: {}", display(root, path)));
    }
    let extension = path.extension().and_then(OsStr::to_str);
    if !matches!(extension, Some("rs" | "toml" | "md" | "json") | None) {
        return Ok(());
    }
    let metadata = fs::metadata(path).map_err(|read_error| read_error.to_string())?;
    if metadata.len() > MAX_TEXT_BYTES {
        return Err(format!("text file exceeds 256 KiB: {}", display(root, path)));
    }
    let text =
        fs::read_to_string(path).map_err(|read_error| format!("{} is not UTF-8: {read_error}", display(root, path)))?;
    for forbidden in ["TO\x44O", "FIX\x4dE", "Bea\x63on", "bea\x63on", "\u{2014}"] {
        if text.contains(forbidden) {
            return Err(format!("{} contains forbidden text {forbidden:?}", display(root, path)));
        }
    }
    if extension == Some("rs") {
        let lines = text.lines().count();
        if lines > MAX_SOURCE_LINES {
            return Err(format!(
                "Rust source exceeds {MAX_SOURCE_LINES} lines: {} has {lines}",
                display(root, path)
            ));
        }
        let unsafe_block = ["unsafe", " {"].concat();
        let unsafe_function = ["unsafe", " fn"].concat();
        let unsafe_implementation = ["unsafe", " impl"].concat();
        if text.contains(&unsafe_block) || text.contains(&unsafe_function) || text.contains(&unsafe_implementation) {
            return Err(format!(
                "portable Supgang source contains unsafe Rust: {}",
                display(root, path)
            ));
        }
    }
    Ok(())
}

fn inspect_workspace_dependencies(root: &Path) -> Result<(), String> {
    let manifest = fs::read_to_string(root.join("Cargo.toml")).map_err(|read_error| read_error.to_string())?;
    let dependencies = manifest
        .split_once("[workspace.dependencies]")
        .and_then(|(_, rest)| rest.split_once("[workspace.lints.rust").map(|(section, _)| section))
        .ok_or_else(|| "workspace dependency section is missing or malformed".to_owned())?;
    for line in dependencies.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if line.contains("git =") {
            return Err(format!("git dependency is not allowed: {line}"));
        }
        if line.contains("version =") && !line.contains("version = \"=") {
            return Err(format!("direct dependency is not exactly pinned: {line}"));
        }
    }
    Ok(())
}

fn inspect_package_identity(root: &Path) -> Result<(), String> {
    let root_license = fs::read_to_string(root.join("LICENSE")).map_err(|read_error| read_error.to_string())?;
    for packaged_license in ["crates/supgang/LICENSE", "crates/supgang-cli/LICENSE"] {
        let packaged = fs::read_to_string(root.join(packaged_license)).map_err(|read_error| read_error.to_string())?;
        if packaged != root_license {
            return Err(format!(
                "packaged licence differs from root LICENSE: {packaged_license}"
            ));
        }
    }

    let core =
        fs::read_to_string(root.join("crates/supgang/Cargo.toml")).map_err(|read_error| read_error.to_string())?;
    for required in [
        "name = \"supgang-core\"",
        "publish = [\"crates-io\"]",
        "name = \"supgang_core\"",
    ] {
        if !core.contains(required) {
            return Err(format!("core package identity is missing: {required}"));
        }
    }

    let command =
        fs::read_to_string(root.join("crates/supgang-cli/Cargo.toml")).map_err(|read_error| read_error.to_string())?;
    for required in [
        "name = \"supgang\"",
        "publish = [\"crates-io\"]",
        "name = \"supgang\"\npath = \"src/main.rs\"",
        "supgang-core = { path = \"../supgang\", version = \"=0.1.0\" }",
    ] {
        if !command.contains(required) {
            return Err(format!("command package identity is missing: {required}"));
        }
    }
    Ok(())
}

fn inspect_duplicate_dependencies(root: &Path) -> Result<(), String> {
    let lockfile = fs::read_to_string(root.join("Cargo.lock")).map_err(|read_error| read_error.to_string())?;
    let mut names = Vec::new();
    for line in lockfile.lines() {
        let Some(name) = line.strip_prefix("name = \"").and_then(|value| value.strip_suffix('"')) else {
            continue;
        };
        if names.contains(&name) {
            if !matches!(
                name,
                "getrandom" | "r-efi" | "rand" | "rand_core" | "syn" | "untrusted" | "windows-sys"
            ) {
                return Err(format!("duplicate dependency lacks a reviewed exception: {name}"));
            }
        } else {
            names.push(name);
        }
    }
    Ok(())
}

fn inspect_dependency_policy(root: &Path) -> Result<(), String> {
    let policy = fs::read_to_string(root.join("deny.toml")).map_err(|read_error| read_error.to_string())?;
    for required in [
        "all-features = true",
        "unknown-registry = \"deny\"",
        "unknown-git = \"deny\"",
        "allow-registry = [\"https://github.com/rust-lang/crates.io-index\"]",
        "allow-git = []",
    ] {
        if !policy.contains(required) {
            return Err(format!("dependency policy is missing required constraint: {required}"));
        }
    }
    Ok(())
}

fn inspect_ci(root: &Path) -> Result<(), String> {
    let workflow =
        fs::read_to_string(root.join(".github/workflows/ci.yml")).map_err(|read_error| read_error.to_string())?;
    if workflow.contains("pull_request_target:") || workflow.contains("permissions: write-all") {
        return Err("CI contains a privileged trigger or broad write permission".to_owned());
    }
    for line in workflow.lines().map(str::trim) {
        let Some(reference) = line.strip_prefix("uses:").map(str::trim) else {
            continue;
        };
        let Some((action, revision)) = reference.split_once('@') else {
            return Err(format!("CI action is missing an immutable revision: {reference}"));
        };
        let revision = revision.split_ascii_whitespace().next().unwrap_or_default();
        if action.is_empty() || revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("CI action is not pinned to a full commit: {reference}"));
        }
    }
    Ok(())
}

fn display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).display().to_string()
}

#[cfg(test)]
mod tests {
    use super::{policy, workspace_root};

    #[test]
    fn repository_policy_passes_its_own_tree() -> Result<(), String> {
        policy(&workspace_root()?)
    }
}
