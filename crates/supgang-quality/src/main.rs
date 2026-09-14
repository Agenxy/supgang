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
            let scratch = test_scratch()?;
            let test_environment: Vec<(&str, &str)> =
                scratch.iter().map(|directory| ("TMPDIR", directory.as_str())).collect();
            run_cargo_with_env(
                &root,
                &["test", "--workspace", "--all-targets", "--locked"],
                &test_environment,
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

/// Where the test suites put their temporary state.
///
/// Storage refuses any ancestor that other users can write, which is the
/// point of it, and on Linux the default temporary directory is exactly that:
/// `/tmp` is world-writable with the sticky bit. Every test that touches
/// state then fails with `UnsafeAncestor` before testing anything, which is
/// what the hosted Linux runner reported. `$HOME/.cache` is the user's own,
/// so the tests exercise the rule there instead of tripping on it.
///
/// macOS is left alone: its per-user temporary directory under `/var/folders`
/// is already owner-only, and the checkout is not a safe alternative there,
/// because `~/Desktop` carries a sharing ACL the storage rules reject.
fn test_scratch() -> Result<Option<String>, String> {
    if cfg!(target_os = "macos") {
        return Ok(None);
    }
    let home = env::var_os("HOME").ok_or_else(|| "HOME is not set".to_owned())?;
    let scratch = PathBuf::from(home).join(".cache").join("supgang").join("test-tmp");
    fs::create_dir_all(&scratch)
        .map_err(|create_error| format!("could not create {}: {create_error}", scratch.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700))
            .map_err(|mode_error| format!("could not restrict {}: {mode_error}", scratch.display()))?;
    }
    scratch
        .into_os_string()
        .into_string()
        .map(Some)
        .map_err(|_| "the home path is not valid Unicode".to_owned())
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
        "Makefile",
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
    inspect_install_policy(root)?;
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
        let contains_unsafe =
            text.contains(&unsafe_block) || text.contains(&unsafe_function) || text.contains(&unsafe_implementation);
        let relative = display(root, path);
        let is_acl_boundary = relative == "crates/supgang-acl/src/lib.rs";
        if contains_unsafe && !is_acl_boundary {
            return Err(format!("portable Supgang source contains unsafe Rust: {relative}"));
        }
        if is_acl_boundary {
            for required in [
                "#![deny(missing_docs, unsafe_op_in_unsafe_fn, warnings)]",
                "//! Small safe boundary around platform descriptor-based ACL APIs.",
            ] {
                if !text.contains(required) {
                    return Err(format!("ACL boundary is missing required safety policy {required:?}"));
                }
            }
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
        "supgang-core = { path = \"../supgang\", version = \"=0.2.0-alpha.10\" }",
    ] {
        if !command.contains(required) {
            return Err(format!("command package identity is missing: {required}"));
        }
    }
    Ok(())
}

fn inspect_duplicate_dependencies(root: &Path) -> Result<(), String> {
    let lockfile = fs::read_to_string(root.join("Cargo.lock")).map_err(|read_error| read_error.to_string())?;
    let identities = lock_identities(&lockfile)?;
    for (name, _, _) in &identities {
        let matching = identities
            .iter()
            .filter(|(candidate, _, _)| candidate == name)
            .collect::<Vec<_>>();
        if matching.len() < 2 {
            continue;
        }
        for (duplicate, version, source) in matching {
            let identity = format!("{duplicate}@{version}");
            if source != "registry+https://github.com/rust-lang/crates.io-index"
                || !REVIEWED_DUPLICATE_IDENTITIES.contains(&identity.as_str())
            {
                return Err(format!(
                    "duplicate dependency identity lacks a reviewed exception: {identity} from {source}"
                ));
            }
        }
    }
    Ok(())
}

const REVIEWED_DUPLICATE_IDENTITIES: &[&str] = &[
    "bitflags@1.3.2",
    "bitflags@2.13.1",
    "getrandom@0.2.17",
    "getrandom@0.3.4",
    "getrandom@0.4.3",
    "jni-sys@0.3.1",
    "jni-sys@0.4.1",
    "r-efi@5.3.0",
    "r-efi@6.0.0",
    "rand@0.9.5",
    "rand@0.10.2",
    "rand_core@0.9.5",
    "rand_core@0.10.1",
    "syn@2.0.119",
    "syn@3.0.3",
    "thiserror@1.0.69",
    "thiserror@2.0.20",
    "thiserror-impl@1.0.69",
    "thiserror-impl@2.0.20",
    "untrusted@0.7.1",
    "untrusted@0.9.0",
    "windows-sys@0.45.0",
    "windows-sys@0.52.0",
    "windows-sys@0.61.2",
    "windows-targets@0.42.2",
    "windows-targets@0.52.6",
    "windows_aarch64_gnullvm@0.42.2",
    "windows_aarch64_gnullvm@0.52.6",
    "windows_aarch64_msvc@0.42.2",
    "windows_aarch64_msvc@0.52.6",
    "windows_i686_gnu@0.42.2",
    "windows_i686_gnu@0.52.6",
    "windows_i686_msvc@0.42.2",
    "windows_i686_msvc@0.52.6",
    "windows_x86_64_gnu@0.42.2",
    "windows_x86_64_gnu@0.52.6",
    "windows_x86_64_gnullvm@0.42.2",
    "windows_x86_64_gnullvm@0.52.6",
    "windows_x86_64_msvc@0.42.2",
    "windows_x86_64_msvc@0.52.6",
];

fn lock_identities(lockfile: &str) -> Result<Vec<(String, String, String)>, String> {
    let mut identities = Vec::new();
    for package in lockfile.split("[[package]]").skip(1) {
        let value = |key: &str| {
            package.lines().find_map(|line| {
                line.strip_prefix(key)
                    .and_then(|value| value.strip_suffix('"'))
                    .map(str::to_owned)
            })
        };
        let name = value("name = \"").ok_or_else(|| "Cargo.lock package is missing a name".to_owned())?;
        let version = value("version = \"").ok_or_else(|| format!("Cargo.lock package {name} is missing a version"))?;
        let source = value("source = \"").unwrap_or_else(|| "workspace".to_owned());
        identities.push((name, version, source));
    }
    Ok(identities)
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

fn inspect_install_policy(root: &Path) -> Result<(), String> {
    let makefile = fs::read_to_string(root.join("Makefile")).map_err(|read_error| read_error.to_string())?;
    for required in [
        "INSTALL_ROOT ?= $(HOME)/.local",
        "--frozen --force --root \"$(INSTALL_ROOT)\" --path crates/supgang-cli",
        "\"$(INSTALL_BIN)\" --version",
    ] {
        if !makefile.contains(required) {
            return Err(format!(
                "local install policy is missing required constraint: {required}"
            ));
        }
    }
    Ok(())
}

fn inspect_ci(root: &Path) -> Result<(), String> {
    for entry in fs::read_dir(root.join(".github/workflows")).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        if !matches!(path.extension().and_then(OsStr::to_str), Some("yml" | "yaml")) {
            continue;
        }
        let workflow = fs::read_to_string(&path).map_err(|read_error| read_error.to_string())?;
        if workflow.contains("pull_request_target:") || workflow.contains("permissions: write-all") {
            return Err(format!(
                "{} contains a privileged trigger or broad write permission",
                display(root, &path)
            ));
        }
        for line in workflow.lines().map(str::trim) {
            let Some(reference) = line.strip_prefix("uses:").map(str::trim) else {
                continue;
            };
            let Some((action, revision)) = reference.split_once('@') else {
                return Err(format!("workflow action is missing an immutable revision: {reference}"));
            };
            let revision = revision.split_ascii_whitespace().next().unwrap_or_default();
            if action.is_empty() || revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!("workflow action is not pinned to a full commit: {reference}"));
            }
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
