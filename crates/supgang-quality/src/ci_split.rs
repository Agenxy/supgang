//! CI-specific split quality gates that partition work across parallel jobs
//! without weakening or skipping any check.

use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use serde_json::Value;

use super::{acceptance, packaged_deps, policy, run_cargo, run_cargo_with_env, test_scratch};

const MAX_METADATA_BYTES: usize = 2 * 1024 * 1024;
const MAX_TEST_LIST_BYTES: usize = 2 * 1024 * 1024;
const CLI_PACKAGE: &str = "supgang";
const CORE_PACKAGE: &str = "supgang-core";
const KDF_KAT_TEST_TARGET: &str = "lms_kdf_kat";
const KDF_KAT_SOURCE: &str = "crates/supgang-cli/tests/lms_kdf_kat.rs";
const LMS_CEREMONY_VERIFY_TEST: &str = "cli_lms_verify::tests::ceremony_file_verifies_and_wrong_inputs_refuse";
const SCENARIO_TEST_FILTER: &str = "service::tests::scenarios::";

/// Runs policy and Rust documentation checks for docs-only pull requests.
pub fn run_docs(root: &Path, output: &mut dyn Write, error: &mut dyn Write) -> Result<(), String> {
    policy(root)?;
    run_cargo_with_env(
        root,
        &["doc", "--workspace", "--no-deps", "--locked"],
        &[("RUSTDOCFLAGS", "-D warnings")],
        output,
        error,
    )?;
    writeln!(output, "Supgang docs quality gates passed.").map_err(|write_error| write_error.to_string())
}

/// Runs the core CI gate: policy, format, check, clippy, non-split workspace
/// tests (in a single `cargo test` invocation), rustdoc, and Python helper
/// regressions.
///
/// Paired with [`run_ci_heavy`] and [`run_ci_package`] on the same runner OS so
/// the union of all three jobs covers every check in `all` plus the release
/// build and packaged-deps gate.
pub fn run_ci_core(root: &Path, output: &mut dyn Write, error: &mut dyn Write) -> Result<(), String> {
    policy(root)?;
    let metadata = workspace_metadata(root)?;
    let packages = workspace_package_names(&metadata)?;
    let kat_tests = kdf_kat_test_names(root)?;

    // Format per workspace package so `cargo fmt --all` does not traverse
    // excluded third_party path dependencies.
    for package in &packages {
        run_cargo(root, &["fmt", "--package", package, "--", "--check"], output, error)?;
    }

    run_cargo(
        root,
        &["check", "--workspace", "--all-targets", "--locked"],
        output,
        error,
    )?;
    run_cargo(
        root,
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
    let test_env = scratch.as_deref().map_or_else(Vec::new, |dir| vec![("TMPDIR", dir)]);

    let mut test_args = vec![
        "test",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "--skip",
        SCENARIO_TEST_FILTER,
        "--skip",
        LMS_CEREMONY_VERIFY_TEST,
    ];
    for kat_name in &kat_tests {
        test_args.push("--skip");
        test_args.push(kat_name.as_str());
    }
    run_cargo_with_env(root, &test_args, &test_env, output, error)?;

    run_cargo_with_env(
        root,
        &["doc", "--workspace", "--no-deps", "--locked"],
        &[("RUSTDOCFLAGS", "-D warnings")],
        output,
        error,
    )?;

    acceptance::run_python_suite(root, output)?;

    writeln!(output, "Supgang CI core quality gates passed.").map_err(|write_error| write_error.to_string())
}

/// Runs the heavy CI split partner on the same runner OS:
/// - the H20 KDF known-answer test in release mode (`lms_kdf_kat`);
/// - the LMS ceremony verification test (`cli_lms_verify::tests::ceremony_file_verifies_and_wrong_inputs_refuse`);
/// - the simulated-network scenario tests (`service::tests::scenarios::`);
/// - release workspace build and CLI smoke test.
pub fn run_ci_heavy(root: &Path, output: &mut dyn Write, error: &mut dyn Write) -> Result<(), String> {
    let scratch = test_scratch()?;
    let test_env = scratch.as_deref().map_or_else(Vec::new, |dir| vec![("TMPDIR", dir)]);

    run_cargo_with_env(
        root,
        &[
            "test",
            "--locked",
            "--package",
            CLI_PACKAGE,
            "--test",
            KDF_KAT_TEST_TARGET,
            "--release",
        ],
        &test_env,
        output,
        error,
    )?;

    run_cargo(root, &["build", "--locked", "--workspace", "--release"], output, error)?;
    run_cargo(
        root,
        &[
            "run",
            "--locked",
            "--package",
            CLI_PACKAGE,
            "--release",
            "--",
            "--version",
        ],
        output,
        error,
    )?;

    let ceremony_matched = count_matching_core_tests(root, LMS_CEREMONY_VERIFY_TEST, &test_env)?;
    if ceremony_matched != 1 {
        return Err(format!(
            "LMS ceremony verify filter {LMS_CEREMONY_VERIFY_TEST:?} matched {ceremony_matched} test(s) in {CORE_PACKAGE}, expected 1"
        ));
    }
    writeln!(
        output,
        "Running {ceremony_matched} split LMS ceremony verify test in {CORE_PACKAGE}."
    )
    .map_err(|write_error| write_error.to_string())?;
    run_cargo_with_env(
        root,
        &[
            "test",
            "--locked",
            "--package",
            CORE_PACKAGE,
            "--lib",
            "--",
            "--exact",
            LMS_CEREMONY_VERIFY_TEST,
        ],
        &test_env,
        output,
        error,
    )?;

    let matched = count_matching_core_tests(root, SCENARIO_TEST_FILTER, &test_env)?;
    if matched == 0 {
        return Err(format!(
            "scenario test filter {SCENARIO_TEST_FILTER:?} matched zero tests in {CORE_PACKAGE}"
        ));
    }
    writeln!(output, "Running {matched} split scenario tests in {CORE_PACKAGE}.")
        .map_err(|write_error| write_error.to_string())?;
    run_cargo_with_env(
        root,
        &[
            "test",
            "--locked",
            "--package",
            CORE_PACKAGE,
            "--lib",
            "--",
            SCENARIO_TEST_FILTER,
        ],
        &test_env,
        output,
        error,
    )?;

    writeln!(output, "Supgang CI heavy quality gates passed.").map_err(|write_error| write_error.to_string())
}

/// Runs isolated packaging verification and the multi-target rehearsal
/// dependency graph check in parallel with `ci-core` and `ci-heavy`.
pub fn run_ci_package(root: &Path, output: &mut dyn Write, error: &mut dyn Write) -> Result<(), String> {
    packaged_deps::verify_packaged_workspace(root, output, error)?;
    packaged_deps::check_rehearsal_graph(root, output, error)?;
    writeln!(output, "Supgang CI package verification passed.").map_err(|write_error| write_error.to_string())
}

fn workspace_metadata(root: &Path) -> Result<Value, String> {
    let output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1", "--locked"])
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .map_err(|command_error| format!("could not run cargo metadata: {command_error}"))?;
    if !output.status.success() {
        return Err("cargo metadata failed while preparing CI split".to_owned());
    }
    if output.stdout.len() > MAX_METADATA_BYTES {
        return Err("cargo metadata exceeded size bound".to_owned());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|parse_error| format!("cargo metadata JSON is invalid: {parse_error}"))
}

fn workspace_package_names(metadata: &Value) -> Result<Vec<String>, String> {
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| "cargo metadata is missing packages".to_owned())?;
    let mut names = Vec::with_capacity(packages.len());
    for package in packages {
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "workspace package is missing a name".to_owned())?;
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

fn kdf_kat_test_names(root: &Path) -> Result<Vec<String>, String> {
    let source = fs::read_to_string(root.join(KDF_KAT_SOURCE))
        .map_err(|read_error| format!("could not read {KDF_KAT_SOURCE}: {read_error}"))?;
    let parsed =
        syn::parse_file(&source).map_err(|parse_error| format!("could not parse {KDF_KAT_SOURCE}: {parse_error}"))?;
    let mut names = Vec::new();
    for item in parsed.items {
        if let syn::Item::Fn(function) = item
            && function.attrs.iter().any(|attr| attr.path().is_ident("test"))
        {
            names.push(function.sig.ident.to_string());
        }
    }
    if names.is_empty() {
        return Err(format!("{KDF_KAT_SOURCE} contains no #[test] functions"));
    }
    names.sort();
    Ok(names)
}

fn count_matching_core_tests(root: &Path, filter: &str, environment: &[(&str, &str)]) -> Result<usize, String> {
    let output = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "--package",
            CORE_PACKAGE,
            "--lib",
            "--",
            filter,
            "--list",
        ])
        .envs(environment.iter().copied())
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .map_err(|command_error| format!("could not list {CORE_PACKAGE} tests: {command_error}"))?;
    if !output.status.success() {
        return Err(format!("could not list {CORE_PACKAGE} tests for filter {filter:?}"));
    }
    if output.stdout.len() > MAX_TEST_LIST_BYTES {
        return Err("cargo test --list output exceeded size bound".to_owned());
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|utf8_error| format!("cargo test --list output is not UTF-8: {utf8_error}"))?;
    Ok(text.lines().filter(|line| line.ends_with(": test")).count())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::{KDF_KAT_SOURCE, kdf_kat_test_names, workspace_metadata, workspace_package_names};
    use crate::workspace_root;

    const LMS_CEREMONY_VERIFY_FN: &str = "ceremony_file_verifies_and_wrong_inputs_refuse";
    const LMS_CEREMONY_VERIFY_SOURCE: &str = "crates/supgang/src/cli_lms_verify.rs";

    fn collect_rust_sources(directory: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<(), String> {
        for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path.is_dir() {
                collect_rust_sources(&path, out)?;
            } else if path.extension().and_then(std::ffi::OsStr::to_str) == Some("rs") {
                out.push(path);
            }
        }
        Ok(())
    }

    #[test]
    fn kdf_kat_test_names_are_present_and_unique_in_workspace() -> Result<(), String> {
        let root = workspace_root()?;
        let metadata = workspace_metadata(&root)?;
        let packages = workspace_package_names(&metadata)?;
        if !packages.iter().any(|name| name == "supgang") || !packages.iter().any(|name| name == "supgang-core") {
            return Err(format!("unexpected workspace packages: {packages:?}"));
        }
        let kat_names = kdf_kat_test_names(&root)?;
        let mut sources = Vec::new();
        collect_rust_sources(&root.join("crates"), &mut sources)?;
        let kat_path = root.join(KDF_KAT_SOURCE);
        for path in sources {
            if path == kat_path {
                continue;
            }
            let text = fs::read_to_string(&path).map_err(|error| error.to_string())?;
            for name in &kat_names {
                if text.contains(name) {
                    return Err(format!(
                        "KDF KAT test name {name:?} also appears in {}, which would over-skip in ci-core",
                        path.display()
                    ));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn lms_ceremony_verify_test_is_present_and_unique_in_workspace() -> Result<(), String> {
        let root = workspace_root()?;
        let verify_path = root.join(LMS_CEREMONY_VERIFY_SOURCE);
        let verify_text = fs::read_to_string(&verify_path)
            .map_err(|error| format!("could not read {}: {error}", verify_path.display()))?;
        if !verify_text.contains(&format!("fn {LMS_CEREMONY_VERIFY_FN}(")) {
            return Err(format!(
                "expected test function {LMS_CEREMONY_VERIFY_FN:?} in {}",
                verify_path.display()
            ));
        }
        let mut sources = Vec::new();
        collect_rust_sources(&root.join("crates"), &mut sources)?;
        for path in sources {
            if path == verify_path || path == root.join("crates/supgang-quality/src/ci_split.rs") {
                continue;
            }
            let text = fs::read_to_string(&path).map_err(|error| error.to_string())?;
            if text.contains(LMS_CEREMONY_VERIFY_FN) {
                return Err(format!(
                    "LMS ceremony verify test {LMS_CEREMONY_VERIFY_FN:?} also appears in {}, which would over-skip in ci-core",
                    path.display()
                ));
            }
        }
        Ok(())
    }
}
