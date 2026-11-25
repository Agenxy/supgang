//! CI-specific split quality gates that partition work across parallel jobs
//! without weakening or skipping any check.

use std::{
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

/// Runs the core CI gate: policy, format, check, clippy, non-split tests,
/// rustdoc, Python helper regressions, and packaged dependency graph checks.
///
/// Paired with [`run_ci_heavy`] on the same runner OS so the union of both jobs
/// covers every check in `all` plus the release build and packaged-deps gate.
pub fn run_ci_core(root: &Path, output: &mut dyn Write, error: &mut dyn Write) -> Result<(), String> {
    policy(root)?;
    let metadata = workspace_metadata(root)?;
    let packages = workspace_package_names(&metadata)?;
    let non_kat_tests = cli_non_kat_test_targets(&metadata)?;

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

    let mut cli_args = vec!["test", "--locked", "--package", CLI_PACKAGE, "--bins", "--examples"];
    for target in &non_kat_tests {
        cli_args.push("--test");
        cli_args.push(target.as_str());
    }
    run_cargo_with_env(root, &cli_args, &test_env, output, error)?;

    // Ensure target/debug/supgang is built for tools/test_lms_hidden_prompt.py.
    run_cargo(root, &["build", "--locked", "--package", CLI_PACKAGE], output, error)?;

    run_cargo_with_env(
        root,
        &[
            "test",
            "--locked",
            "--workspace",
            "--exclude",
            CLI_PACKAGE,
            "--all-targets",
            "--",
            "--skip",
            SCENARIO_TEST_FILTER,
        ],
        &test_env,
        output,
        error,
    )?;

    run_cargo_with_env(
        root,
        &["doc", "--workspace", "--no-deps", "--locked"],
        &[("RUSTDOCFLAGS", "-D warnings")],
        output,
        error,
    )?;

    acceptance::run_python_suite(root, output)?;
    packaged_deps::check_rehearsal_graph(root, output, error)?;

    writeln!(output, "Supgang CI core quality gates passed.").map_err(|write_error| write_error.to_string())
}

/// Runs the heavy CI split partner on the same runner OS:
/// - the H20 KDF known-answer test in release mode (`lms_kdf_kat`);
/// - the simulated-network scenario tests (`service::tests::scenarios::`);
/// - isolated `cargo package` build verification of all publishable crates;
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

    packaged_deps::verify_packaged_workspace(root, output, error)?;

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

    writeln!(output, "Supgang CI heavy quality gates passed.").map_err(|write_error| write_error.to_string())
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

fn cli_non_kat_test_targets(metadata: &Value) -> Result<Vec<String>, String> {
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| "cargo metadata is missing packages".to_owned())?;
    let cli = packages
        .iter()
        .find(|package| package.get("name").and_then(Value::as_str) == Some(CLI_PACKAGE))
        .ok_or_else(|| format!("workspace package {CLI_PACKAGE} not found in cargo metadata"))?;
    let targets = cli
        .get("targets")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("package {CLI_PACKAGE} is missing targets"))?;

    let mut saw_kat = false;
    let mut others = Vec::new();
    for target in targets {
        let is_integration_test = target
            .get("kind")
            .and_then(Value::as_array)
            .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("test")));
        if !is_integration_test {
            continue;
        }
        let name = target
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("integration test target in {CLI_PACKAGE} is missing a name"))?;
        if name == KDF_KAT_TEST_TARGET {
            saw_kat = true;
        } else {
            others.push(name.to_owned());
        }
    }
    if !saw_kat {
        return Err(format!(
            "expected split integration test target {KDF_KAT_TEST_TARGET:?} was not found in {CLI_PACKAGE}"
        ));
    }
    others.sort();
    Ok(others)
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
    use super::{KDF_KAT_TEST_TARGET, cli_non_kat_test_targets, workspace_metadata, workspace_package_names};
    use crate::workspace_root;

    #[test]
    fn cli_test_partition_excludes_only_lms_kdf_kat() -> Result<(), String> {
        let metadata = workspace_metadata(&workspace_root()?)?;
        let packages = workspace_package_names(&metadata)?;
        if !packages.iter().any(|name| name == "supgang") || !packages.iter().any(|name| name == "supgang-core") {
            return Err(format!("unexpected workspace packages: {packages:?}"));
        }
        let non_kat = cli_non_kat_test_targets(&metadata)?;
        if non_kat.iter().any(|name| name == KDF_KAT_TEST_TARGET) {
            return Err(format!("{KDF_KAT_TEST_TARGET} must be excluded from core CLI tests"));
        }
        if non_kat.is_empty() {
            return Err("expected at least one non-KAT integration test target in supgang".to_owned());
        }
        Ok(())
    }
}
