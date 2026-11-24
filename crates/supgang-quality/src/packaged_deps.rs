//! Packaged-crate verification and multi-target rehearsal dependency graph gate.
//!
//! Cargo does not carry workspace `[patch.crates-io]` entries into published
//! `.crate` archives. This module packages every publishable crate, unpacks the
//! exact `.crate` archives into an isolated workspace with no `[patch]`, and
//! resolves the dependency graph for every supported target to verify that no
//! forbidden or stale dependency (`chrono`, `paste`, upstream `netwatch`,
//! upstream `portmapper`, `netlink-packet-core <0.9`, or duplicate netwatch)
//! can enter a published release.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_REGISTRY_ENTRIES: usize = 64;
const MAX_STAGE_FILES: usize = 4_096;
const PUBLISHED_CRATES: &[&str] = &[
    "supgang-netwatch",
    "supgang-portmapper",
    "supgang-acl",
    "supgang-core",
    "supgang",
];

/// Every target triple verified during release rehearsal.
pub const SUPPORTED_TARGETS: &[&str] = &[
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "riscv64gc-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
];

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Packages and compiles every publishable crate in an isolated per-run workspace.
pub fn verify_packaged_workspace(root: &Path, output: &mut dyn Write, error: &mut dyn Write) -> Result<(), String> {
    let run = IsolatedRun::create(&verification_base_dir()?, resolve_host_cargo_home().as_deref())?;
    stage_workspace(root, &run.stage_dir)?;
    let cargo_home = path_to_str(&run.cargo_home)?;
    let target_dir = path_to_str(&run.target_dir)?;
    let mut args = vec!["package", "--allow-dirty"];
    for name in PUBLISHED_CRATES {
        args.push("--package");
        args.push(name);
    }
    super::run_cargo_with_env(
        &run.stage_dir,
        &args,
        &[("CARGO_HOME", cargo_home), ("CARGO_TARGET_DIR", target_dir)],
        output,
        error,
    )
}

/// Packages every publishable crate, unpacks the exact `.crate` archives into an
/// isolated temp workspace with no `[patch]`, and verifies the resolved dependency
/// graph for every supported target.
pub fn check_rehearsal_graph(root: &Path, output: &mut dyn Write, error: &mut dyn Write) -> Result<(), String> {
    let run = IsolatedRun::create(&verification_base_dir()?, resolve_host_cargo_home().as_deref())?;
    stage_workspace(root, &run.stage_dir)?;
    let cargo_home = path_to_str(&run.cargo_home)?;
    let target_dir = path_to_str(&run.target_dir)?;
    let mut args = vec!["package", "--allow-dirty", "--no-verify"];
    for name in PUBLISHED_CRATES {
        args.push("--package");
        args.push(name);
    }
    super::run_cargo_with_env(
        &run.stage_dir,
        &args,
        &[("CARGO_HOME", cargo_home), ("CARGO_TARGET_DIR", target_dir)],
        output,
        error,
    )?;

    let package_dir = run.target_dir.join("package");
    let unpacked_dirs = unpack_archives(&package_dir, &run.unpacked_dir)?;
    build_unpacked_workspace(&run.unpacked_dir, &unpacked_dirs)?;

    let manifest = run.unpacked_dir.join("Cargo.toml");
    let manifest_str = path_to_str(&manifest)?;
    for target in SUPPORTED_TARGETS {
        for all_features in [false, true] {
            let mut tree_args = vec![
                "tree",
                "--manifest-path",
                manifest_str,
                "--package",
                "supgang",
                "--edges",
                "normal,build",
                "--target",
                target,
                "--prefix",
                "none",
                "--format",
                "{p}",
            ];
            if all_features {
                tree_args.push("--all-features");
            }
            let stdout = capture_cargo(
                &run.unpacked_dir,
                &tree_args,
                &[("CARGO_HOME", cargo_home), ("CARGO_TARGET_DIR", target_dir)],
            )?;
            if let Err((offender, reason)) = inspect_resolved_graph(target, &stdout) {
                let why = capture_cargo(
                    &run.unpacked_dir,
                    &[
                        "tree",
                        "--manifest-path",
                        manifest_str,
                        "--package",
                        "supgang",
                        "--target",
                        target,
                        "-i",
                        &offender,
                    ],
                    &[("CARGO_HOME", cargo_home), ("CARGO_TARGET_DIR", target_dir)],
                )
                .unwrap_or_else(|err| format!("(could not run cargo tree -i: {err})"));
                return Err(format!(
                    "{reason}\ninverse dependency tree for {offender} on {target}:\n{why}"
                ));
            }
        }
        writeln!(output, "packaged-deps target={target} status=ok").map_err(|err| err.to_string())?;
    }
    writeln!(
        output,
        "Packaged multi-target dependency rehearsal gate passed ({} targets).",
        SUPPORTED_TARGETS.len()
    )
    .map_err(|err| err.to_string())
}

/// Validates a `cargo tree --prefix none --format "{p}"` output for one target.
///
/// Fails if `chrono`, `paste`, upstream `netwatch`, upstream `portmapper`,
/// `netlink-packet-core <0.9.0`, or duplicate/missing `supgang-netwatch` appear.
pub fn inspect_resolved_graph(target: &str, tree_output: &str) -> Result<(), (String, String)> {
    let mut versions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in tree_output.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let Some(raw_version) = parts.next() else {
            continue;
        };
        let version = raw_version.strip_prefix('v').unwrap_or(raw_version);
        versions.entry(name.to_owned()).or_default().insert(version.to_owned());
    }

    for forbidden in ["chrono", "paste", "netwatch", "portmapper"] {
        if let Some(found) = versions.get(forbidden) {
            return Err((
                forbidden.to_owned(),
                format!("target {target}: forbidden dependency `{forbidden}` resolved in packaged graph ({found:?})"),
            ));
        }
    }

    if let Some(netlink_versions) = versions.get("netlink-packet-core") {
        for version in netlink_versions {
            if is_netlink_below_0_9(version) {
                return Err((
                    format!("netlink-packet-core@{version}"),
                    format!(
                        "target {target}: legacy netlink-packet-core {version} (<0.9.0) resolved in packaged graph"
                    ),
                ));
            }
        }
    }

    match versions.get("supgang-netwatch") {
        None => Err((
            "supgang-netwatch".to_owned(),
            format!("target {target}: expected vendored `supgang-netwatch` was not resolved"),
        )),
        Some(found) if found.len() > 1 => Err((
            "supgang-netwatch".to_owned(),
            format!("target {target}: duplicate `supgang-netwatch` versions resolved ({found:?})"),
        )),
        Some(_) => Ok(()),
    }
}

fn is_netlink_below_0_9(version: &str) -> bool {
    let core = version.split('-').next().unwrap_or(version);
    let mut parts = core.split('.');
    let major = parts.next().and_then(|part| part.parse::<u64>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u64>().ok());
    match (major, minor) {
        (Some(0), Some(minor)) => minor < 9,
        (Some(_), Some(_)) => false,
        _ => true,
    }
}

fn stage_workspace(root: &Path, stage_dir: &Path) -> Result<(), String> {
    let mut remaining = MAX_STAGE_FILES;
    for dir in [
        "third_party/netwatch",
        "third_party/portmapper",
        "crates/supgang-acl",
        "crates/supgang",
        "crates/supgang-cli",
        "crates/supgang-quality",
    ] {
        copy_tree(&root.join(dir), &stage_dir.join(dir), &mut remaining)?;
    }
    for file in ["README.md", "LICENSE", "Cargo.lock"] {
        let source = root.join(file);
        let dest = stage_dir.join(file);
        fs::copy(&source, &dest).map_err(|err| format!("copy {file}: {err}"))?;
    }
    let root_manifest = fs::read_to_string(root.join("Cargo.toml")).map_err(|err| err.to_string())?;
    let staged_manifest = rewrite_root_manifest_for_packaging(&root_manifest)?;
    fs::write(stage_dir.join("Cargo.toml"), staged_manifest).map_err(|err| err.to_string())
}

fn rewrite_root_manifest_for_packaging(manifest: &str) -> Result<String, String> {
    if manifest.contains("[patch.") {
        return Err("root Cargo.toml must not contain [patch.*] sections".to_owned());
    }
    let old_members =
        "members = [\"crates/supgang\", \"crates/supgang-acl\", \"crates/supgang-cli\", \"crates/supgang-quality\"]";
    let new_members = "members = [\"third_party/netwatch\", \"third_party/portmapper\", \"crates/supgang-acl\", \"crates/supgang\", \"crates/supgang-cli\", \"crates/supgang-quality\"]";
    let old_exclude = "exclude = [\"third_party/netwatch\", \"third_party/portmapper\"]\n";
    if manifest.matches(old_members).count() != 1 || manifest.matches(old_exclude).count() != 1 {
        return Err("root Cargo.toml workspace members/exclude layout changed unexpectedly".to_owned());
    }
    Ok(manifest
        .replacen(old_members, new_members, 1)
        .replacen(old_exclude, "", 1))
}

fn unpack_archives(package_dir: &Path, unpacked_dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut found = BTreeMap::new();
    let entries =
        fs::read_dir(package_dir).map_err(|err| format!("could not read {}: {err}", package_dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| err.to_string())?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("crate") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|name| name.to_str()) else {
            continue;
        };
        let status = Command::new("tar")
            .args(["-xzf"])
            .arg(&path)
            .arg("-C")
            .arg(unpacked_dir)
            .stdin(Stdio::null())
            .status()
            .map_err(|err| format!("could not unpack {}: {err}", path.display()))?;
        if !status.success() {
            return Err(format!("tar failed unpacking {} with {status}", path.display()));
        }
        let crate_name = PUBLISHED_CRATES
            .iter()
            .copied()
            .filter(|name| stem.starts_with(&format!("{name}-")))
            .max_by_key(|name| name.len())
            .ok_or_else(|| format!("unexpected packaged archive: {stem}.crate"))?;
        found.insert(crate_name.to_owned(), stem.to_owned());
    }
    for required in PUBLISHED_CRATES {
        if !found.contains_key(*required) {
            return Err(format!("missing packaged archive for `{required}`"));
        }
    }
    Ok(found)
}

fn build_unpacked_workspace(unpacked_dir: &Path, dirs: &BTreeMap<String, String>) -> Result<(), String> {
    for (name, dir_name) in dirs {
        let manifest_path = unpacked_dir.join(dir_name).join("Cargo.toml");
        let text =
            fs::read_to_string(&manifest_path).map_err(|err| format!("read {}: {err}", manifest_path.display()))?;
        if text.contains("[patch.") {
            return Err(format!("packaged `{name}` manifest unexpectedly contains [patch]"));
        }
        let rewritten = rewire_intra_supgang_paths(name, &text, dirs)?;
        fs::write(&manifest_path, rewritten).map_err(|err| format!("write {}: {err}", manifest_path.display()))?;
    }

    let members = PUBLISHED_CRATES
        .iter()
        .map(|name| {
            dirs.get(*name)
                .map(|dir| format!("    \"{dir}\","))
                .ok_or_else(|| format!("missing unpacked dir for {name}"))
        })
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    let workspace_toml = format!("[workspace]\nmembers = [\n{members}\n]\nresolver = \"3\"\n");
    fs::write(unpacked_dir.join("Cargo.toml"), workspace_toml).map_err(|err| err.to_string())
}

/// Rewires only the exact intra-Supgang dependency edges between the five
/// unpacked `.crate` directories so Cargo resolves them without `[patch]`.
/// Every external dependency resolves strictly from crates.io.
fn rewire_intra_supgang_paths(
    crate_name: &str,
    manifest: &str,
    dirs: &BTreeMap<String, String>,
) -> Result<String, String> {
    match crate_name {
        "supgang-portmapper" => {
            let target_dir = dirs
                .get("supgang-netwatch")
                .ok_or_else(|| "missing unpacked supgang-netwatch".to_owned())?;
            inject_path_into_section(
                manifest,
                "[dependencies.netwatch]",
                Some("package = \"supgang-netwatch\""),
                &format!("../{target_dir}"),
            )
        }
        "supgang-core" => {
            let pm_dir = dirs
                .get("supgang-portmapper")
                .ok_or_else(|| "missing unpacked supgang-portmapper".to_owned())?;
            let acl_dir = dirs
                .get("supgang-acl")
                .ok_or_else(|| "missing unpacked supgang-acl".to_owned())?;
            let with_pm = inject_path_into_section(
                manifest,
                "[dependencies.portmapper]",
                Some("package = \"supgang-portmapper\""),
                &format!("../{pm_dir}"),
            )?;
            inject_path_into_section(&with_pm, "[dependencies.supgang-acl]", None, &format!("../{acl_dir}"))
        }
        "supgang" => {
            let core_dir = dirs
                .get("supgang-core")
                .ok_or_else(|| "missing unpacked supgang-core".to_owned())?;
            inject_path_into_section(manifest, "[dependencies.supgang-core]", None, &format!("../{core_dir}"))
        }
        _ => Ok(manifest.to_owned()),
    }
}

fn inject_path_into_section(
    manifest: &str,
    header: &str,
    required_line: Option<&str>,
    rel_path: &str,
) -> Result<String, String> {
    let lines: Vec<&str> = manifest.lines().collect();
    let Some(start) = lines.iter().position(|line| line.trim() == header) else {
        return Err(format!("packaged manifest is missing expected section {header}"));
    };
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, line)| line.trim_start().starts_with('['))
        .map_or(lines.len(), |(index, _)| index);
    if let Some(required) = required_line {
        let has_required = lines
            .get(start + 1..end)
            .is_some_and(|section| section.iter().any(|line| line.trim() == required));
        if !has_required {
            return Err(format!("section {header} is missing required `{required}`"));
        }
    }
    let mut output = Vec::with_capacity(lines.len() + 1);
    let path_line = format!("path = \"{rel_path}\"");
    for (index, line) in lines.iter().enumerate() {
        output.push((*line).to_owned());
        if index == start {
            output.push(path_line.clone());
        }
    }
    Ok(format!("{}\n", output.join("\n")))
}

fn copy_tree(source: &Path, destination: &Path, remaining: &mut usize) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|err| format!("could not create {}: {err}", destination.display()))?;
    for entry in fs::read_dir(source).map_err(|err| format!("read {}: {err}", source.display()))? {
        let entry = entry.map_err(|err| err.to_string())?;
        let name = entry.file_name();
        if name == "target" || name == ".git" {
            continue;
        }
        let kind = entry.file_type().map_err(|err| err.to_string())?;
        let src_path = entry.path();
        let dst_path = destination.join(&name);
        if kind.is_dir() {
            copy_tree(&src_path, &dst_path, remaining)?;
        } else if kind.is_file() {
            if *remaining == 0 {
                return Err("staged workspace exceeded bounded file limit".to_owned());
            }
            *remaining -= 1;
            fs::copy(&src_path, &dst_path).map_err(|err| format!("copy {}: {err}", src_path.display()))?;
        } else {
            return Err(format!("unsupported entry in staged crate: {}", src_path.display()));
        }
    }
    Ok(())
}

fn capture_cargo(cwd: &Path, args: &[&str], env_vars: &[(&str, &str)]) -> Result<String, String> {
    let output = Command::new("cargo")
        .args(args)
        .envs(env_vars.iter().copied())
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("could not run cargo {}: {err}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "cargo {} failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| "cargo output was not valid UTF-8".to_owned())
}

struct IsolatedRun {
    run_dir: PathBuf,
    stage_dir: PathBuf,
    unpacked_dir: PathBuf,
    target_dir: PathBuf,
    cargo_home: PathBuf,
    linked_caches: Vec<PathBuf>,
}

impl IsolatedRun {
    fn create(base_dir: &Path, host_cargo_home: Option<&Path>) -> Result<Self, String> {
        fs::create_dir_all(base_dir).map_err(|err| format!("create {}: {err}", base_dir.display()))?;
        restrict_owner_only(base_dir)?;
        let run_dir = create_unique_run_dir(base_dir)?;
        let mut run = Self {
            stage_dir: run_dir.join("stage"),
            unpacked_dir: run_dir.join("unpacked"),
            target_dir: run_dir.join("target"),
            cargo_home: run_dir.join("cargo-home"),
            run_dir,
            linked_caches: Vec::new(),
        };
        for dir in [&run.stage_dir, &run.unpacked_dir, &run.target_dir, &run.cargo_home] {
            fs::create_dir(dir).map_err(|err| format!("create {}: {err}", dir.display()))?;
            restrict_owner_only(dir)?;
        }
        if let Some(host_home) = host_cargo_home {
            run.seed_crates_io_registry(host_home)?;
        }
        Ok(run)
    }

    #[cfg(unix)]
    fn seed_crates_io_registry(&mut self, host_cargo_home: &Path) -> Result<(), String> {
        use std::os::unix::fs::symlink;

        let host_registry = host_cargo_home.join("registry");
        let run_registry = self.cargo_home.join("registry");
        fs::create_dir(&run_registry).map_err(|err| format!("create {}: {err}", run_registry.display()))?;
        for kind in ["index", "cache", "src"] {
            let run_subdir = run_registry.join(kind);
            fs::create_dir(&run_subdir).map_err(|err| format!("create {}: {err}", run_subdir.display()))?;
            let host_subdir = host_registry.join(kind);
            if !host_subdir.is_dir() {
                continue;
            }
            for entry in fs::read_dir(&host_subdir)
                .map_err(|err| format!("read {}: {err}", host_subdir.display()))?
                .take(MAX_REGISTRY_ENTRIES)
            {
                let entry = entry.map_err(|err| err.to_string())?;
                let file_name = entry.file_name();
                let Some(name) = file_name.to_str() else {
                    continue;
                };
                if !name.starts_with("index.crates.io-") || !entry.path().is_dir() {
                    continue;
                }
                let destination = run_subdir.join(name);
                symlink(entry.path(), &destination).map_err(|err| format!("link {}: {err}", destination.display()))?;
                self.linked_caches.push(destination);
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn seed_crates_io_registry(&mut self, _host_cargo_home: &Path) -> Result<(), String> {
        Ok(())
    }
}

impl Drop for IsolatedRun {
    fn drop(&mut self) {
        for link in &self.linked_caches {
            if link.starts_with(&self.run_dir)
                && fs::symlink_metadata(link).is_ok_and(|meta| meta.file_type().is_symlink())
            {
                let _removed = fs::remove_file(link);
            }
        }
        let _removed = fs::remove_dir_all(&self.run_dir);
    }
}

fn create_unique_run_dir(base_dir: &Path) -> Result<PathBuf, String> {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    for _ in 0..16 {
        let sequence = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = base_dir.join(format!("run-{pid}-{nanos}-{sequence}"));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                restrict_owner_only(&candidate)?;
                return Ok(candidate);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("could not create {}: {error}", candidate.display())),
        }
    }
    Err(format!(
        "could not allocate isolated run dir under {}",
        base_dir.display()
    ))
}

fn verification_base_dir() -> Result<PathBuf, String> {
    if cfg!(target_os = "macos") {
        return Ok(env::temp_dir().join("supgang-packaged-deps"));
    }
    let home = env::var_os("HOME").ok_or_else(|| "HOME is not set".to_owned())?;
    Ok(PathBuf::from(home).join(".cache").join("supgang").join("packaged-deps"))
}

fn resolve_host_cargo_home() -> Option<PathBuf> {
    env::var_os("CARGO_HOME").map_or_else(
        || env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")),
        |home| Some(PathBuf::from(home)),
    )
}

fn path_to_str(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid Unicode: {}", path.display()))
}

#[cfg(unix)]
fn restrict_owner_only(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("could not restrict {}: {err}", path.display()))
}

#[cfg(not(unix))]
fn restrict_owner_only(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{inspect_resolved_graph, is_netlink_below_0_9, rewire_intra_supgang_paths};

    #[test]
    fn resolved_graph_accepts_clean_packaged_tree() -> Result<(), String> {
        let tree = concat!(
            "supgang v0.2.0-alpha.21 (/tmp/unpacked/supgang-0.2.0-alpha.21)\n",
            "supgang-core v0.2.0-alpha.21 (/tmp/unpacked/supgang-core-0.2.0-alpha.21)\n",
            "supgang-portmapper v0.20.2 (/tmp/unpacked/supgang-portmapper-0.20.2)\n",
            "supgang-netwatch v0.20.2 (/tmp/unpacked/supgang-netwatch-0.20.2)\n",
            "netlink-packet-core v0.9.0\n",
            "wmi v0.18.1\n",
        );
        inspect_resolved_graph("x86_64-pc-windows-msvc", tree).map_err(|(_, msg)| msg)
    }

    #[test]
    fn resolved_graph_rejects_chrono_paste_upstream_netwatch_old_netlink_and_duplicates() {
        let cases = [
            ("chrono", "supgang-netwatch v0.20.2\nchrono v0.4.39\n", "chrono"),
            ("paste", "supgang-netwatch v0.20.2\npaste v1.0.15\n", "paste"),
            (
                "upstream netwatch",
                "supgang-netwatch v0.20.2\nnetwatch v0.20.2\n",
                "netwatch",
            ),
            (
                "upstream portmapper",
                "supgang-netwatch v0.20.2\nportmapper v0.20.2\n",
                "portmapper",
            ),
            (
                "legacy netlink-packet-core",
                "supgang-netwatch v0.20.2\nnetlink-packet-core v0.8.2\n",
                "netlink-packet-core@0.8.2",
            ),
            (
                "duplicate supgang-netwatch",
                "supgang-netwatch v0.20.2\nsupgang-netwatch v0.19.1\n",
                "supgang-netwatch",
            ),
        ];
        for (label, tree, expected_offender) in cases {
            let result = inspect_resolved_graph("x86_64-unknown-linux-gnu", tree);
            assert!(result.is_err(), "{label} must fail rehearsal gate");
            if let Err((offender, _)) = result {
                assert_eq!(offender, expected_offender, "unexpected offender for {label}");
            }
        }
    }

    #[test]
    fn netlink_version_check_distinguishes_0_8_from_0_9_and_1_0() {
        assert!(is_netlink_below_0_9("0.8.2"));
        assert!(is_netlink_below_0_9("0.8.1"));
        assert!(!is_netlink_below_0_9("0.9.0"));
        assert!(!is_netlink_below_0_9("1.0.0-rc2"));
    }

    #[test]
    fn rewire_requires_exact_supgang_package_renames() -> Result<(), String> {
        let mut dirs = BTreeMap::new();
        dirs.insert("supgang-netwatch".to_owned(), "supgang-netwatch-0.20.2".to_owned());
        dirs.insert("supgang-portmapper".to_owned(), "supgang-portmapper-0.20.2".to_owned());
        dirs.insert("supgang-acl".to_owned(), "supgang-acl-0.2.0-alpha.21".to_owned());

        let valid_pm = "[dependencies.netwatch]\nversion = \"=0.20.2\"\npackage = \"supgang-netwatch\"\n";
        let rewritten = rewire_intra_supgang_paths("supgang-portmapper", valid_pm, &dirs)?;
        assert!(rewritten.contains("path = \"../supgang-netwatch-0.20.2\""));

        let unrenamed_pm = "[dependencies.netwatch]\nversion = \"0.20.2\"\n";
        assert!(rewire_intra_supgang_paths("supgang-portmapper", unrenamed_pm, &dirs).is_err());
        Ok(())
    }
}
