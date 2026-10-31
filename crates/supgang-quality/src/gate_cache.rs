//! Exact-input receipts for repeat local quality runs.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fmt::Write as _,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime},
};

use serde_json::Value;
use sha2::{Digest as _, Sha256};

const MAX_SOURCE_FILES: usize = 20_000;
const MAX_SOURCE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ONE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOOL_BANNER_BYTES: usize = 4096;
const MAX_TOOL_BYTES: u64 = 128 * 1024 * 1024;
const RECEIPT_AGE: Duration = Duration::from_hours(24);
const RECEIPT_MARK: &str = "supgang-quality-pass-v1\n";

#[derive(Clone, Copy)]
pub enum Stage {
    Format,
    Check,
    Clippy,
    Test,
    Doc,
}

impl Stage {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Format => "format",
            Self::Check => "check",
            Self::Clippy => "clippy",
            Self::Test => "test",
            Self::Doc => "doc",
        }
    }

    pub(super) fn arguments(self, package: Option<&str>) -> Vec<String> {
        let mut arguments = match self {
            Self::Format => vec!["fmt".to_owned()],
            Self::Check => vec!["check".to_owned()],
            Self::Clippy => vec!["clippy".to_owned()],
            Self::Test => vec!["test".to_owned()],
            Self::Doc => vec!["doc".to_owned()],
        };
        match package {
            Some(name) => arguments.extend(["--package".to_owned(), name.to_owned()]),
            None if matches!(self, Self::Format) => arguments.push("--all".to_owned()),
            None => arguments.push("--workspace".to_owned()),
        }
        match self {
            Self::Format => arguments.extend(["--".to_owned(), "--check".to_owned()]),
            Self::Check | Self::Test => arguments.extend(["--all-targets".to_owned(), "--locked".to_owned()]),
            Self::Clippy => arguments.extend([
                "--all-targets".to_owned(),
                "--all-features".to_owned(),
                "--locked".to_owned(),
                "--".to_owned(),
                "-D".to_owned(),
                "warnings".to_owned(),
            ]),
            Self::Doc => arguments.extend(["--no-deps".to_owned(), "--locked".to_owned()]),
        }
        arguments
    }
}

#[derive(Clone)]
struct Package {
    name: String,
    directory: String,
    local_dependencies: Vec<String>,
}

pub struct GateCache {
    root: PathBuf,
    inputs: BTreeMap<String, [u8; 32]>,
    packages: Vec<Package>,
    context: [u8; 32],
    receipts: Option<PathBuf>,
    pending: Vec<(PathBuf, Vec<u8>)>,
    hits: usize,
    misses: usize,
}

impl GateCache {
    pub(super) fn open(root: &Path) -> Result<Self, String> {
        let inputs = source_inventory(root)?;
        let packages = workspace_packages(root)?;
        let context = environment_context(root)?;
        let receipts = if env::var_os("SUPGANG_QUALITY_CACHE").as_deref() == Some("off".as_ref()) {
            None
        } else {
            let home = env::var_os("HOME").ok_or_else(|| "HOME is required for quality receipts".to_owned())?;
            Some(PathBuf::from(home).join(".cache/agenxy/supgang-quality/v1"))
        };
        Ok(Self {
            root: root.to_path_buf(),
            inputs,
            packages,
            context,
            receipts,
            pending: Vec::new(),
            hits: 0,
            misses: 0,
        })
    }

    pub(super) fn packages(&self) -> impl Iterator<Item = &str> {
        self.packages.iter().map(|package| package.name.as_str())
    }

    pub(super) fn missed(&mut self, stage: Stage, output: &mut dyn Write) -> Result<Vec<String>, String> {
        let mut missing = Vec::new();
        for package in &self.packages {
            let key = self.package_key(stage, &package.name)?;
            let hit = self.receipt_hit(stage.name(), &package.name, &key);
            self.hits += usize::from(hit);
            self.misses += usize::from(!hit);
            writeln!(
                output,
                "quality-cache stage={} package={} status={}",
                stage.name(),
                package.name,
                if hit { "hit skip" } else { "miss run" }
            )
            .map_err(|error| error.to_string())?;
            if !hit {
                missing.push(package.name.clone());
            }
        }
        Ok(missing)
    }

    pub(super) fn record_packages(&mut self, stage: Stage, packages: &[String]) -> Result<(), String> {
        for package in packages {
            let key = self.package_key(stage, package)?;
            self.record(stage.name(), package, &key);
        }
        Ok(())
    }

    pub(super) fn acceptance_hit(&mut self, output: &mut dyn Write) -> Result<bool, String> {
        let key = self.acceptance_key();
        let hit = self.receipt_hit("acceptance", "workspace", &key);
        self.hits += usize::from(hit);
        self.misses += usize::from(!hit);
        writeln!(
            output,
            "quality-cache stage=acceptance package=workspace status={}",
            if hit { "hit skip" } else { "miss run" }
        )
        .map_err(|error| error.to_string())?;
        Ok(hit)
    }

    pub(super) fn record_acceptance(&mut self) {
        let key = self.acceptance_key();
        self.record("acceptance", "workspace", &key);
    }

    pub(super) fn finish(self, output: &mut dyn Write) -> Result<(), String> {
        if source_inventory(&self.root)? != self.inputs {
            return Err("source tree changed during the quality run; no pass receipt was written".to_owned());
        }
        for (path, contents) in &self.pending {
            write_receipt(path, contents)?;
        }
        writeln!(
            output,
            "quality-cache hits={} misses={} skips={}",
            self.hits, self.misses, self.hits
        )
        .map_err(|error| error.to_string())
    }

    fn package_key(&self, stage: Stage, name: &str) -> Result<[u8; 32], String> {
        let mut directories = BTreeSet::new();
        self.add_closure(name, &mut directories)?;
        let mut hash = Sha256::new();
        hash.update(b"supgang-quality-package-v1\0");
        hash.update(self.context);
        field(&mut hash, stage.name().as_bytes());
        field(&mut hash, name.as_bytes());
        for (path, digest) in &self.inputs {
            let common = !path.starts_with("crates/") || path.starts_with("crates/supgang-quality/");
            if common || directories.iter().any(|directory| path.starts_with(directory)) {
                field(&mut hash, path.as_bytes());
                hash.update(digest);
            }
        }
        Ok(hash.finalize().into())
    }

    fn add_closure(&self, name: &str, directories: &mut BTreeSet<String>) -> Result<(), String> {
        let package = self
            .packages
            .iter()
            .find(|package| package.name == name)
            .ok_or_else(|| format!("unknown workspace package: {name}"))?;
        let prefix = format!("{}/", package.directory);
        if directories.insert(prefix) {
            for dependency in &package.local_dependencies {
                self.add_closure(dependency, directories)?;
            }
        }
        Ok(())
    }

    fn acceptance_key(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"supgang-quality-acceptance-v1\0");
        hash.update(self.context);
        for (path, digest) in &self.inputs {
            field(&mut hash, path.as_bytes());
            hash.update(digest);
        }
        hash.finalize().into()
    }

    fn receipt_hit(&self, stage: &str, package: &str, key: &[u8; 32]) -> bool {
        let Some(path) = self.receipt_path(stage, package, key) else {
            return false;
        };
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            return false;
        };
        if !metadata.file_type().is_file() || metadata.len() > 128 {
            return false;
        }
        if metadata
            .modified()
            .ok()
            .and_then(|at| SystemTime::now().duration_since(at).ok())
            .is_none_or(|age| age > RECEIPT_AGE)
        {
            return false;
        }
        fs::read(path).is_ok_and(|contents| contents == receipt_contents(key))
    }

    fn receipt_path(&self, stage: &str, package: &str, key: &[u8; 32]) -> Option<PathBuf> {
        self.receipts
            .as_ref()
            .map(|root| root.join(stage).join(package).join(format!("{}.pass", hex_digest(key))))
    }

    fn record(&mut self, stage: &str, package: &str, key: &[u8; 32]) {
        if let Some(path) = self.receipt_path(stage, package, key) {
            self.pending.push((path, receipt_contents(key)));
        }
    }
}

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hash.update(bytes);
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut result, byte| {
        let _ = write!(&mut result, "{byte:02x}");
        result
    })
}

fn receipt_contents(key: &[u8; 32]) -> Vec<u8> {
    format!("{RECEIPT_MARK}{}\n", hex_digest(key)).into_bytes()
}

fn write_receipt(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "receipt has no parent directory".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| format!("cannot create quality receipt directory: {error}"))?;
    for attempt in 0..8 {
        let temporary = parent.join(format!(".receipt-{}-{attempt}", std::process::id()));
        let mut file = match fs::OpenOptions::new().write(true).create_new(true).open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("cannot create quality receipt: {error}")),
        };
        file.write_all(contents).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(&temporary, path).map_err(|error| error.to_string())?;
        return Ok(());
    }
    Err("quality receipt temporary names were exhausted".to_owned())
}

fn source_inventory(root: &Path) -> Result<BTreeMap<String, [u8; 32]>, String> {
    let mut inputs = BTreeMap::new();
    let mut total = 0_u64;
    let mut pending = vec![root.to_path_buf()];
    let mut directories = 0_usize;
    while let Some(directory) = pending.pop() {
        directories += 1;
        if directories > MAX_SOURCE_FILES {
            return Err("source inventory exceeds its directory budget".to_owned());
        }
        for entry in fs::read_dir(&directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name();
            if name == ".git" {
                continue;
            }
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            if kind.is_dir() {
                if !name.to_str().is_some_and(|value| super::BUILD_OUTPUT.contains(&value)) {
                    pending.push(entry.path());
                }
                continue;
            }
            if !kind.is_file() {
                return Err(format!(
                    "source inventory contains a non-file: {}",
                    entry.path().display()
                ));
            }
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .ok()
                .and_then(|value| value.to_str())
                .ok_or_else(|| "source path is not valid UTF-8".to_owned())?;
            let length = entry.metadata().map_err(|error| error.to_string())?.len();
            total = total.saturating_add(length);
            if length > MAX_ONE_FILE_BYTES || total > MAX_SOURCE_BYTES || inputs.len() >= MAX_SOURCE_FILES {
                return Err("source inventory exceeds its file or byte budget".to_owned());
            }
            let mut file = fs::File::open(&path).map_err(|error| error.to_string())?;
            let mut hash = Sha256::new();
            let mut buffer = [0_u8; 8192];
            loop {
                let count = file.read(&mut buffer).map_err(|error| error.to_string())?;
                if count == 0 {
                    break;
                }
                hash.update(
                    buffer
                        .get(..count)
                        .ok_or_else(|| "source read exceeded buffer".to_owned())?,
                );
            }
            inputs.insert(relative.to_owned(), hash.finalize().into());
        }
    }
    Ok(inputs)
}

fn workspace_packages(root: &Path) -> Result<Vec<Package>, String> {
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--locked",
            "--offline",
        ])
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot inspect Cargo package graph: {error}"))?;
    if !output.status.success() || output.stdout.len() > MAX_METADATA_BYTES {
        return Err("Cargo package graph is unavailable or exceeds its bound".to_owned());
    }
    let metadata: Value = serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    let members = metadata
        .get("workspace_members")
        .ok_or_else(|| "Cargo workspace members are missing".to_owned())?
        .as_array()
        .ok_or_else(|| "Cargo workspace members are missing".to_owned())?;
    if members.len() > 32 {
        return Err("Cargo workspace has too many packages for the quality cache".to_owned());
    }
    let packages = metadata
        .get("packages")
        .ok_or_else(|| "Cargo packages are missing".to_owned())?
        .as_array()
        .ok_or_else(|| "Cargo packages are missing".to_owned())?;
    let mut selected = Vec::new();
    for package in packages {
        if !package.get("id").is_some_and(|id| members.contains(id)) {
            continue;
        }
        let name = package
            .get("name")
            .ok_or_else(|| "Cargo package name is missing".to_owned())?
            .as_str()
            .ok_or_else(|| "Cargo package name is missing".to_owned())?;
        let manifest = package
            .get("manifest_path")
            .ok_or_else(|| "Cargo package manifest is missing".to_owned())?
            .as_str()
            .ok_or_else(|| "Cargo package manifest is missing".to_owned())?;
        let directory = Path::new(manifest)
            .parent()
            .and_then(|value| value.strip_prefix(root).ok())
            .and_then(Path::to_str)
            .ok_or_else(|| "Cargo package is outside this workspace".to_owned())?;
        let dependencies = package
            .get("dependencies")
            .ok_or_else(|| "Cargo package dependencies are missing".to_owned())?
            .as_array()
            .ok_or_else(|| "Cargo package dependencies are missing".to_owned())?;
        let local_dependencies = dependencies
            .iter()
            .filter(|dependency| dependency.get("path").is_some_and(Value::is_string))
            .map(|dependency| {
                dependency
                    .get("name")
                    .ok_or_else(|| "local Cargo dependency has no name".to_owned())?
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "local Cargo dependency has no name".to_owned())
            })
            .collect::<Result<Vec<_>, String>>()?;
        selected.push(Package {
            name: name.to_owned(),
            directory: directory.to_owned(),
            local_dependencies,
        });
    }
    selected.sort_by(|left, right| left.name.cmp(&right.name));
    if selected.len() != members.len() {
        return Err("Cargo package graph omitted a workspace member".to_owned());
    }
    for package in &selected {
        for dependency in &package.local_dependencies {
            if !selected.iter().any(|candidate| candidate.name == *dependency) {
                return Err(format!("local dependency is outside the workspace: {dependency}"));
            }
        }
    }
    Ok(selected)
}

fn environment_context(root: &Path) -> Result<[u8; 32], String> {
    let mut hash = Sha256::new();
    hash.update(b"supgang-quality-environment-v1\0");
    field(&mut hash, root.as_os_str().as_encoded_bytes());
    let mut variables = env::vars_os().collect::<Vec<_>>();
    variables.sort_by(|left, right| left.0.cmp(&right.0));
    for (name, value) in variables {
        if !stable_environment_variable(&name) {
            continue;
        }
        field(&mut hash, name.as_encoded_bytes());
        field(&mut hash, value.as_encoded_bytes());
    }
    for (command, arguments) in [
        ("rustc", &["-vV"][..]),
        ("cargo", &["-Vv"][..]),
        ("uv", &["--version"][..]),
        ("uname", &["-s", "-m", "-r"][..]),
    ] {
        let output = Command::new(command)
            .args(arguments)
            .current_dir(root)
            .output()
            .map_err(|error| format!("cannot read {command} identity: {error}"))?;
        if !output.status.success() || output.stdout.len() > MAX_TOOL_BANNER_BYTES {
            return Err(format!("{command} identity is unavailable or too large"));
        }
        field(&mut hash, command.as_bytes());
        field(&mut hash, &output.stdout);
    }
    for tool in ["rustc", "cargo", "rustfmt", "clippy-driver", "rustdoc"] {
        let selected = selected_tool_path(root, "rustup", &["which", tool])?;
        field(&mut hash, tool.as_bytes());
        field(&mut hash, &tool_digest(&selected)?);
    }
    let sysroot = selected_tool_path(root, "rustc", &["--print", "sysroot"])?;
    field(&mut hash, sysroot.as_os_str().as_encoded_bytes());
    for name in ["components", "multirust-config.toml", "multirust-channel-manifest.toml"] {
        let manifest = sysroot.join("lib").join("rustlib").join(name);
        field(&mut hash, name.as_bytes());
        field(&mut hash, &tool_digest(&manifest)?);
    }
    let floor = super::acceptance::declared_python_floor(&root.join("tools/check.py"))
        .ok_or_else(|| "tools/check.py has no Python floor".to_owned())?;
    let interpreter = selected_tool_path(root, "uv", &["python", "find", &floor, "--offline"])?;
    field(&mut hash, interpreter.as_os_str().as_encoded_bytes());
    field(&mut hash, &tool_digest(&interpreter)?);
    Ok(hash.finalize().into())
}

fn stable_environment_variable(name: &std::ffi::OsStr) -> bool {
    // The Codex host changes this identifier for every command invocation.
    // It carries no build input, so hashing it would prevent identical-tree hits.
    !matches!(
        name.to_str(),
        Some("CARGO_MAKEFLAGS" | "MAKEFLAGS" | "MFLAGS" | "SHLVL" | "_" | "PWD" | "CODEX_TOOL_CALL_ID")
    )
}

fn selected_tool_path(root: &Path, program: &str, arguments: &[&str]) -> Result<PathBuf, String> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot locate selected {program}: {error}"))?;
    if !output.status.success() || output.stdout.len() > MAX_TOOL_BANNER_BYTES {
        return Err(format!("selected {program} path is unavailable or too large"));
    }
    let path = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
    let path = PathBuf::from(path.trim());
    if !path.is_absolute() {
        return Err(format!("selected {program} path is not absolute"));
    }
    Ok(path)
}

fn tool_digest(path: &Path) -> Result<[u8; 32], String> {
    let metadata = fs::metadata(path).map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_TOOL_BYTES {
        return Err(format!("tool identity file is absent or too large: {}", path.display()));
    }
    let mut binary = fs::File::open(path).map_err(|error| format!("cannot hash {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut consumed = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = binary.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        consumed = consumed.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        if consumed > MAX_TOOL_BYTES {
            return Err(format!("tool identity grew beyond its bound: {}", path.display()));
        }
        digest.update(
            buffer
                .get(..count)
                .ok_or_else(|| "tool read exceeded buffer".to_owned())?,
        );
    }
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, ffi::OsStr, path::PathBuf};

    use super::{GateCache, Package, Stage, receipt_contents};

    #[test]
    fn stage_arguments_keep_the_workspace_and_package_gates_equivalent() {
        assert_eq!(Stage::Format.arguments(None), ["fmt", "--all", "--", "--check"]);
        assert_eq!(
            Stage::Clippy.arguments(None),
            [
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--",
                "-D",
                "warnings"
            ]
        );
        assert_eq!(
            Stage::Test.arguments(Some("supgang-core")),
            ["test", "--package", "supgang-core", "--all-targets", "--locked"]
        );
    }

    #[test]
    fn changing_command_identity_does_not_invalidate_build_receipts() {
        assert!(!super::stable_environment_variable(OsStr::new("CODEX_TOOL_CALL_ID")));
        assert!(super::stable_environment_variable(OsStr::new("RUSTFLAGS")));
    }

    #[test]
    fn a_receipt_has_a_fixed_marker_and_exact_digest() {
        let receipt = receipt_contents(&[0xa5; 32]);
        assert_eq!(receipt.len(), super::RECEIPT_MARK.len() + 64 + 1);
        assert!(receipt.ends_with(b"\n"));
    }

    #[test]
    fn source_changes_invalidate_only_the_local_dependency_closure() -> Result<(), String> {
        let packages = vec![
            Package {
                name: "supgang-acl".to_owned(),
                directory: "crates/supgang-acl".to_owned(),
                local_dependencies: Vec::new(),
            },
            Package {
                name: "supgang-core".to_owned(),
                directory: "crates/supgang".to_owned(),
                local_dependencies: vec!["supgang-acl".to_owned()],
            },
            Package {
                name: "supgang".to_owned(),
                directory: "crates/supgang-cli".to_owned(),
                local_dependencies: vec!["supgang-core".to_owned()],
            },
            Package {
                name: "supgang-quality".to_owned(),
                directory: "crates/supgang-quality".to_owned(),
                local_dependencies: Vec::new(),
            },
        ];
        let mut cache = GateCache {
            root: PathBuf::new(),
            inputs: BTreeMap::from([
                ("Cargo.lock".to_owned(), [1; 32]),
                ("crates/supgang-acl/src/lib.rs".to_owned(), [2; 32]),
                ("crates/supgang/src/lib.rs".to_owned(), [3; 32]),
                ("crates/supgang-cli/src/main.rs".to_owned(), [4; 32]),
                ("crates/supgang-quality/src/main.rs".to_owned(), [5; 32]),
            ]),
            packages,
            context: [0; 32],
            receipts: None,
            pending: Vec::new(),
            hits: 0,
            misses: 0,
        };
        let before = cache
            .packages()
            .map(|name| Ok((name.to_owned(), cache.package_key(Stage::Test, name)?)))
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        cache.inputs.insert("crates/supgang/src/lib.rs".to_owned(), [9; 32]);
        for (name, expected_changed) in [
            ("supgang-acl", false),
            ("supgang-core", true),
            ("supgang", true),
            ("supgang-quality", false),
        ] {
            let prior = before.get(name).ok_or_else(|| "missing prior key".to_owned())?;
            assert_eq!(prior != &cache.package_key(Stage::Test, name)?, expected_changed);
        }
        Ok(())
    }
}
