//! Isolated per-run verification of registry-style Cargo packages.
//!
//! `cargo package` stages interdependent workspace crates through a temporary
//! local registry and unpacks them under `CARGO_HOME/registry/src/<hash>`.
//! Reusing a shared target directory or shared `CARGO_HOME` across source
//! revisions that share a prerelease version lets Cargo compile against a
//! stale extraction from an earlier revision. Each verification run therefore
//! uses a fresh per-run target directory and a fresh `CARGO_HOME` that reuses
//! only real `index.crates.io-*` cache entries and cleans up strictly the
//! directory it created.

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_REGISTRY_ENTRIES: usize = 64;

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Mode flags for an isolated `cargo package` invocation.
#[derive(Clone, Copy)]
pub struct PackageFlags {
    pub locked: bool,
    pub offline: bool,
    pub no_verify: bool,
}

/// Runs `cargo package` for `packages` inside the isolated per-run target
/// directory and `CARGO_HOME`.
pub fn run_cargo_package(
    manifest_dir: &Path,
    packages: &[&str],
    run: &IsolatedPackageRun,
    flags: PackageFlags,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<(), String> {
    let cargo_home = run.cargo_home_str()?;
    let target_dir = run.target_dir_str()?;

    let mut arguments = vec!["package", "--allow-dirty"];
    if flags.locked {
        arguments.push("--locked");
    }
    if flags.offline {
        arguments.push("--offline");
    }
    if flags.no_verify {
        arguments.push("--no-verify");
    }
    for package in packages {
        arguments.push("--package");
        arguments.push(package);
    }

    let environment = [("CARGO_HOME", cargo_home), ("CARGO_TARGET_DIR", target_dir)];
    super::run_cargo_with_env(manifest_dir, &arguments, &environment, output, error)
}

/// Per-run isolated directory holding a fresh `CARGO_TARGET_DIR` and
/// `CARGO_HOME`, cleaned up strictly on drop.
pub struct IsolatedPackageRun {
    run_dir: PathBuf,
    target_dir: PathBuf,
    cargo_home: PathBuf,
    linked_caches: Vec<PathBuf>,
}

impl IsolatedPackageRun {
    /// Creates an isolated run under the platform-appropriate base directory
    /// for `namespace`, seeding real `index.crates.io-*` entries from the host
    /// `CARGO_HOME`.
    pub fn create_default(namespace: &str) -> Result<Self, String> {
        let base = verification_base_dir(namespace)?;
        let host_cargo_home = resolve_host_cargo_home();
        Self::create(&base, host_cargo_home.as_deref())
    }

    /// Creates an isolated run under `base_dir`, seeding real
    /// `index.crates.io-*` entries from `host_cargo_home` when present.
    pub fn create(base_dir: &Path, host_cargo_home: Option<&Path>) -> Result<Self, String> {
        fs::create_dir_all(base_dir)
            .map_err(|create_error| format!("could not create {}: {create_error}", base_dir.display()))?;
        restrict_owner_only(base_dir)?;

        let run_dir = create_unique_run_dir(base_dir)?;
        let target_dir = run_dir.join("target");
        let cargo_home = run_dir.join("cargo-home");
        let mut run = Self {
            run_dir,
            target_dir,
            cargo_home,
            linked_caches: Vec::new(),
        };

        fs::create_dir(&run.target_dir)
            .map_err(|create_error| format!("could not create {}: {create_error}", run.target_dir.display()))?;
        fs::create_dir(&run.cargo_home)
            .map_err(|create_error| format!("could not create {}: {create_error}", run.cargo_home.display()))?;
        restrict_owner_only(&run.target_dir)?;
        restrict_owner_only(&run.cargo_home)?;

        if let Some(host_home) = host_cargo_home {
            run.seed_crates_io_registry(host_home)?;
        }
        Ok(run)
    }

    /// Creates an owner-only scratch subdirectory inside this run's directory.
    pub fn create_subdir(&self, name: &str) -> Result<PathBuf, String> {
        let path = self.run_dir.join(name);
        fs::create_dir(&path).map_err(|create_error| format!("could not create {}: {create_error}", path.display()))?;
        restrict_owner_only(&path)?;
        Ok(path)
    }

    pub fn target_dir(&self) -> &Path {
        &self.target_dir
    }

    pub fn target_dir_str(&self) -> Result<&str, String> {
        path_to_str(&self.target_dir)
    }

    pub fn cargo_home_str(&self) -> Result<&str, String> {
        path_to_str(&self.cargo_home)
    }

    #[cfg(unix)]
    fn seed_crates_io_registry(&mut self, host_cargo_home: &Path) -> Result<(), String> {
        use std::os::unix::fs::symlink;

        let host_registry = host_cargo_home.join("registry");
        let run_registry = self.cargo_home.join("registry");
        fs::create_dir(&run_registry)
            .map_err(|create_error| format!("could not create {}: {create_error}", run_registry.display()))?;

        for kind in ["index", "cache", "src"] {
            let run_subdir = run_registry.join(kind);
            fs::create_dir(&run_subdir)
                .map_err(|create_error| format!("could not create {}: {create_error}", run_subdir.display()))?;
            let host_subdir = host_registry.join(kind);
            if !host_subdir.is_dir() {
                continue;
            }
            let entries = fs::read_dir(&host_subdir)
                .map_err(|read_error| format!("could not read {}: {read_error}", host_subdir.display()))?;
            for entry in entries.take(MAX_REGISTRY_ENTRIES) {
                let entry = entry.map_err(|read_error| read_error.to_string())?;
                let file_name = entry.file_name();
                let Some(name) = file_name.to_str() else {
                    continue;
                };
                // Reuse only real crates.io caches; never link Cargo temporary
                // registry extractions (named `-<hash>`) from the host CARGO_HOME.
                if !name.starts_with("index.crates.io-") {
                    continue;
                }
                let source = entry.path();
                if !source.is_dir() {
                    continue;
                }
                let destination = run_subdir.join(name);
                symlink(&source, &destination).map_err(|link_error| {
                    format!(
                        "could not link {} to {}: {link_error}",
                        source.display(),
                        destination.display()
                    )
                })?;
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

impl Drop for IsolatedPackageRun {
    fn drop(&mut self) {
        // Explicitly unlink every cache symlink we created inside run_dir before
        // deleting run_dir so cleanup can never touch host registry entries.
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
            Err(error) => {
                return Err(format!("could not create {}: {error}", candidate.display()));
            }
        }
    }
    Err(format!(
        "could not allocate a unique package-verification directory under {}",
        base_dir.display()
    ))
}

fn verification_base_dir(namespace: &str) -> Result<PathBuf, String> {
    if cfg!(target_os = "macos") {
        return Ok(env::temp_dir().join(namespace));
    }
    let home = env::var_os("HOME").ok_or_else(|| "HOME is not set".to_owned())?;
    Ok(PathBuf::from(home).join(".cache").join("supgang").join(namespace))
}

fn resolve_host_cargo_home() -> Option<PathBuf> {
    env::var_os("CARGO_HOME").map_or_else(
        || env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")),
        |home| Some(PathBuf::from(home)),
    )
}

pub fn path_to_str(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid Unicode: {}", path.display()))
}

#[cfg(unix)]
fn restrict_owner_only(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|mode_error| format!("could not restrict {}: {mode_error}", path.display()))
}

#[cfg(not(unix))]
fn restrict_owner_only(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{IsolatedPackageRun, PackageFlags, run_cargo_package};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(label: &str) -> Result<Self, String> {
            let sequence = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "supgang-pkg-verify-test-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).map_err(|error| error.to_string())?;
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.0);
        }
    }

    fn write_fixture_workspace(workspace: &Path, dep_lib: &str, app_main: &str) -> Result<(), String> {
        fs::create_dir_all(workspace.join("crates/dep/src")).map_err(|error| error.to_string())?;
        fs::create_dir_all(workspace.join("crates/app/src")).map_err(|error| error.to_string())?;
        fs::write(
            workspace.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/dep\", \"crates/app\"]\nresolver = \"3\"\n",
        )
        .map_err(|error| error.to_string())?;
        fs::write(
            workspace.join("crates/dep/Cargo.toml"),
            concat!(
                "[package]\n",
                "name = \"fixture-dep\"\n",
                "version = \"0.1.0-alpha.1\"\n",
                "edition = \"2024\"\n",
                "license = \"Apache-2.0\"\n",
                "description = \"Fixture dependency for package verification isolation\"\n",
            ),
        )
        .map_err(|error| error.to_string())?;
        fs::write(workspace.join("crates/dep/src/lib.rs"), dep_lib).map_err(|error| error.to_string())?;
        fs::write(
            workspace.join("crates/app/Cargo.toml"),
            concat!(
                "[package]\n",
                "name = \"fixture-app\"\n",
                "version = \"0.1.0-alpha.1\"\n",
                "edition = \"2024\"\n",
                "license = \"Apache-2.0\"\n",
                "description = \"Fixture consumer for package verification isolation\"\n",
                "\n",
                "[dependencies]\n",
                "fixture-dep = { path = \"../dep\", version = \"=0.1.0-alpha.1\" }\n",
            ),
        )
        .map_err(|error| error.to_string())?;
        fs::write(workspace.join("crates/app/src/main.rs"), app_main).map_err(|error| error.to_string())?;

        let status = Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| format!("could not generate fixture lockfile: {error}"))?;
        if !status.success() {
            return Err(format!("cargo generate-lockfile failed with {status}"));
        }
        Ok(())
    }

    fn verify_fixture(
        workspace: &Path,
        run_base: &Path,
        host_cargo_home: &Path,
        output: &mut Vec<u8>,
        error: &mut Vec<u8>,
    ) -> Result<(), String> {
        let run = IsolatedPackageRun::create(run_base, Some(host_cargo_home))?;
        run_cargo_package(
            workspace,
            &["fixture-dep", "fixture-app"],
            &run,
            PackageFlags {
                locked: true,
                offline: true,
                no_verify: false,
            },
            output,
            error,
        )
    }

    #[test]
    fn repeated_same_version_revisions_verify_new_bytes_without_touching_host_cargo_home() -> Result<(), String> {
        let root = TempRoot::new("same-version")?;
        let workspace = root.path().join("ws");
        let run_base = root.path().join("runs");
        let host_cargo_home = root.path().join("host-cargo-home");
        let host_crates_io_cache = host_cargo_home.join("registry/cache/index.crates.io-test");
        let pre_existing_temp = host_cargo_home.join("registry/src/-deadbeef00000000/fixture-dep-0.1.0-alpha.1");
        fs::create_dir_all(&host_crates_io_cache).map_err(|error| error.to_string())?;
        fs::create_dir_all(&pre_existing_temp).map_err(|error| error.to_string())?;
        let sentinel = pre_existing_temp.join("sentinel.txt");
        fs::write(&sentinel, b"must-not-be-deleted").map_err(|error| error.to_string())?;
        let cache_marker = host_crates_io_cache.join("keep.marker");
        fs::write(&cache_marker, b"keep-host-cache").map_err(|error| error.to_string())?;

        // Revision 1 at prerelease 0.1.0-alpha.1 exports REV_ONE.
        write_fixture_workspace(
            &workspace,
            "pub const REV_ONE: u32 = 1;\n",
            "fn main() { let _ = fixture_dep::REV_ONE; }\n",
        )?;
        let mut output = Vec::new();
        let mut error = Vec::new();
        verify_fixture(&workspace, &run_base, &host_cargo_home, &mut output, &mut error)?;

        // Revision 2 keeps the exact same 0.1.0-alpha.1 version, removes REV_ONE,
        // and introduces REV_TWO. If Cargo reused revision 1's extraction, this
        // verification would fail to compile fixture-app.
        write_fixture_workspace(
            &workspace,
            "pub const REV_TWO: u32 = 2;\n",
            "fn main() { let _ = fixture_dep::REV_TWO; }\n",
        )?;
        verify_fixture(&workspace, &run_base, &host_cargo_home, &mut output, &mut error)?;

        // Fail-closed check: referencing removed REV_ONE against revision 2 must fail.
        write_fixture_workspace(
            &workspace,
            "pub const REV_TWO: u32 = 2;\n",
            "fn main() { let _ = fixture_dep::REV_ONE; }\n",
        )?;
        let broken = verify_fixture(&workspace, &run_base, &host_cargo_home, &mut output, &mut error);
        if broken.is_ok() {
            return Err("package verification must fail closed when consumer references removed API".to_owned());
        }

        // Verify no per-run directories remain after success or failure.
        let leftover = fs::read_dir(&run_base)
            .map_err(|err| err.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| err.to_string())?;
        if !leftover.is_empty() {
            return Err(format!("expected empty run_base, found {} entries", leftover.len()));
        }

        // Verify host CARGO_HOME was neither polluted nor modified/deleted.
        if !sentinel.is_file() || !cache_marker.is_file() {
            return Err("host CARGO_HOME entries outside gate-owned paths were modified".to_owned());
        }
        let host_src_entries = fs::read_dir(host_cargo_home.join("registry/src"))
            .map_err(|err| err.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| err.to_string())?;
        if host_src_entries.len() != 1 {
            return Err(format!(
                "expected host registry/src to remain untouched (1 pre-existing entry), found {}",
                host_src_entries.len()
            ));
        }
        Ok(())
    }
}
