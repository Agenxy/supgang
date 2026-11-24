//! Offline verification of the reviewed `supgang-netwatch` vendor crate.

use std::{
    collections::BTreeSet,
    env,
    fmt::Write as _,
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

use sha2::{Digest as _, Sha256};

const UPSTREAM_NAME: &str = "netwatch";
const VERSION: &str = "0.20.2";
const UPSTREAM_COMMIT: &str = "334793cfdaf3487db0c721b9312179a8ae3b0dcb";
const REGISTRY: &str = "index.crates.io-1949cf8c6b5b557f";
const ARCHIVE_SHA256: &str = "2acf7a1ca9205d7c1fc9a1595193a8cbaa7537b4a07dca93c6ae3de7c8d0e597";
pub const APACHE_SHA256: &str = "7986218ec4ea89de3511a843ae27fea2584a525036c220ff7b26589179f07888";
pub const MIT_SHA256: &str = "33616ec4c88b6e00de66e6c06f1a55d80bb32a9d7939f3aa83d28e673a1adcae";
pub const SKIPPED_ARCHIVE_METADATA: &[&str] = &[".cargo_vcs_info.json", "Cargo.lock", "Cargo.toml.orig"];

const PACKAGE_BEFORE: &str = "name = \"netwatch\"\nversion = \"0.20.2\"\n";
const PACKAGE_AFTER: &str = "name = \"supgang-netwatch\"\nversion = \"0.20.2\"\npublish = [\"crates-io\"]\n";
const CHRONO_BEFORE: &str = "[target.'cfg(target_os = \"windows\")'.dependencies.chrono]\nversion = \"0.4.23\"\n\n";
const WMI_BEFORE: &str = "[target.'cfg(target_os = \"windows\")'.dependencies.wmi]\nversion = \"0.18\"\n";
const WMI_AFTER: &str =
    "[target.'cfg(target_os = \"windows\")'.dependencies.wmi]\nversion = \"0.18\"\ndefault-features = false\n";

pub fn check(root: &Path) -> Result<(), String> {
    let vendor = root.join("third_party/netwatch");
    let manifest = fs::read_to_string(root.join("Cargo.toml")).map_err(|error| error.to_string())?;
    if !manifest.contains("exclude = [\"third_party/netwatch\", \"third_party/portmapper\"]") {
        return Err("workspace exclude for third_party/netwatch and third_party/portmapper is missing".to_owned());
    }
    if manifest.contains("[patch.crates-io]") {
        return Err("root Cargo.toml must not use [patch.crates-io] for vendored crates".to_owned());
    }
    let lockfile = fs::read_to_string(root.join("Cargo.lock")).map_err(|error| error.to_string())?;
    if !lockfile.contains("name = \"supgang-netwatch\"\nversion = \"0.20.2\"\n") {
        return Err("supgang-netwatch 0.20.2 is not locked".to_owned());
    }
    for forbidden in ["name = \"netwatch\"\n", "name = \"chrono\"\n", "name = \"paste\"\n"] {
        if lockfile.contains(forbidden) {
            return Err(format!("Cargo.lock still contains forbidden package: {forbidden:?}"));
        }
    }
    let patch_note = fs::read_to_string(vendor.join("PATCH.md")).map_err(|error| error.to_string())?;
    for required in [
        VERSION,
        UPSTREAM_COMMIT,
        ARCHIVE_SHA256,
        APACHE_SHA256,
        MIT_SHA256,
        "supgang-netwatch",
        "dependencies.wmi]",
        "+default-features = false",
    ] {
        if !patch_note.contains(required) {
            return Err(format!("netwatch PATCH.md is missing {required}"));
        }
    }
    verify_licenses(&vendor)?;

    let archive = archive_path(UPSTREAM_NAME, VERSION)?;
    verify_archive_diff(
        &vendor,
        &archive,
        UPSTREAM_NAME,
        VERSION,
        ARCHIVE_SHA256,
        UPSTREAM_COMMIT,
        patched_manifest,
    )
}

pub fn verify_licenses(vendor: &Path) -> Result<(), String> {
    for (name, expected) in [("LICENSE-APACHE", APACHE_SHA256), ("LICENSE-MIT", MIT_SHA256)] {
        let path = vendor.join(name);
        let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        verify_hash(&bytes, expected, name)?;
    }
    Ok(())
}

pub fn verify_archive_diff(
    vendor: &Path,
    archive: &Path,
    upstream_name: &str,
    version: &str,
    archive_sha256: &str,
    upstream_commit: &str,
    patch_manifest: fn(&[u8]) -> Result<Vec<u8>, String>,
) -> Result<(), String> {
    let bytes = fs::read(archive).map_err(|error| {
        format!(
            "{}: {error}; fetch and hash the exact archive using the command in third_party/{upstream_name}/PATCH.md",
            archive.display()
        )
    })?;
    verify_hash(&bytes, archive_sha256, &format!("{upstream_name} archive"))?;

    let listed = tar(archive, &["-tzf"], None)?;
    let prefix = format!("{upstream_name}-{version}/");
    let mut entries = BTreeSet::new();
    let mut saw_vcs_info = false;
    for line in listed.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
        let entry = std::str::from_utf8(line).map_err(|error| error.to_string())?;
        let relative = entry
            .strip_prefix(&prefix)
            .ok_or_else(|| format!("unexpected {upstream_name} archive entry: {entry}"))?;
        let path = Path::new(relative);
        if relative.is_empty()
            || !path
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            return Err(format!("disallowed archive path in {upstream_name}: {entry}"));
        }
        if relative == ".cargo_vcs_info.json" {
            let vcs = tar(archive, &["-xOzf"], Some(entry))?;
            let vcs_text = std::str::from_utf8(&vcs).map_err(|error| error.to_string())?;
            if !vcs_text.contains(upstream_commit) {
                return Err(format!(
                    "{upstream_name} archive commit does not match expected {upstream_commit}"
                ));
            }
            saw_vcs_info = true;
            continue;
        }
        if SKIPPED_ARCHIVE_METADATA.contains(&relative) {
            continue;
        }
        if !entries.insert(relative.to_owned()) {
            return Err(format!("duplicate {upstream_name} archive entry: {entry}"));
        }
        let upstream = tar(archive, &["-xOzf"], Some(entry))?;
        let expected = if relative == "Cargo.toml" {
            patch_manifest(&upstream)?
        } else {
            upstream
        };
        let actual =
            fs::read(vendor.join(relative)).map_err(|error| format!("vendor {upstream_name}/{relative}: {error}"))?;
        if actual != expected {
            return Err(format!(
                "vendored {upstream_name} differs from the published archive: {relative}"
            ));
        }
    }
    if !saw_vcs_info {
        return Err(format!("{upstream_name} archive is missing .cargo_vcs_info.json"));
    }

    let mut vendored = BTreeSet::new();
    collect(vendor, vendor, &mut vendored)?;
    vendored.remove("PATCH.md");
    vendored.remove("LICENSE-APACHE");
    vendored.remove("LICENSE-MIT");
    if vendored != entries {
        return Err(format!(
            "vendored {upstream_name} file set differs from the published archive"
        ));
    }
    Ok(())
}

pub fn archive_path(upstream_name: &str, version: &str) -> Result<PathBuf, String> {
    let cargo_home = env::var_os("CARGO_HOME")
        .map_or_else(
            || env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")),
            |home| Some(PathBuf::from(home)),
        )
        .ok_or_else(|| "CARGO_HOME and HOME are both unset".to_owned())?;
    Ok(cargo_home
        .join("registry/cache")
        .join(REGISTRY)
        .join(format!("{upstream_name}-{version}.crate")))
}

pub fn verify_hash(bytes: &[u8], expected: &str, label: &str) -> Result<(), String> {
    let mut actual = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(actual, "{byte:02x}").map_err(|error| error.to_string())?;
    }
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label} SHA-256 mismatch: expected {expected}, got {actual}"))
    }
}

pub fn tar(archive: &Path, flags: &[&str], entry: Option<&str>) -> Result<Vec<u8>, String> {
    let mut command = Command::new("tar");
    command.args(flags).arg(archive);
    if let Some(entry) = entry {
        command.arg(entry);
    }
    let output = command
        .output()
        .map_err(|error| format!("could not inspect archive {}: {error}", archive.display()))?;
    if !output.status.success() {
        return Err(format!(
            "could not inspect archive {}: {}",
            archive.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout)
}

fn patched_manifest(upstream: &[u8]) -> Result<Vec<u8>, String> {
    let source = std::str::from_utf8(upstream).map_err(|error| error.to_string())?;
    if source.matches(PACKAGE_BEFORE).count() != 1 {
        return Err("published netwatch manifest package header changed".to_owned());
    }
    if source.matches(CHRONO_BEFORE).count() != 1 {
        return Err("published netwatch manifest chrono stanza changed".to_owned());
    }
    if source.matches(WMI_BEFORE).count() != 1 {
        return Err("published netwatch manifest WMI stanza changed".to_owned());
    }
    let updated = source
        .replacen(PACKAGE_BEFORE, PACKAGE_AFTER, 1)
        .replacen(CHRONO_BEFORE, "", 1)
        .replacen(WMI_BEFORE, WMI_AFTER, 1);
    Ok(updated.into_bytes())
}

pub fn collect(base: &Path, directory: &Path, result: &mut BTreeSet<String>) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        if kind.is_dir() {
            collect(base, &path, result)?;
        } else if kind.is_file() {
            let relative = path.strip_prefix(base).map_err(|error| error.to_string())?;
            result.insert(relative.to_string_lossy().replace('\\', "/"));
        } else {
            return Err(format!("vendored crate has a non-file entry: {}", path.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CHRONO_BEFORE, PACKAGE_AFTER, PACKAGE_BEFORE, WMI_AFTER, WMI_BEFORE, patched_manifest};

    #[test]
    fn patch_changes_only_package_identity_chrono_and_wmi_features() -> Result<(), String> {
        let source = format!("start\n{PACKAGE_BEFORE}mid\n{CHRONO_BEFORE}{WMI_BEFORE}end\n");
        let output = patched_manifest(source.as_bytes())?;
        assert_eq!(
            String::from_utf8(output).ok(),
            Some(format!("start\n{PACKAGE_AFTER}mid\n{WMI_AFTER}end\n"))
        );
        assert!(patched_manifest(format!("{PACKAGE_BEFORE}{WMI_BEFORE}").as_bytes()).is_err());
        Ok(())
    }
}
