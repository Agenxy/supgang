//! Offline verification of the reviewed netwatch vendor patch.

use std::{
    collections::BTreeSet,
    env,
    fmt::Write as _,
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

use sha2::{Digest as _, Sha256};

const VERSION: &str = "0.19.1";
const REGISTRY: &str = "index.crates.io-1949cf8c6b5b557f";
const ARCHIVE_SHA256: &str = "4d9cbe01741347ef750d743d6690603f5eed8341e679fb51c8e629337aa11976";
const APACHE_SHA256: &str = "7986218ec4ea89de3511a843ae27fea2584a525036c220ff7b26589179f07888";
const MIT_SHA256: &str = "33616ec4c88b6e00de66e6c06f1a55d80bb32a9d7939f3aa83d28e673a1adcae";
const BEFORE: &str = "[target.'cfg(target_os = \"windows\")'.dependencies.wmi]\nversion = \"0.18\"\n";
const AFTER: &str =
    "[target.'cfg(target_os = \"windows\")'.dependencies.wmi]\nversion = \"0.18\"\ndefault-features = false\n";

pub fn check(root: &Path) -> Result<(), String> {
    let vendor = root.join("third_party/netwatch");
    let manifest = fs::read_to_string(root.join("Cargo.toml")).map_err(|error| error.to_string())?;
    if !manifest.contains("exclude = [\"third_party/netwatch\", \"third_party/netlink-packet-core\"]")
        || !manifest.contains("netwatch = { path = \"third_party/netwatch\" }")
    {
        return Err("netwatch path patch or workspace exclusion is missing".to_owned());
    }
    let lockfile = fs::read_to_string(root.join("Cargo.lock")).map_err(|error| error.to_string())?;
    if !lockfile.contains("name = \"netwatch\"\nversion = \"0.19.1\"\n") {
        return Err("netwatch 0.19.1 is not locked".to_owned());
    }
    let patch_note = fs::read_to_string(vendor.join("PATCH.md")).map_err(|error| error.to_string())?;
    for required in [
        ARCHIVE_SHA256,
        APACHE_SHA256,
        MIT_SHA256,
        "dependencies.wmi]",
        "version = \"0.18\"",
        "+default-features = false",
    ] {
        if !patch_note.contains(required) {
            return Err(format!("netwatch PATCH.md is missing {required}"));
        }
    }
    for (name, expected) in [("LICENSE-APACHE", APACHE_SHA256), ("LICENSE-MIT", MIT_SHA256)] {
        let path = vendor.join(name);
        let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        verify_hash(&bytes, expected, name)?;
    }

    let archive = archive_path()?;
    let bytes = fs::read(&archive).map_err(|error| {
        format!(
            "{}: {error}; fetch and hash the exact archive using the command in third_party/netwatch/PATCH.md",
            archive.display()
        )
    })?;
    verify_hash(&bytes, ARCHIVE_SHA256, "netwatch archive")?;

    let listed = tar(&archive, &["-tzf"], None)?;
    let prefix = format!("netwatch-{VERSION}/");
    let mut entries = BTreeSet::new();
    for line in listed.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
        let entry = std::str::from_utf8(line).map_err(|error| error.to_string())?;
        let relative = entry
            .strip_prefix(&prefix)
            .ok_or_else(|| format!("unexpected archive entry: {entry}"))?;
        let path = Path::new(relative);
        if relative.is_empty()
            || !path
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            return Err(format!("unsafe archive entry: {entry}"));
        }
        if !entries.insert(relative.to_owned()) {
            return Err(format!("duplicate archive entry: {entry}"));
        }
        let upstream = tar(&archive, &["-xOzf"], Some(entry))?;
        let expected = if relative == "Cargo.toml" {
            patched_manifest(&upstream)?
        } else {
            upstream
        };
        let actual = fs::read(vendor.join(relative)).map_err(|error| format!("vendor {relative}: {error}"))?;
        if actual != expected {
            return Err(format!(
                "vendored netwatch differs from the published archive: {relative}"
            ));
        }
    }

    let mut vendored = BTreeSet::new();
    collect(&vendor, &vendor, &mut vendored)?;
    vendored.remove("PATCH.md");
    vendored.remove("LICENSE-APACHE");
    vendored.remove("LICENSE-MIT");
    if vendored != entries {
        return Err("vendored netwatch file set differs from the published archive".to_owned());
    }
    Ok(())
}

fn archive_path() -> Result<PathBuf, String> {
    let cargo_home = env::var_os("CARGO_HOME")
        .map_or_else(
            || env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")),
            |home| Some(PathBuf::from(home)),
        )
        .ok_or_else(|| "CARGO_HOME and HOME are both unset".to_owned())?;
    Ok(cargo_home
        .join("registry/cache")
        .join(REGISTRY)
        .join(format!("netwatch-{VERSION}.crate")))
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
        .map_err(|error| format!("could not inspect netwatch archive: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "could not inspect netwatch archive: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout)
}

fn patched_manifest(upstream: &[u8]) -> Result<Vec<u8>, String> {
    let source = std::str::from_utf8(upstream).map_err(|error| error.to_string())?;
    if source.matches(BEFORE).count() != 1 {
        return Err("published netwatch manifest WMI stanza changed".to_owned());
    }
    Ok(source.replacen(BEFORE, AFTER, 1).into_bytes())
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
            return Err(format!("vendored netwatch has a non-file entry: {}", path.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AFTER, BEFORE, patched_manifest};

    #[test]
    fn patch_changes_only_the_wmi_feature_line() -> Result<(), String> {
        let source = format!("start\n{BEFORE}end\n");
        let output = patched_manifest(source.as_bytes())?;
        assert_eq!(String::from_utf8(output).ok(), Some(format!("start\n{AFTER}end\n")));
        assert!(patched_manifest(format!("{BEFORE}{BEFORE}").as_bytes()).is_err());
        Ok(())
    }
}
