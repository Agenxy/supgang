//! Offline archive and single-dependency patch check for netlink-packet-core.

use std::{
    collections::BTreeSet,
    env, fs,
    path::{Component, Path, PathBuf},
};

use super::vendored_netwatch::{collect, tar, verify_hash};

const VERSION: &str = "0.8.2";
const ARCHIVE_SHA256: &str = "b897d7bd4f0af82e68d40d0344cf37e97f9c97ddf74a098de3e4da05e96ca395";
const BEFORE_MANIFEST: &str = "[dependencies.paste]\nversion = \"1\"\n";
const AFTER_MANIFEST: &str = "[dependencies.paste]\npackage = \"pastey\"\nversion = \"=0.2.3\"\n";
const BEFORE_ORIG: &str = "paste = \"1\"";
const AFTER_ORIG: &str = "paste = { package = \"pastey\", version = \"=0.2.3\" }";

pub fn check(root: &Path) -> Result<(), String> {
    let vendor = root.join("third_party/netlink-packet-core");
    let manifest = fs::read_to_string(root.join("Cargo.toml")).map_err(|error| error.to_string())?;
    if !manifest.contains("exclude = [\"third_party/netwatch\", \"third_party/netlink-packet-core\"]")
        || !manifest.contains("netlink-packet-core = { path = \"third_party/netlink-packet-core\" }")
    {
        return Err("netlink-packet-core path patch or workspace exclusion is missing".to_owned());
    }
    let lock = fs::read_to_string(root.join("Cargo.lock")).map_err(|error| error.to_string())?;
    if !lock.contains("name = \"netlink-packet-core\"\nversion = \"0.8.2\"\n")
        || !lock.contains("name = \"pastey\"\nversion = \"0.2.3\"\n")
        || lock.contains("name = \"paste\"\n")
    {
        return Err("reviewed netlink-packet-core/pastey dependency graph is not locked".to_owned());
    }
    let patch_note = fs::read_to_string(vendor.join("PATCH.md")).map_err(|error| error.to_string())?;
    for required in [ARCHIVE_SHA256, "RUSTSEC-2024-0436", "pastey", "LICENSE-MIT"] {
        if !patch_note.contains(required) {
            return Err(format!("netlink-packet-core PATCH.md is missing {required}"));
        }
    }
    let archive = archive_path()?;
    let bytes = fs::read(&archive).map_err(|error| {
        format!(
            "{}: {error}; fetch the pinned archive as described in third_party/netlink-packet-core/PATCH.md",
            archive.display()
        )
    })?;
    verify_hash(&bytes, ARCHIVE_SHA256, "netlink-packet-core archive")?;
    let listed = tar(&archive, &["-tzf"], None)?;
    let prefix = format!("netlink-packet-core-{VERSION}/");
    let mut entries = BTreeSet::new();
    for line in listed.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
        let entry = std::str::from_utf8(line).map_err(|error| error.to_string())?;
        let relative = entry
            .strip_prefix(&prefix)
            .ok_or_else(|| format!("unexpected netlink archive entry: {entry}"))?;
        let path = Path::new(relative);
        if relative.is_empty()
            || !path
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            return Err(format!("unsafe netlink archive entry: {entry}"));
        }
        if !entries.insert(relative.to_owned()) {
            return Err(format!("duplicate netlink archive entry: {entry}"));
        }
        let upstream = tar(&archive, &["-xOzf"], Some(entry))?;
        let expected = match relative {
            "Cargo.toml" => patched(&upstream, BEFORE_MANIFEST, AFTER_MANIFEST)?,
            "Cargo.toml.orig" => patched(&upstream, BEFORE_ORIG, AFTER_ORIG)?,
            _ => upstream,
        };
        let actual = fs::read(vendor.join(relative)).map_err(|error| format!("vendor {relative}: {error}"))?;
        if actual != expected {
            return Err(format!(
                "vendored netlink-packet-core differs from the published archive: {relative}"
            ));
        }
    }
    let mut vendored = BTreeSet::new();
    collect(&vendor, &vendor, &mut vendored)?;
    vendored.remove("PATCH.md");
    if vendored != entries {
        return Err("vendored netlink-packet-core file set differs from the published archive".to_owned());
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
        .join("registry/cache/index.crates.io-1949cf8c6b5b557f")
        .join(format!("netlink-packet-core-{VERSION}.crate")))
}

fn patched(upstream: &[u8], before: &str, after: &str) -> Result<Vec<u8>, String> {
    let source = std::str::from_utf8(upstream).map_err(|error| error.to_string())?;
    if source.matches(before).count() != 1 {
        return Err("published netlink-packet-core manifest changed".to_owned());
    }
    Ok(source.replacen(before, after, 1).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::{AFTER_MANIFEST, BEFORE_MANIFEST, patched};

    #[test]
    fn patch_changes_only_the_paste_dependency() -> Result<(), String> {
        let source = format!("start\n{BEFORE_MANIFEST}end\n");
        assert_eq!(
            patched(source.as_bytes(), BEFORE_MANIFEST, AFTER_MANIFEST)?,
            format!("start\n{AFTER_MANIFEST}end\n").into_bytes()
        );
        assert!(
            patched(
                format!("{BEFORE_MANIFEST}{BEFORE_MANIFEST}").as_bytes(),
                BEFORE_MANIFEST,
                AFTER_MANIFEST
            )
            .is_err()
        );
        Ok(())
    }
}
