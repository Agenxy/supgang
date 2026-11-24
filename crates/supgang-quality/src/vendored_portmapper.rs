//! Offline verification of the reviewed `supgang-portmapper` vendor crate.

use std::{fs, path::Path};

use super::vendored_netwatch::{APACHE_SHA256, MIT_SHA256, archive_path, verify_archive_diff, verify_licenses};

const UPSTREAM_NAME: &str = "portmapper";
const VERSION: &str = "0.20.2";
const UPSTREAM_COMMIT: &str = "334793cfdaf3487db0c721b9312179a8ae3b0dcb";
const ARCHIVE_SHA256: &str = "d36ce759df600731dd2511cd2d640bd551086b2f7b68bceb9bbcfd8c7ff86053";

const PACKAGE_BEFORE: &str = "name = \"portmapper\"\nversion = \"0.20.2\"\n";
const PACKAGE_AFTER: &str = "name = \"supgang-portmapper\"\nversion = \"0.20.2\"\npublish = [\"crates-io\"]\n";
const NETWATCH_BEFORE: &str = "[dependencies.netwatch]\nversion = \"0.20.2\"\n";
const NETWATCH_AFTER: &str =
    "[dependencies.netwatch]\npackage = \"supgang-netwatch\"\nversion = \"=0.20.2\"\npath = \"../netwatch\"\n";

pub fn check(root: &Path) -> Result<(), String> {
    let vendor = root.join("third_party/portmapper");
    let manifest = fs::read_to_string(root.join("Cargo.toml")).map_err(|error| error.to_string())?;
    let expected_dep = "portmapper = { package = \"supgang-portmapper\", path = \"third_party/portmapper\", version = \"=0.20.2\", default-features = false }";
    if !manifest.contains(expected_dep) {
        return Err("workspace portmapper dependency must point to supgang-portmapper =0.20.2".to_owned());
    }
    let lock = fs::read_to_string(root.join("Cargo.lock")).map_err(|error| error.to_string())?;
    if !lock.contains("name = \"supgang-portmapper\"\nversion = \"0.20.2\"\n")
        || !lock.contains("name = \"netlink-packet-core\"\nversion = \"0.9.0\"\n")
        || lock.contains("name = \"portmapper\"\n")
        || lock.contains("name = \"paste\"\n")
    {
        return Err("reviewed supgang-portmapper/netlink-packet-core 0.9.0 dependency graph is not locked".to_owned());
    }
    let patch_note = fs::read_to_string(vendor.join("PATCH.md")).map_err(|error| error.to_string())?;
    for required in [
        VERSION,
        UPSTREAM_COMMIT,
        ARCHIVE_SHA256,
        APACHE_SHA256,
        MIT_SHA256,
        "supgang-portmapper",
        "supgang-netwatch",
    ] {
        if !patch_note.contains(required) {
            return Err(format!("portmapper PATCH.md is missing {required}"));
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

fn patched_manifest(upstream: &[u8]) -> Result<Vec<u8>, String> {
    let source = std::str::from_utf8(upstream).map_err(|error| error.to_string())?;
    if source.matches(PACKAGE_BEFORE).count() != 1 {
        return Err("published portmapper manifest package header changed".to_owned());
    }
    if source.matches(NETWATCH_BEFORE).count() != 1 {
        return Err("published portmapper manifest netwatch stanza changed".to_owned());
    }
    let updated = source
        .replacen(PACKAGE_BEFORE, PACKAGE_AFTER, 1)
        .replacen(NETWATCH_BEFORE, NETWATCH_AFTER, 1);
    Ok(updated.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::{NETWATCH_AFTER, NETWATCH_BEFORE, PACKAGE_AFTER, PACKAGE_BEFORE, patched_manifest};

    #[test]
    fn patch_changes_only_package_identity_and_netwatch_dependency() -> Result<(), String> {
        let source = format!("start\n{PACKAGE_BEFORE}mid\n{NETWATCH_BEFORE}end\n");
        let output = patched_manifest(source.as_bytes())?;
        assert_eq!(
            String::from_utf8(output).ok(),
            Some(format!("start\n{PACKAGE_AFTER}mid\n{NETWATCH_AFTER}end\n"))
        );
        assert!(patched_manifest(format!("{PACKAGE_BEFORE}{PACKAGE_BEFORE}{NETWATCH_BEFORE}").as_bytes()).is_err());
        Ok(())
    }
}
