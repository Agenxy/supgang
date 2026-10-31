//! Embed product identity in the standalone macOS executable before signing.

use std::{env, fs, io::Write, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = std::io::stdout().lock();
    writeln!(output, "cargo::rerun-if-changed=macos/Info.plist.in")?;
    if env::var("CARGO_CFG_TARGET_OS")? != "macos" {
        return Ok(());
    }
    let release = env::var("CARGO_PKG_VERSION")?;
    let short = format!(
        "{}.{}.{}",
        env::var("CARGO_PKG_VERSION_MAJOR")?,
        env::var("CARGO_PKG_VERSION_MINOR")?,
        env::var("CARGO_PKG_VERSION_PATCH")?
    );
    let template = include_str!("macos/Info.plist.in");
    let plist = template
        .replace("@SHORT_VERSION@", &short)
        .replace("@RELEASE_VERSION@", &release);
    let path = PathBuf::from(env::var_os("OUT_DIR").ok_or("Cargo did not provide OUT_DIR")?).join("Info.plist");
    fs::write(&path, plist)?;
    let path = path.to_str().ok_or("Info.plist path is not Unicode")?;
    if path.chars().any(char::is_control) {
        return Err("Info.plist path contains a control character".into());
    }
    // Separate linker arguments preserve spaces and commas in a checkout path.
    for argument in ["-sectcreate", "__TEXT", "__info_plist", path] {
        writeln!(output, "cargo::rustc-link-arg-bin=supgang=-Xlinker")?;
        writeln!(output, "cargo::rustc-link-arg-bin=supgang={argument}")?;
    }
    Ok(())
}
