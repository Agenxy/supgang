//! Verify the actual shipped executable, not only the source metadata template.

#[test]
fn command_and_core_have_the_same_release_identity() {
    assert_eq!(env!("CARGO_PKG_VERSION"), supgang_core::VERSION);
}

#[cfg(target_os = "macos")]
#[test]
fn executable_has_embedded_product_metadata() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    let binary = env!("CARGO_BIN_EXE_supgang");
    let section = Command::new("/usr/bin/otool").args(["-P", binary]).output()?;
    assert!(section.status.success());
    let section = String::from_utf8(section.stdout)?;
    let (_, xml) = section.split_once("<?xml").ok_or("missing embedded product metadata")?;
    let xml = format!("<?xml{xml}");
    // Apple's parser verifies the emitted section before its values are checked.
    let mut parser = Command::new("/usr/bin/plutil")
        .args(["-lint", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    parser
        .stdin
        .take()
        .ok_or("missing plist parser input")?
        .write_all(xml.as_bytes())?;
    assert!(parser.wait_with_output()?.status.success());
    for (key, expected) in [
        ("CFBundleIdentifier", "org.agenxy.supgang.runtime"),
        ("CFBundleName", "Supgang"),
        ("CFBundleDisplayName", "Supgang"),
        ("CFBundleExecutable", "supgang"),
        ("SupgangReleaseVersion", env!("CARGO_PKG_VERSION")),
    ] {
        assert!(
            xml.contains(&format!("<key>{key}</key>\n    <string>{expected}</string>")),
            "{key}"
        );
    }
    assert!(!xml.contains("<string></string>"));
    assert!(!xml.contains('@'));
    assert!(
        Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict", binary])
            .status()?
            .success()
    );
    Ok(())
}
