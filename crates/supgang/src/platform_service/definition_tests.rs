use std::{os::unix::ffi::OsStrExt as _, path::Path};

use super::definition::{render_launchd, render_systemd};

#[test]
fn each_renderer_is_byte_exact_and_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let executable = Path::new("/safe/bin/supgang");
    let state = Path::new("/safe/state");
    for (rendered, repeated, literal) in [
        (
            render_launchd(executable, state, None, true, true)?,
            render_launchd(executable, state, None, true, true)?,
            include_str!("fixtures/launchd.plist"),
        ),
        (
            render_systemd(executable, state, None, true, true)?,
            render_systemd(executable, state, None, true, true)?,
            include_str!("fixtures/systemd.service"),
        ),
    ] {
        assert_eq!(rendered, literal);
        assert_eq!(rendered, repeated);
    }
    Ok(())
}

#[test]
fn every_renderer_refuses_controls_relative_paths_and_non_unicode_in_every_argument() {
    let safe = Path::new("/safe");
    for bad in [
        "/bad\npath",
        "/bad\rpath",
        "/bad\tpath",
        "/bad\0path",
        "/bad\u{7f}",
        "/bad\u{ffff}",
        "relative",
        "",
    ] {
        for (program, state, endpoints) in [
            (Path::new(bad), safe, Some(safe)),
            (safe, Path::new(bad), None),
            (safe, safe, Some(Path::new(bad))),
        ] {
            assert!(render_launchd(program, state, endpoints, false, false).is_err());
            assert!(render_systemd(program, state, endpoints, false, false).is_err());
        }
    }
    let invalid = Path::new(std::ffi::OsStr::from_bytes(b"/bad\xff"));
    assert!(render_launchd(invalid, safe, None, false, false).is_err());
    assert!(render_systemd(invalid, safe, None, false, false).is_err());
}

#[test]
fn both_renderers_refuse_fixed_endpoints_with_router_mapping_before_installation() {
    let path = Path::new("/safe");
    assert!(render_launchd(path, path, Some(path), false, true).is_err());
    assert!(render_systemd(path, path, Some(path), false, true).is_err());
}
