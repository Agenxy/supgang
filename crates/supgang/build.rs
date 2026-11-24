//! Embed the source commit at build time without requiring git in packaged builds.

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const COMMIT_HEX_LEN: usize = 40;
const UNKNOWN_COMMIT: &str = "unknown";
const MAX_VCS_INFO_BYTES: u64 = 4_096;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = std::io::stdout().lock();
    writeln!(output, "cargo::rerun-if-env-changed=SUPGANG_BUILD_COMMIT")?;

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("Cargo did not provide CARGO_MANIFEST_DIR")?);
    let vcs_info_path = manifest_dir.join(".cargo_vcs_info.json");
    if vcs_info_path.is_file() {
        emit_rerun_if_changed(&mut output, &vcs_info_path)?;
    }

    // Prefer .cargo_vcs_info.json when present so a packaged crate unpacked
    // under another Git repository never reports that outer repository's HEAD.
    let commit = vcs_info_commit(&vcs_info_path)
        .or(workspace_git_commit(&manifest_dir, &mut output)?)
        .or_else(env_commit)
        .unwrap_or_else(|| UNKNOWN_COMMIT.to_owned());

    let version = env::var("CARGO_PKG_VERSION")?;
    let short = if commit == UNKNOWN_COMMIT {
        UNKNOWN_COMMIT
    } else {
        commit.get(..7).unwrap_or(UNKNOWN_COMMIT)
    };
    let display = format!("{version} ({short})");

    writeln!(output, "cargo::rustc-env=SUPGANG_SOURCE_COMMIT={commit}")?;
    writeln!(output, "cargo::rustc-env=SUPGANG_VERSION_DISPLAY={display}")?;
    Ok(())
}

fn workspace_git_commit(
    manifest_dir: &Path,
    output: &mut impl Write,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Ok(canonical_manifest) = fs::canonicalize(manifest_dir) else {
        return Ok(None);
    };
    let Some(toplevel_raw) = run_git(manifest_dir, &["rev-parse", "--show-toplevel"]) else {
        return Ok(None);
    };
    let Ok(canonical_toplevel) = fs::canonicalize(PathBuf::from(toplevel_raw)) else {
        return Ok(None);
    };
    // Only read Git HEAD when CARGO_MANIFEST_DIR is this workspace's own crate
    // directory, never when a packaged tarball sits under an unrelated repo.
    if canonical_toplevel.join("crates").join("supgang") != canonical_manifest {
        return Ok(None);
    }

    let Some(commit) = run_git(manifest_dir, &["rev-parse", "--verify", "HEAD"]).and_then(|value| parse_commit(&value))
    else {
        return Ok(None);
    };

    if let Some(head_rel) = run_git(manifest_dir, &["rev-parse", "--git-path", "HEAD"]) {
        let head_path = resolve_git_path(manifest_dir, &head_rel);
        if head_path.is_file() {
            emit_rerun_if_changed(output, &head_path)?;
            if let Ok(head_contents) = fs::read_to_string(&head_path)
                && let Some(reference) = head_contents.trim().strip_prefix("ref:")
            {
                let reference = reference.trim();
                if let Some(ref_rel) = run_git(manifest_dir, &["rev-parse", "--git-path", reference]) {
                    let ref_path = resolve_git_path(manifest_dir, &ref_rel);
                    if ref_path.is_file() {
                        emit_rerun_if_changed(output, &ref_path)?;
                    }
                }
            }
        }
    }
    if let Some(packed_rel) = run_git(manifest_dir, &["rev-parse", "--git-path", "packed-refs"]) {
        let packed_path = resolve_git_path(manifest_dir, &packed_rel);
        if packed_path.is_file() {
            emit_rerun_if_changed(output, &packed_path)?;
        }
    }

    Ok(Some(commit))
}

fn run_git(manifest_dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(manifest_dir)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok().map(|text| text.trim().to_owned())
}

fn resolve_git_path(manifest_dir: &Path, relative_or_abs: &str) -> PathBuf {
    let path = PathBuf::from(relative_or_abs);
    if path.is_absolute() {
        path
    } else {
        manifest_dir.join(path)
    }
}

fn emit_rerun_if_changed(output: &mut impl Write, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(text) = path.to_str()
        && !text.chars().any(char::is_control)
    {
        writeln!(output, "cargo::rerun-if-changed={text}")?;
    }
    Ok(())
}

fn env_commit() -> Option<String> {
    env::var("SUPGANG_BUILD_COMMIT")
        .ok()
        .and_then(|value| parse_commit(&value))
}

fn vcs_info_commit(path: &Path) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    if metadata.len() > MAX_VCS_INFO_BYTES {
        return None;
    }
    let contents = fs::read_to_string(path).ok()?;
    let after_key = contents.split_once("\"sha1\"")?.1;
    let after_colon = after_key.trim_start().strip_prefix(':')?.trim_start();
    let after_quote = after_colon.strip_prefix('"')?;
    let (candidate, _) = after_quote.split_once('"')?;
    parse_commit(candidate)
}

fn parse_commit(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() == COMMIT_HEX_LEN && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(trimmed.to_ascii_lowercase())
    } else {
        None
    }
}
