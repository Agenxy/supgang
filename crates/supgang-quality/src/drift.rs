//! Scheduled check that every pinned tool is its latest upstream release.
//!
//! Gates measured on a stale compiler, linter or runner measure the past: a newer clippy found 33
//! issues on a tree that the pinned one called clean. An upstream release is not a defect in any
//! one pull request, so this runs on a schedule and never inside `all`. It asks `gh` and `uv`,
//! which the hosted runner already has, and makes no other connection.

use std::{fs, path::Path, process::Command};

/// One pinned tool and where its pin lives.
#[derive(Debug, Eq, PartialEq)]
struct Pin {
    name: String,
    pinned: String,
    source: String,
}

/// Compare every pin with upstream and fail if any is behind.
///
/// # Errors
/// Returns every outdated pin, or the first pin that cannot be read or looked up.
pub fn run(root: &Path, output: &mut dyn std::io::Write) -> Result<(), String> {
    let mut pins = vec![toolchain_pin(root)?];
    let directory = root.join(".github/workflows");
    let mut workflows = fs::read_dir(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .map(|entry| entry.map(|entry| entry.path()).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    workflows.sort();
    for path in workflows
        .iter()
        .filter(|path| path.extension().is_some_and(|extension| extension == "yml"))
    {
        let text = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let name = path
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
        pins.extend(workflow_pins(&text, &name)?);
    }
    pins.sort_by(|left, right| (&left.name, &left.source).cmp(&(&right.name, &right.source)));
    pins.dedup_by(|left, right| left.name == right.name && left.pinned == right.pinned);
    let mut behind = Vec::new();
    for pin in &pins {
        let latest = latest(&pin.name)?;
        let state = if latest == pin.pinned { "current" } else { "BEHIND" };
        writeln!(
            output,
            "{state}: {} {} ({}), latest {latest}",
            pin.name, pin.pinned, pin.source
        )
        .map_err(|error| error.to_string())?;
        if latest != pin.pinned {
            behind.push(format!("{} {} -> {latest}", pin.name, pin.pinned));
        }
    }
    if behind.is_empty() {
        Ok(())
    } else {
        Err(format!("pinned tools behind upstream: {}", behind.join(", ")))
    }
}

fn toolchain_pin(root: &Path) -> Result<Pin, String> {
    let text = fs::read_to_string(root.join("rust-toolchain.toml")).map_err(|error| error.to_string())?;
    let pinned = quoted_value(&text, "channel = ").ok_or("rust-toolchain.toml has no channel")?;
    Ok(Pin {
        name: "rust-lang/rust".to_owned(),
        pinned,
        source: "rust-toolchain.toml".to_owned(),
    })
}

/// Actions pinned by commit with a `# vX.Y.Z` label, plus the uv and Python versions setup-uv installs.
fn workflow_pins(text: &str, workflow: &str) -> Result<Vec<Pin>, String> {
    let mut pins = Vec::new();
    for line in text.lines().map(str::trim) {
        if let Some(used) = line.strip_prefix("uses: ").or_else(|| line.strip_prefix("- uses: ")) {
            let (action, label) = used
                .split_once('@')
                .ok_or_else(|| format!("{workflow}: unpinned {used}"))?;
            let label = label
                .split_once("# ")
                .map(|(_, label)| label.trim())
                .ok_or_else(|| format!("{workflow}: {action} has no `# vX.Y.Z` release label"))?;
            pins.push(Pin {
                name: action.to_owned(),
                pinned: label.to_owned(),
                source: workflow.to_owned(),
            });
        } else if let Some(version) = quoted_value(line, "version: ") {
            pins.push(Pin {
                name: "astral-sh/uv".to_owned(),
                pinned: version,
                source: workflow.to_owned(),
            });
        } else if let Some(version) = quoted_value(line, "python-version: ") {
            pins.push(Pin {
                name: "python".to_owned(),
                pinned: version,
                source: workflow.to_owned(),
            });
        }
    }
    Ok(pins)
}

fn quoted_value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(key))
        .and_then(|value| value.strip_prefix('"'))
        .and_then(|value| value.split_once('"'))
        .map(|(value, _)| value.to_owned())
}

fn latest(name: &str) -> Result<String, String> {
    if name == "python" {
        return latest_python();
    }
    let tag = capture(
        "gh",
        &[
            "release", "view", "--repo", name, "--json", "tagName", "--jq", ".tagName",
        ],
    )?;
    // Actions are labelled with their `v` tag; Rust and uv tags carry none.
    Ok(tag.trim().to_owned())
}

/// The newest stable `CPython` that uv can install, which is what `setup-uv` provides.
fn latest_python() -> Result<String, String> {
    let listing = capture(
        "uv",
        &[
            "python",
            "list",
            "--only-downloads",
            "--all-versions",
            "--output-format",
            "json",
        ],
    )?;
    let entries: Vec<serde_json::Value> = serde_json::from_str(&listing).map_err(|error| error.to_string())?;
    entries
        .iter()
        .filter(|entry| entry["implementation"] == "cpython" && entry["variant"] == "default")
        .filter_map(|entry| entry["version"].as_str())
        .filter(|version| version.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.'))
        .filter_map(|version| {
            let parts = version
                .split('.')
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            Some((parts, version.to_owned()))
        })
        .max()
        .map(|(_, version)| version)
        .ok_or_else(|| "uv listed no stable CPython".to_owned())
}

fn capture(program: &str, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| format!("could not start {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{program} {} returned {}", arguments.join(" "), output.status));
    }
    String::from_utf8(output.stdout).map_err(|_| format!("{program} printed non-UTF-8 output"))
}

#[cfg(test)]
mod tests {
    use super::{quoted_value, workflow_pins};

    #[test]
    fn workflow_pins_read_labelled_actions_and_setup_uv_versions() -> Result<(), String> {
        let text = "      - uses: actions/checkout@3d3c42e5 # v7.0.1\n        uses: astral-sh/setup-uv@68559e99 # v10.3.3\n          version: \"0.13.6\"\n          python-version: \"3.15.2\"\n";
        let pins = workflow_pins(text, "ci.yml")?;
        let names: Vec<_> = pins
            .iter()
            .map(|pin| (pin.name.as_str(), pin.pinned.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("actions/checkout", "v7.0.1"),
                ("astral-sh/setup-uv", "v10.3.3"),
                ("astral-sh/uv", "0.13.6"),
                ("python", "3.15.2"),
            ]
        );
        Ok(())
    }

    #[test]
    fn an_action_without_a_release_label_is_refused() {
        let refused = workflow_pins("      - uses: actions/checkout@3d3c42e5\n", "ci.yml");
        assert_eq!(
            refused,
            Err("ci.yml: actions/checkout has no `# vX.Y.Z` release label".to_owned())
        );
    }

    #[test]
    fn the_toolchain_channel_is_read_exactly() {
        assert_eq!(
            quoted_value("[toolchain]\nchannel = \"1.99.1\"\n", "channel = "),
            Some("1.99.1".to_owned())
        );
        assert_eq!(quoted_value("channel = 1.99.1\n", "channel = "), None);
    }
}
