#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Update every pinned Supgang workspace version reference together. Apache-2.0.

Re-runnable on a draft release-bump branch so the release lead can switch the
target version (for example between 0.2.0 and 0.2.0-alpha.22) in one command
once the owner selects the release version.
"""

from __future__ import annotations

import argparse
from datetime import date
import os
from pathlib import Path
import re
import subprocess
import sys


SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[a-z0-9]+(?:\.[a-z0-9]+)*)?$")
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
WORKSPACE_VERSION_RE = re.compile(
    r'(\[workspace\.package\]\nversion = ")([^"]+)(")',
    re.MULTILINE,
)
MAX_VERSION_LEN = 64


def validate_version(version: str) -> str:
    if not version or len(version) > MAX_VERSION_LEN or not SEMVER_RE.fullmatch(version):
        raise ValueError(
            f"invalid SemVer version {version!r}; expected MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-pre.N (no leading 'v')"
        )
    return version


def validate_date(value: str) -> str:
    if not DATE_RE.fullmatch(value):
        raise ValueError(f"invalid release date {value!r}; expected YYYY-MM-DD")
    return value


def read_workspace_version(root: Path) -> str:
    manifest = (root / "Cargo.toml").read_text(encoding="utf-8")
    matches = WORKSPACE_VERSION_RE.findall(manifest)
    if len(matches) != 1:
        raise ValueError("Cargo.toml must have exactly one [workspace.package] version")
    return matches[0][1]


def replace_exact(text: str, old: str, new: str, expected_count: int, label: str) -> str:
    actual = text.count(old)
    if actual != expected_count:
        raise ValueError(f"{label}: expected {expected_count} occurrence(s) of {old!r}, found {actual}")
    return text.replace(old, new)


def plan_updates(root: Path, new_version: str, release_date: str, update_changelog: bool) -> dict[Path, str]:
    validate_version(new_version)
    validate_date(release_date)
    old_version = read_workspace_version(root)

    planned: dict[Path, str] = {}

    root_manifest_path = root / "Cargo.toml"
    root_manifest = root_manifest_path.read_text(encoding="utf-8")
    root_manifest = replace_exact(
        root_manifest,
        f'[workspace.package]\nversion = "{old_version}"\n',
        f'[workspace.package]\nversion = "{new_version}"\n',
        1,
        "Cargo.toml [workspace.package]",
    )
    root_manifest = replace_exact(
        root_manifest,
        f'supgang-acl = {{ path = "crates/supgang-acl", version = "={old_version}" }}',
        f'supgang-acl = {{ path = "crates/supgang-acl", version = "={new_version}" }}',
        1,
        "Cargo.toml supgang-acl pin",
    )
    planned[root_manifest_path] = root_manifest

    cli_manifest_path = root / "crates/supgang-cli/Cargo.toml"
    cli_manifest = cli_manifest_path.read_text(encoding="utf-8")
    cli_manifest = replace_exact(
        cli_manifest,
        f'supgang-core = {{ path = "../supgang", version = "={old_version}" }}',
        f'supgang-core = {{ path = "../supgang", version = "={new_version}" }}',
        1,
        "crates/supgang-cli/Cargo.toml",
    )
    planned[cli_manifest_path] = cli_manifest

    quality_main_path = root / "crates/supgang-quality/src/main.rs"
    quality_main = quality_main_path.read_text(encoding="utf-8")
    quality_main = replace_exact(
        quality_main,
        f'"supgang-core = {{ path = \\"../supgang\\", version = \\"={old_version}\\" }}",',
        f'"supgang-core = {{ path = \\"../supgang\\", version = \\"={new_version}\\" }}",',
        1,
        "crates/supgang-quality/src/main.rs",
    )
    planned[quality_main_path] = quality_main

    mcp_fixture_path = root / "crates/supgang/assets/mcp-sdk-client.ndjson"
    mcp_fixture = mcp_fixture_path.read_text(encoding="utf-8")
    mcp_fixture = replace_exact(
        mcp_fixture,
        f'"version":"{old_version}"',
        f'"version":"{new_version}"',
        2,
        "crates/supgang/assets/mcp-sdk-client.ndjson",
    )
    planned[mcp_fixture_path] = mcp_fixture

    if update_changelog:
        changelog_path = root / "CHANGELOG.md"
        changelog = changelog_path.read_text(encoding="utf-8")
        planned[changelog_path] = update_changelog_text(changelog, old_version, new_version, release_date)

    return planned


def update_changelog_text(text: str, old_version: str, new_version: str, release_date: str) -> str:
    draft_heading_re = re.compile(
        rf"^(## Unreleased\n\n)(## {re.escape(old_version)} - [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}\n)",
        re.MULTILINE,
    )
    if draft_heading_re.search(text):
        return draft_heading_re.sub(
            rf"\g<1>## {new_version} - {release_date}\n",
            text,
            count=1,
        )

    marker = "## Unreleased\n"
    if text.count(marker) != 1:
        raise ValueError("CHANGELOG.md must contain exactly one '## Unreleased' heading")
    replacement = f"## Unreleased\n\n## {new_version} - {release_date}\n"
    return text.replace(marker, replacement, 1)


def check_consistency(root: Path) -> str:
    current = read_workspace_version(root)
    validate_version(current)
    plan_updates(root, current, "2000-01-01", update_changelog=False)
    lock_path = root / "Cargo.lock"
    if lock_path.is_file():
        lock_text = lock_path.read_text(encoding="utf-8")
        for crate in ("supgang", "supgang-acl", "supgang-core", "supgang-quality"):
            expected = f'name = "{crate}"\nversion = "{current}"\n'
            if expected not in lock_text:
                raise ValueError(f"Cargo.lock is missing {crate} at version {current}")
    return current


def refresh_lockfile(root: Path) -> None:
    env = dict(os.environ)
    cargo_bin = Path.home() / ".cargo" / "bin"
    if cargo_bin.is_dir():
        env["PATH"] = f'{cargo_bin}{os.pathsep}{env.get("PATH", "")}'
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--offline"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cargo metadata --offline failed: {result.stderr.strip()}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", help="target SemVer version (e.g. 0.2.0 or 0.2.0-alpha.22)")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="repository root")
    parser.add_argument("--date", default=date.today().isoformat(), help="release date YYYY-MM-DD for CHANGELOG.md")
    parser.add_argument("--check", action="store_true", help="verify every pinned file matches Cargo.toml")
    parser.add_argument("--dry-run", action="store_true", help="validate and print planned changes without writing")
    parser.add_argument("--no-changelog", action="store_true", help="skip CHANGELOG.md heading promotion")
    parser.add_argument("--no-lock", action="store_true", help="skip Cargo.lock refresh")
    args = parser.parse_args(argv)

    try:
        if args.check:
            current = check_consistency(args.root)
            print(f"version-check ok: {current}")
            return 0
        if not args.version:
            parser.error("provide a target version or --check")
        planned = plan_updates(args.root, args.version, args.date, update_changelog=not args.no_changelog)
        if args.dry_run:
            for path in planned:
                print(f"would update {path.relative_to(args.root)}")
            return 0
        for path, content in planned.items():
            path.write_text(content, encoding="utf-8")
        if not args.no_lock:
            refresh_lockfile(args.root)
        verified = check_consistency(args.root)
        print(f"bumped workspace version to {verified}")
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print(f"bump_version: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
