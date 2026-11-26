#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Classify changed repository paths for CI gating. Apache-2.0.

A pull request is docs-only only when every changed path is a top-level
Markdown file or a non-vector documentation asset under `docs/`. Test
vectors under `docs/vectors/` are consumed by Rust and Python suites and
always trigger the full gate. Non-pull-request events (such as pushes to
`main`), empty diffs, and unexpected paths fail closed to the full gate.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
from typing import Sequence

DOCS_ALLOWED_SUFFIXES = frozenset({
    ".md",
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".txt",
})


def is_docs_only_path(raw_path: str) -> bool:
    """Return True only for pure documentation paths outside `docs/vectors/`."""
    if not raw_path or raw_path.startswith("/") or "\\" in raw_path:
        return False
    pure = PurePosixPath(raw_path)
    parts = pure.parts
    if not parts or ".." in parts or "." in parts:
        return False
    suffix = pure.suffix.lower()
    if len(parts) == 1:
        return suffix == ".md"
    if parts[0] != "docs":
        return False
    if len(parts) >= 2 and parts[1] == "vectors":
        return False
    return suffix in DOCS_ALLOWED_SUFFIXES


def classify_paths(event: str, paths: Sequence[str]) -> bool:
    """Return True iff the event is a pull request touching only pure docs."""
    if event != "pull_request":
        return False
    if not paths:
        return False
    return all(is_docs_only_path(path) for path in paths)


def git_changed_paths(repo_root: Path, base: str, head: str) -> list[str]:
    """Return changed file paths between base and head without rename collapsing."""
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "diff",
            "--no-renames",
            "--name-only",
            "-z",
            f"{base}...{head}",
        ],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git diff {base}...{head} failed: {stderr}")
    raw = result.stdout
    if not raw:
        return []
    return [entry.decode("utf-8") for entry in raw.split(b"\0") if entry]


def write_github_output(output_path: Path, docs_only: bool) -> None:
    """Append boolean outputs in GitHub Actions GITHUB_OUTPUT format."""
    docs_value = "true" if docs_only else "false"
    full_value = "false" if docs_only else "true"
    with output_path.open("a", encoding="utf-8") as handle:
        handle.write(f"docs_only={docs_value}\n")
        handle.write(f"full_gate={full_value}\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify changed paths for CI.")
    parser.add_argument("--event", required=True, help="GitHub Actions event name")
    parser.add_argument("--base", default="", help="Base commit SHA for pull requests")
    parser.add_argument("--head", default="HEAD", help="Head commit SHA for pull requests")
    parser.add_argument(
        "--repo",
        default=str(Path(__file__).resolve().parent.parent),
        help="Repository root directory",
    )
    parser.add_argument(
        "--github-output",
        default="",
        help="Optional GITHUB_OUTPUT file path to append outputs to",
    )
    args = parser.parse_args(argv)

    paths: list[str] = []
    if args.event == "pull_request":
        if not args.base:
            print("error: --base is required for pull_request events", file=sys.stderr)
            return 2
        try:
            paths = git_changed_paths(Path(args.repo), args.base, args.head)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    docs_only = classify_paths(args.event, paths)
    if args.github_output:
        write_github_output(Path(args.github_output), docs_only)

    summary = {
        "event": args.event,
        "changed_count": len(paths),
        "docs_only": docs_only,
        "full_gate": not docs_only,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
