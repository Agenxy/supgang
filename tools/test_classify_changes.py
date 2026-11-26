#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Unit and git-repository tests for tools/classify_changes.py. Apache-2.0."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


def load_module():
    script = Path(__file__).resolve().parent / "classify_changes.py"
    spec = importlib.util.spec_from_file_location("classify_changes", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = load_module()


class ClassifyChangesTest(unittest.TestCase):
    def test_pure_docs_pull_request_is_docs_only(self):
        paths = [
            "README.md",
            "CHANGELOG.md",
            "docs/architecture/0008-scoped-guest-credentials.md",
            "docs/development/release-runbook.md",
            "docs/icon.svg",
        ]
        self.assertTrue(MOD.classify_paths("pull_request", paths))

    def test_push_event_never_uses_docs_only_fast_path(self):
        self.assertFalse(MOD.classify_paths("push", ["README.md", "docs/product-identity.md"]))

    def test_empty_diff_fails_closed_to_full_gate(self):
        self.assertFalse(MOD.classify_paths("pull_request", []))

    def test_vectors_under_docs_always_require_full_gate(self):
        for vector_path in [
            "docs/vectors/sign-v1/agenxy-launcher-install.json",
            "docs/vectors/lms-nc0-test/README.md",
            "docs/vectors/owner-action-draft-v1/manifest.json",
            "docs/vectors/mcp/status-call.ndjson",
        ]:
            with self.subTest(path=vector_path):
                self.assertFalse(MOD.classify_paths("pull_request", [vector_path]))

    def test_code_workflows_and_cargo_files_require_full_gate(self):
        for path in [
            "Cargo.toml",
            "Cargo.lock",
            "deny.toml",
            "Makefile",
            "LICENSE",
            ".github/workflows/ci.yml",
            "crates/supgang/src/lib.rs",
            "crates/supgang/README.md",
            "third_party/netwatch/README.md",
            "tools/check.py",
            "docs/helper.py",
            "docs/snippet.rs",
            "docs/data.json",
            "../README.md",
            "/README.md",
        ]:
            with self.subTest(path=path):
                self.assertFalse(MOD.classify_paths("pull_request", [path]))

    def test_mixed_docs_and_code_requires_full_gate(self):
        self.assertFalse(
            MOD.classify_paths(
                "pull_request",
                ["docs/development/release-runbook.md", "crates/supgang-quality/src/main.rs"],
            )
        )

    def test_git_diff_treats_rename_from_code_to_docs_as_full_gate(self):
        with tempfile.TemporaryDirectory(prefix="supgang-classify-") as temp_dir:
            repo = Path(temp_dir)
            self._git(repo, "init", "-b", "main")
            self._git(repo, "config", "user.name", "Test")
            self._git(repo, "config", "user.email", "test@example.invalid")

            (repo / "crates").mkdir()
            (repo / "docs").mkdir()
            (repo / "crates" / "demo.rs").write_text("pub fn demo() {}\n", encoding="utf-8")
            (repo / "docs" / "guide.md").write_text("# Guide\n", encoding="utf-8")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-m", "base")
            base_sha = self._git(repo, "rev-parse", "HEAD")

            # Docs-only branch.
            self._git(repo, "checkout", "-b", "docs-only")
            (repo / "docs" / "guide.md").write_text("# Updated guide\n", encoding="utf-8")
            self._git(repo, "add", "docs/guide.md")
            self._git(repo, "commit", "-m", "docs edit")
            docs_sha = self._git(repo, "rev-parse", "HEAD")
            docs_paths = MOD.git_changed_paths(repo, base_sha, docs_sha)
            self.assertEqual(docs_paths, ["docs/guide.md"])
            self.assertTrue(MOD.classify_paths("pull_request", docs_paths))

            # Rename from code into docs must NOT be classified as docs-only.
            self._git(repo, "checkout", "-b", "rename-code", base_sha)
            self._git(repo, "mv", "crates/demo.rs", "docs/demo.md")
            self._git(repo, "commit", "-m", "rename code to doc")
            rename_sha = self._git(repo, "rev-parse", "HEAD")
            rename_paths = MOD.git_changed_paths(repo, base_sha, rename_sha)
            self.assertIn("crates/demo.rs", rename_paths)
            self.assertFalse(MOD.classify_paths("pull_request", rename_paths))

            # Verify GITHUB_OUTPUT writer.
            gh_out = repo / "github_output.txt"
            rc = MOD.main([
                "--event",
                "pull_request",
                "--base",
                base_sha,
                "--head",
                docs_sha,
                "--repo",
                str(repo),
                "--github-output",
                str(gh_out),
            ])
            self.assertEqual(rc, 0)
            self.assertEqual(
                gh_out.read_text(encoding="utf-8"),
                "docs_only=true\nfull_gate=false\n",
            )

    @staticmethod
    def _git(repo: Path, *args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()


if __name__ == "__main__":
    unittest.main()
