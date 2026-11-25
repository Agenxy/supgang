#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Regression tests for tools/bump_version.py. Apache-2.0."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import bump_version


class BumpVersionTests(unittest.TestCase):
    def _write_fixture(self, root: Path, version: str = "0.2.0-alpha.21") -> None:
        (root / "crates/supgang-cli").mkdir(parents=True)
        (root / "crates/supgang-quality/src").mkdir(parents=True)
        (root / "crates/supgang/assets").mkdir(parents=True)

        (root / "Cargo.toml").write_text(
            f'[workspace.package]\nversion = "{version}"\nedition = "2024"\n\n'
            f'[workspace.dependencies]\nsupgang-acl = {{ path = "crates/supgang-acl", version = "={version}" }}\n',
            encoding="utf-8",
        )
        (root / "crates/supgang-cli/Cargo.toml").write_text(
            f'[dependencies]\nsupgang-core = {{ path = "../supgang", version = "={version}" }}\n',
            encoding="utf-8",
        )
        (root / "crates/supgang-quality/src/main.rs").write_text(
            f'    for required in [\n'
            f'        "supgang-core = {{ path = \\"../supgang\\", version = \\"={version}\\" }}",\n'
            f'    ] {{}}\n',
            encoding="utf-8",
        )
        (root / "crates/supgang/assets/mcp-sdk-client.ndjson").write_text(
            f'S:{{"serverInfo":{{"version":"{version}"}}}}\n'
            f'S:{{"serverInfo":{{"version":"{version}"}}}}\n',
            encoding="utf-8",
        )
        (root / "CHANGELOG.md").write_text(
            "# Changelog\n\n## Unreleased\n\n- Feature entry.\n\n## 0.1.0\n\n- Initial.\n",
            encoding="utf-8",
        )

    def test_repository_version_pins_are_consistent(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        current = bump_version.check_consistency(repo_root)
        self.assertTrue(current)

    def test_bump_and_reparameterise_between_candidate_versions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_fixture(root)

            rc = bump_version.main(["0.2.0", "--root", str(root), "--date", "2026-11-24", "--no-lock"])
            self.assertEqual(rc, 0)
            self.assertEqual(bump_version.check_consistency(root), "0.2.0")
            changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
            self.assertIn("## Unreleased\n\n## 0.2.0 - 2026-11-24\n\n- Feature entry.", changelog)

            # Re-run to switch the same draft PR to a prerelease version cleanly.
            rc = bump_version.main(["0.2.0-alpha.22", "--root", str(root), "--date", "2026-11-25", "--no-lock"])
            self.assertEqual(rc, 0)
            self.assertEqual(bump_version.check_consistency(root), "0.2.0-alpha.22")
            changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
            self.assertIn("## Unreleased\n\n## 0.2.0-alpha.22 - 2026-11-25\n\n- Feature entry.", changelog)
            self.assertNotIn("## 0.2.0 - 2026-11-24", changelog)

    def test_invalid_versions_are_refused(self) -> None:
        for bad in ("", "v0.2.0", "0.2", "0.2.0+meta", "0.2.0 alpha", "01.2.3"):
            with self.assertRaises(ValueError):
                bump_version.validate_version(bad)

    def test_mismatch_fails_closed_without_modifying_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_fixture(root)
            cli_path = root / "crates/supgang-cli/Cargo.toml"
            cli_path.write_text('supgang-core = { path = "../supgang", version = "=9.9.9" }\n', encoding="utf-8")

            before_root = (root / "Cargo.toml").read_text(encoding="utf-8")
            rc = bump_version.main(["0.2.0", "--root", str(root), "--date", "2026-11-24", "--no-lock"])
            self.assertNotEqual(rc, 0)
            self.assertEqual((root / "Cargo.toml").read_text(encoding="utf-8"), before_root)


if __name__ == "__main__":
    unittest.main()
