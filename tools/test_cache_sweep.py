#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Bounded cache-sweep safety tests. Apache-2.0."""

import fcntl
import os
from pathlib import Path
import tempfile
import unittest

import cache_sweep


class CacheSweepTests(unittest.TestCase):
    def test_dry_run_and_age_then_apply(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lane = root / ("rustc-1.97.1-aarch64-apple-darwin-" + "a" * 16) / "dev" / ("flags-" + "b" * 16)
            lane.mkdir(parents=True)
            marker = lane / ".agenxy-lane.lock"
            marker.touch()
            (lane / "dependency.rlib").write_bytes(b"artifact")
            now = 1_000_000.0
            os.utime(marker, (now - 31 * 86400, now - 31 * 86400))
            self.assertEqual(cache_sweep.sweep(root, apply=False, older_than_days=30, now=now), (1, 8))
            self.assertTrue(lane.exists())
            self.assertEqual(cache_sweep.sweep(root, apply=True, older_than_days=30, now=now), (1, 8))
            self.assertFalse(lane.exists())

    def test_active_lock_prevents_reclaim_and_symlinks_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lane = root / ("rustc-1.97.1-aarch64-apple-darwin-" + "a" * 16) / "dev" / ("flags-" + "b" * 16)
            lane.mkdir(parents=True)
            marker = lane / ".agenxy-lane.lock"
            marker.touch()
            now = 1_000_000.0
            os.utime(marker, (now - 31 * 86400, now - 31 * 86400))
            with marker.open("rb") as lock:
                fcntl.flock(lock, fcntl.LOCK_SH)
                self.assertEqual(cache_sweep.sweep(root, apply=True, older_than_days=30, now=now), (0, 0))
            (lane / "outside").symlink_to(root / "unrelated")
            with self.assertRaisesRegex(ValueError, "symlink or special file"):
                cache_sweep.sweep(root, apply=True, older_than_days=30, now=now)
            self.assertTrue(lane.exists())


if __name__ == "__main__":
    unittest.main()
