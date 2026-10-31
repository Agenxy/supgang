#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Selection controls for Supgang's shared Cargo output. Apache-2.0."""

import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import cargo_cache


class CargoCacheSelectionTests(unittest.TestCase):
    def test_compiler_profile_and_flags_have_separate_namespaces(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            compiler = Path(temporary) / "rustc"
            compiler.write_bytes(b"selected compiler binary")
            manifests = Path(temporary) / "lib" / "rustlib"
            manifests.mkdir(parents=True)
            for name in ("components", "multirust-config.toml", "multirust-channel-manifest.toml"):
                (manifests / name).write_text("selected component")
            environment = {
                "HOME": temporary,
                "AGENXY_CARGO_TARGET_ROOT": str(Path(temporary) / "shared"),
            }
            banner = "rustc 1.97.1\nhost: aarch64-apple-darwin\nrelease: 1.97.1"

            def output(command: list[str], _environment: dict[str, str]) -> str:
                if command[:2] == ["rustup", "which"]:
                    return str(compiler)
                if command == ["rustc", "--print", "sysroot"]:
                    return temporary
                return banner

            with patch.object(cargo_cache, "read_output", side_effect=output):
                first = cargo_cache.namespace("dev", environment)
                self.assertEqual(first, cargo_cache.namespace("dev", environment))
                self.assertNotEqual(first, cargo_cache.namespace("release", environment))
                environment["RUSTFLAGS"] = "-Ctarget-cpu=native"
                self.assertNotEqual(first, cargo_cache.namespace("dev", environment))
                environment.pop("RUSTFLAGS")
                environment["RUSTC_WRAPPER"] = "/selected/custom-wrapper"
                self.assertNotEqual(first, cargo_cache.namespace("dev", environment))
                environment.pop("RUSTC_WRAPPER")
                environment["CARGO_INCREMENTAL"] = "1"
                self.assertNotEqual(first, cargo_cache.namespace("dev", environment))
                environment.pop("CARGO_INCREMENTAL")
                environment["CARGO_PROFILE_DEV_CODEGEN_UNITS"] = "1"
                self.assertNotEqual(first, cargo_cache.namespace("dev", environment))
                environment.pop("CARGO_PROFILE_DEV_CODEGEN_UNITS")
                compiler.write_bytes(b"different compiler with same banner")
                self.assertNotEqual(first, cargo_cache.namespace("dev", environment))
                compiler.write_bytes(b"selected compiler binary")
                (manifests / "components").write_text("changed component")
                self.assertNotEqual(first, cargo_cache.namespace("dev", environment))

    def test_wrong_compiler_pin_is_rejected_before_running_cargo(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.97.1"\n')
            with patch.object(cargo_cache, "read_output", return_value="release: 1.98.1"):
                with self.assertRaisesRegex(ValueError, "does not match the repository pin"):
                    cargo_cache.pinned_environment(root, {"HOME": temporary, "PATH": "/usr/bin"})


if __name__ == "__main__":
    unittest.main()
