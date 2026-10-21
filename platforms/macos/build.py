#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Build the optional native helper and place it beside a selected Supgang binary.

SwiftPM products stay in a user cache, outside the source-policy walk. Cargo never
invokes this script. No signing identity, provisioning profile or network is used.
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--beside", type=Path, required=True, help="existing supgang or test executable")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("WrongPlatform: the Secure Enclave helper is for macOS")
    swift = shutil.which("swift")
    if swift is None:
        parser.error("ToolchainMissing: install the Swift toolchain to build the optional helper")
    if not args.beside.is_file():
        parser.error("--beside must name an existing executable")
    package = Path(__file__).resolve().parent
    scratch = Path.home() / ".cache" / "agenxy" / "supgang-macos"
    scratch.mkdir(parents=True, exist_ok=True)
    command = [swift, "build", "--package-path", str(package), "--scratch-path", str(scratch),
               "--cache-path", str(scratch / "cache"), "--config-path", str(scratch / "config"),
               "--security-path", str(scratch / "security"),
               "--disable-sandbox", "--configuration", "release", "-debug-info-format", "none",
               "--product", "supgang-secure-enclave"]
    environment = dict(os.environ, CLANG_MODULE_CACHE_PATH=str(scratch / "clang-cache"))
    subprocess.run(command, check=True, timeout=300, env=environment)
    # show-bin-path handles SwiftPM's target-triple directory without guessing it.
    result = subprocess.run(command + ["--show-bin-path"], check=True, capture_output=True, text=True, timeout=30,
                            env=environment)
    source = Path(result.stdout.strip()) / "supgang-secure-enclave"
    destination = args.beside.resolve().parent / "supgang-secure-enclave"
    shutil.copyfile(source, destination)
    destination.chmod(0o755)
    print(f"Built {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
