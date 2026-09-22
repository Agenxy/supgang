#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Exercise the real helper's public framing and refusal paths without creating keys."""

import argparse
from pathlib import Path
import subprocess


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", required=True, type=Path)
    args = parser.parse_args()
    helper = str(args.helper.resolve())
    version = b"supgang/custody/v1 "

    def exchange(request: bytes, *arguments: str) -> bytes:
        result = subprocess.run([helper, *arguments], input=request, capture_output=True, timeout=10, check=True)
        assert not result.stderr, "the helper wrote unexpected diagnostics"
        assert len(result.stdout) <= 16384, "response exceeds the wire bound"
        return result.stdout

    probe = exchange(version + b"probe\n")
    assert probe in [version + b"ok probe supgang-secure-enclave ready\n",
                     version + b"ok probe supgang-secure-enclave no-hardware\n"]
    malformed = [b"", b"supgang/custody/v2 probe\n", version + b"probe\r\n",
                 version + b"probe\nextra\n", version + b"probe", version + b"unknown\n",
                 version + b"generate --maybe\n", version + b"public --sealed zz\n",
                 version + b"public --sealed AA\n", version + b"sign --sealed 01 00\n",
                 b"a" * 16385 + b"\n"]
    for request in malformed:
        assert exchange(request) == version + b"error protocol\n", "malformed framing was not refused"
    assert exchange(version + b"probe\n", "probe") == version + b"error protocol\n"
    print(f"Helper protocol passed: product probe, {len(malformed)} malformed requests, argv refusal; no keys created.")


if __name__ == "__main__":
    main()
