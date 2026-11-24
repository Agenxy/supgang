#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Offline two-way SLIP-39 cross-check against hash-pinned shamir-mnemonic 0.3.0. Apache-2.0."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

WHEEL_NAME = "shamir_mnemonic-0.3.0-py3-none-any.whl"
WHEEL_SHA256 = "188c6b5bd00d5e756e12e2b186c3cb7c98ff7ff44df608d4c1d2077f6b6e730f"
SDIST_SHA256 = "bc04886a1ddfe2a64d8a3ec51abf0f664d98d5b557cc7e78a8ad2d10a1d87438"
ROOT = Path(__file__).resolve().parent.parent

WORKER_CODE = r"""
import itertools
import json
import secrets
import subprocess
import sys
import shamir_mnemonic

assert shamir_mnemonic.__file__, "shamir_mnemonic not loaded"

rust_bin = sys.argv[1]


def run_rust(stdin_text: str) -> tuple[bool, list[str]]:
    proc = subprocess.run(
        [rust_bin],
        input=stdin_text.encode("utf-8"),
        capture_output=True,
        check=True,
    )
    lines = proc.stdout.decode("utf-8").splitlines()
    assert lines, "empty response from Rust helper"
    if lines[0] == "OK":
        return True, lines[1:]
    return False, lines


# 1. Two-way 2-of-3 NC0 ceremony scheme (32-byte master, empty passphrase)
test_masters = [
    bytes(range(32)),
    bytes([0x00] * 32),
    bytes([0xFF] * 32),
    secrets.token_bytes(32),
    secrets.token_bytes(32),
]

rust_to_py_pairs = 0
py_to_rust_pairs = 0

for master in test_masters:
    master_hex = master.hex()

    # Direction A: Rust split_2_of_3 -> Python combine_mnemonics for all 3 pairs
    ok, rust_shares = run_rust(f"split_2_of_3 {master_hex}\n")
    assert ok, f"Rust split_2_of_3 failed: {rust_shares}"
    assert len(rust_shares) == 3
    for pair in itertools.combinations(rust_shares, 2):
        recovered = shamir_mnemonic.combine_mnemonics(list(pair), b"")
        assert recovered == master, "Rust->Python mismatch"
        rust_to_py_pairs += 1

    # Direction B: Python generate_mnemonics -> Rust combine_mnemonics
    # Test both extendable=True/exponent=1 and extendable=False/exponent=0.
    for extendable, exponent in [(True, 1), (False, 0)]:
        py_shares = shamir_mnemonic.generate_mnemonics(
            1, [(2, 3)], master, b"", extendable=extendable, iteration_exponent=exponent
        )[0]
        assert len(py_shares) == 3
        for pair in itertools.combinations(py_shares, 2):
            ok, out = run_rust("combine\n" + "\n".join(pair) + "\n")
            assert ok and len(out) == 1, f"Rust combine failed: {out}"
            assert out[0] == master_hex, "Python->Rust mismatch"
            py_to_rust_pairs += 1

# 2. Multi-group (2-of-2 groups, 2-of-3 members each) + non-empty ASCII passphrase
multi_master = secrets.token_bytes(32)
multi_pass = b"test-only-slip39-passphrase"
py_multi = shamir_mnemonic.generate_mnemonics(
    2, [(2, 3), (2, 3)], multi_master, multi_pass, extendable=True, iteration_exponent=1
)
selected = [py_multi[0][0], py_multi[0][2], py_multi[1][1], py_multi[1][2]]
ok, out = run_rust(f"combine {multi_pass.hex()}\n" + "\n".join(selected) + "\n")
assert ok and out == [multi_master.hex()], f"Multi-group P->R failed: {out}"

ok, lines = run_rust(f"split 0 1 2 2:3,2:3 {multi_pass.hex()} {multi_master.hex()}\n")
assert ok, f"Multi-group Rust split failed: {lines}"
by_group = {0: [], 1: []}
for line in lines:
    g_idx, mnemonic = line.split("|", 1)
    by_group[int(g_idx)].append(mnemonic)
recovered_multi = shamir_mnemonic.combine_mnemonics(
    [by_group[0][0], by_group[0][1], by_group[1][0], by_group[1][2]],
    multi_pass,
)
assert recovered_multi == multi_master, "Multi-group R->P mismatch"

# 3. Negative checks: single share and tampered checksum must fail on both sides
ok_single, _ = run_rust("combine\n" + py_shares[0] + "\n")
assert not ok_single, "Rust accepted single 2-of-3 share"

words = rust_shares[0].split()
words[-1] = "acid" if words[-1] == "academic" else "academic"
bad_share = " ".join(words)
ok_bad, _ = run_rust("combine\n" + bad_share + "\n" + rust_shares[1] + "\n")
assert not ok_bad, "Rust accepted tampered checksum"
try:
    shamir_mnemonic.combine_mnemonics([bad_share, rust_shares[1]], b"")
    raise AssertionError("Python accepted tampered checksum")
except shamir_mnemonic.MnemonicError:
    pass

print(json.dumps({
    "status": "ok",
    "shamir_mnemonic_file": shamir_mnemonic.__file__,
    "rust_to_python_pairs_verified": rust_to_py_pairs,
    "python_to_rust_pairs_verified": py_to_rust_pairs,
    "multi_group_two_way": "ok",
    "negative_checks": "ok",
}, indent=2))
"""


def build_rust_helper() -> Path:
    env = os.environ.copy()
    cargo_bin = str(Path.home() / ".cargo" / "bin")
    env["PATH"] = f"{cargo_bin}:{env.get('PATH', '')}"
    subprocess.run(
        ["cargo", "build", "--locked", "--package", "supgang", "--example", "slip39_crosscheck"],
        cwd=ROOT,
        env=env,
        check=True,
    )
    binary = ROOT / "target" / "debug" / "examples" / "slip39_crosscheck"
    if not binary.is_file():
        raise FileNotFoundError(f"built helper not found at {binary}")
    return binary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wheel-dir",
        type=Path,
        help="Directory holding the pre-fetched shamir_mnemonic-0.3.0 wheel for strict offline installation.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Pass --offline to uv pip install (requires --wheel-dir or warm uv cache).",
    )
    args = parser.parse_args()

    if args.wheel_dir is not None:
        wheel_path = args.wheel_dir / WHEEL_NAME
        if not wheel_path.is_file():
            raise FileNotFoundError(f"missing expected wheel: {wheel_path}")
        actual = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
        if actual != WHEEL_SHA256:
            raise ValueError(f"wheel SHA-256 mismatch: expected {WHEEL_SHA256}, got {actual}")
        print(f"Verified local wheel {wheel_path.name} sha256={actual}")

    rust_bin = build_rust_helper()

    with tempfile.TemporaryDirectory(prefix="supgang-slip39-xcheck-") as tmp:
        tmp_path = Path(tmp)
        venv_dir = tmp_path / "venv"
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            f"shamir-mnemonic==0.3.0 \\\n"
            f"    --hash=sha256:{WHEEL_SHA256} \\\n"
            f"    --hash=sha256:{SDIST_SHA256}\n",
            encoding="utf-8",
        )
        subprocess.run(["uv", "venv", "--quiet", str(venv_dir)], check=True)
        install_cmd = [
            "uv",
            "pip",
            "install",
            "--python",
            str(venv_dir / "bin" / "python"),
            "--require-hashes",
            "--only-binary",
            ":all:",
            "--no-deps",
        ]
        if args.offline or args.wheel_dir is not None:
            install_cmd.append("--offline")
        if args.wheel_dir is not None:
            install_cmd.extend(["--no-index", "--find-links", str(args.wheel_dir)])
        install_cmd.extend(["-r", str(req_file)])
        subprocess.run(install_cmd, check=True)

        subprocess.run(
            [str(venv_dir / "bin" / "python"), "-c", WORKER_CODE, str(rust_bin)],
            check=True,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
