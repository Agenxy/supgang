#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Run Cargo in a compiler- and profile-scoped shared output directory.

The repository's Rust pin remains authoritative.  This wrapper changes only
the environment of the command it launches; it never changes a global tool
selector or migrates another project's output.
"""

import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib


MAX_BANNER_BYTES = 4096
MAX_TOOL_BYTES = 128 * 1024 * 1024
SCCACHE_VERSION = "sccache 0.18.0"
NAMESPACE_VARIABLES = (
    "CARGO_BUILD_TARGET", "CARGO_ENCODED_RUSTFLAGS", "CARGO_PROFILE_DEV_DEBUG",
    "CARGO_PROFILE_DEV_OPT_LEVEL", "CARGO_PROFILE_RELEASE_DEBUG",
    "CARGO_PROFILE_RELEASE_OPT_LEVEL", "CC", "CFLAGS", "CXX", "CXXFLAGS",
    "MACOSX_DEPLOYMENT_TARGET", "RUSTFLAGS", "RUSTDOCFLAGS", "SDKROOT",
)


def read_output(command: list[str], environment: dict[str, str]) -> str:
    result = subprocess.run(command, env=environment, capture_output=True, timeout=10, check=True)
    if len(result.stdout) > MAX_BANNER_BYTES:
        raise ValueError("tool identity exceeds the bounded banner size")
    return result.stdout.decode("utf-8", errors="strict").strip()


def hash_tool(path: Path, digest) -> None:
    if not path.is_file() or path.stat().st_size > MAX_TOOL_BYTES:
        raise ValueError(f"tool identity file is absent or too large: {path}")
    with path.open("rb") as stream:
        consumed = 0
        while chunk := stream.read(1024 * 1024):
            consumed += len(chunk)
            if consumed > MAX_TOOL_BYTES:
                raise ValueError(f"tool identity grew beyond its bound: {path}")
            digest.update(chunk)


def pinned_environment(root: Path, environment: dict[str, str]) -> dict[str, str]:
    selected = environment.copy()
    rustup_bin = Path(selected["HOME"]) / ".cargo" / "bin"
    if (rustup_bin / "rustup").is_file():
        selected["PATH"] = f'{rustup_bin}{os.pathsep}{selected.get("PATH", "")}'
    with (root / "rust-toolchain.toml").open("rb") as stream:
        pin = tomllib.load(stream)["toolchain"]["channel"]
    banner = read_output(["rustc", "-vV"], selected)
    if f"release: {pin}" not in banner.splitlines():
        raise ValueError(f"selected rustc does not match the repository pin {pin}")
    cargo = read_output(["cargo", "-Vv"], selected)
    if f"release: {pin}" not in cargo.splitlines():
        raise ValueError(f"selected cargo does not match the repository pin {pin}")
    return selected


def namespace(profile: str, environment: dict[str, str]) -> Path:
    banner = read_output(["rustc", "-vV"], environment)
    host = next((line.removeprefix("host: ") for line in banner.splitlines() if line.startswith("host: ")), None)
    release = next((line.removeprefix("release: ") for line in banner.splitlines() if line.startswith("release: ")), None)
    if host is None or release is None or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", host):
        raise ValueError("rustc did not report a usable host identity")
    compiler = read_output(["rustup", "which", "rustc"], environment)
    compiler_path = Path(compiler)
    identity = hashlib.sha256()
    hash_tool(compiler_path, identity)
    identity.update(banner.encode())
    sysroot = Path(read_output(["rustc", "--print", "sysroot"], environment))
    if not sysroot.is_absolute() or not sysroot.is_dir():
        raise ValueError("rustc did not report a usable sysroot")
    identity.update(str(sysroot.resolve()).encode())
    for name in ("components", "multirust-config.toml", "multirust-channel-manifest.toml"):
        identity.update(name.encode())
        hash_tool(sysroot / "lib" / "rustlib" / name, identity)
    flags = hashlib.sha256()
    for name in NAMESPACE_VARIABLES:
        flags.update(name.encode())
        flags.update(b"\0")
        flags.update(environment.get(name, "").encode())
        flags.update(b"\0")
    extra_names = {"CARGO_INCREMENTAL", "RUSTC", "RUSTDOC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"}
    extra_prefixes = ("CARGO_PROFILE_", "CARGO_TARGET_", "CARGO_BUILD_", "CC_", "CFLAGS_", "CXX_", "CXXFLAGS_", "AR_")
    for name in sorted(environment):
        if name in NAMESPACE_VARIABLES or not (name in extra_names or name.startswith(extra_prefixes)):
            continue
        flags.update(name.encode())
        flags.update(b"\0")
        flags.update(environment[name].encode())
        flags.update(b"\0")
    base = Path(environment.get("AGENXY_CARGO_TARGET_ROOT", str(Path(environment["HOME"]) / ".cache" / "agenxy" / "cargo-targets" / "supgang")))
    if not base.is_absolute():
        raise ValueError("AGENXY_CARGO_TARGET_ROOT must be absolute")
    return base / f"rustc-{release}-{host}-{identity.hexdigest()[:16]}" / profile / f"flags-{flags.hexdigest()[:16]}"


def installed_sccache(environment: dict[str, str]) -> str | None:
    candidates = []
    if explicit := environment.get("SUPGANG_SCCACHE"):
        candidates.append(explicit)
    if found := shutil.which("sccache", path=environment.get("PATH")):
        candidates.append(found)
    mise = Path(environment["HOME"]) / ".local" / "share" / "mise" / "installs" / "sccache" / "0.18.0"
    if mise.is_dir():
        candidates.extend(str(path) for path in sorted(mise.glob("sccache-*/sccache"))[:4])
    for candidate in candidates[:8]:
        try:
            if read_output([candidate, "--version"], environment) == SCCACHE_VERSION:
                return candidate
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
            continue
    if environment.get("SUPGANG_SCCACHE"):
        raise ValueError("SUPGANG_SCCACHE is not the selected sccache 0.18.0 executable")
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("dev", "release"), required=True)
    parser.add_argument("--print-target-dir", action="store_true", help="show the selected lane without running Cargo")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command and not args.print_target_dir:
        parser.error("a Cargo command is required after --")
    root = Path(__file__).resolve().parents[1]
    try:
        environment = pinned_environment(root, dict(os.environ))
        if not environment.get("CARGO_TARGET_DIR"):
            environment["CARGO_TARGET_DIR"] = str(namespace(args.profile, environment))
        if args.print_target_dir:
            print(environment["CARGO_TARGET_DIR"])
            return 0
        environment.setdefault("CARGO_INCREMENTAL", "0")
        if not environment.get("RUSTC_WRAPPER"):
            wrapper = installed_sccache(environment)
            if wrapper:
                environment["RUSTC_WRAPPER"] = wrapper
        print(f'cargo-cache profile={args.profile} target={environment["CARGO_TARGET_DIR"]} '
              f'sccache={"enabled" if environment.get("RUSTC_WRAPPER") else "unavailable"}',
              file=sys.stderr, flush=True)
        lane = Path(environment["CARGO_TARGET_DIR"])
        lane.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (lane / ".agenxy-lane.lock").open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            try:
                return subprocess.run(command, env=environment, cwd=root, check=False).returncode
            finally:
                os.utime(lock.name, None)
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError, KeyError) as error:
        print(f"cargo-cache: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
