#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""List idle shared Cargo lanes older than 30 days; --apply reclaims them.

Only lanes created by tools/cargo_cache.py have the required lock marker. The
lock is held exclusively during deletion, so a cooperating build cannot use a
lane while it is reclaimed. This command never touches a repository target/.
"""

import argparse
import fcntl
import os
from pathlib import Path
import re
import sys
import time


MAX_LANES = 2
MAX_ENTRIES = 200_000
MAX_BYTES = 200 * 1024**3
MAX_DISCOVERY = 512
LANE_NAME = re.compile(r"flags-[0-9a-f]{16}\Z")
TOOLCHAIN_NAME = re.compile(r"rustc-[A-Za-z0-9_.-]{1,160}-[0-9a-f]{16}\Z")


def candidates(root: Path) -> list[Path]:
    if not root.is_dir() or root.is_symlink():
        return []
    found: list[Path] = []
    examined = 0
    for toolchain in root.iterdir():
        examined += 1
        if examined > MAX_DISCOVERY:
            raise ValueError("cache discovery exceeds its directory bound")
        if not TOOLCHAIN_NAME.fullmatch(toolchain.name) or toolchain.is_symlink() or not toolchain.is_dir():
            continue
        for profile in toolchain.iterdir():
            examined += 1
            if examined > MAX_DISCOVERY:
                raise ValueError("cache discovery exceeds its directory bound")
            if profile.name not in ("dev", "release") or profile.is_symlink() or not profile.is_dir():
                continue
            for lane in profile.iterdir():
                examined += 1
                if examined > MAX_DISCOVERY:
                    raise ValueError("cache discovery exceeds its directory bound")
                if LANE_NAME.fullmatch(lane.name) and not lane.is_symlink() and lane.is_dir():
                    found.append(lane)
    return sorted(found)


def inventory(lane: Path) -> tuple[list[Path], list[Path], int]:
    files: list[Path] = []
    directories: list[Path] = []
    bytes_used = 0
    pending = [lane]
    while pending:
        directory = pending.pop()
        directories.append(directory)
        with os.scandir(directory) as entries:
            for entry in entries:
                if len(files) + len(directories) + len(pending) >= MAX_ENTRIES:
                    raise ValueError("cache lane exceeds its entry bound")
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    bytes_used += entry.stat(follow_symlinks=False).st_size
                    if bytes_used > MAX_BYTES:
                        raise ValueError("cache lane exceeds its byte bound")
                    files.append(path)
                else:
                    raise ValueError(f"cache lane contains a symlink or special file: {path}")
    return files, directories, bytes_used


def sweep(root: Path, *, apply: bool, older_than_days: int, now: float) -> tuple[int, int]:
    if older_than_days < 7 or older_than_days > 365:
        raise ValueError("older-than-days must be between 7 and 365")
    if not root.is_absolute():
        raise ValueError("cache root must be absolute")
    active = os.environ.get("CARGO_TARGET_DIR")
    active_path = Path(active).resolve() if active else None
    selected = 0
    total_bytes = 0
    for lane in candidates(root):
        if active_path == lane.resolve():
            continue
        marker = lane / ".agenxy-lane.lock"
        if marker.is_symlink() or not marker.is_file():
            continue
        if now - marker.stat().st_mtime < older_than_days * 86400:
            continue
        if selected >= MAX_LANES:
            break
        with marker.open("rb") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                continue
            if now - os.fstat(lock.fileno()).st_mtime < older_than_days * 86400:
                continue
            files, directories, bytes_used = inventory(lane)
            if total_bytes + bytes_used > MAX_BYTES:
                raise ValueError("cache sweep exceeds its total byte bound")
            total_bytes += bytes_used
            selected += 1
            print(f'cache-sweep action={"delete" if apply else "dry-run"} lane={lane} '
                  f'files={len(files)} bytes={bytes_used}')
            if apply:
                for file in files:
                    file.unlink()
                for directory in reversed(directories):
                    directory.rmdir()
    print(f"cache-sweep lanes={selected} bytes={total_bytes} applied={str(apply).lower()}")
    return selected, total_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="delete selected idle lanes")
    parser.add_argument("--older-than-days", type=int, default=30)
    parser.add_argument("--root", type=Path,
                        default=Path.home() / ".cache" / "agenxy" / "cargo-targets" / "supgang")
    args = parser.parse_args()
    try:
        sweep(args.root, apply=args.apply, older_than_days=args.older_than_days, now=time.time())
        return 0
    except (OSError, ValueError) as error:
        print(f"cache-sweep: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
