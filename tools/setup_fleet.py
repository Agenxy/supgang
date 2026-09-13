#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Run the reviewed owner setup on this Mac and one explicitly selected SSH peer. Apache-2.0."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import shlex
import subprocess
import sys


class SetupFailure(RuntimeError):
    """A stage-specific error safe to display without private tool output."""


def ssh_command(peer: str, interactive: bool = False) -> list[str]:
    return ["/usr/bin/ssh", "-t" if interactive else "-T", "-o", "BatchMode=yes",
            "-o", "NumberOfPasswordPrompts=0", "-o", "ConnectionAttempts=1",
            "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=yes", peer]


def check_connection(peer: str) -> None:
    """One read-only login attempt. Never submit a password or retry."""
    try:
        result = subprocess.run([*ssh_command(peer), "/usr/bin/true"], capture_output=True,
                                text=True, timeout=15, check=False)
    except subprocess.TimeoutExpired:
        raise SetupFailure("The home peer did not complete its connection check within 15 seconds. "
                           "No setup started on either computer. Check that it is awake and reachable.") from None
    except OSError:
        raise SetupFailure("This laptop could not start its SSH client. No setup started on either computer.") from None
    if result.returncode == 0:
        return
    detail = result.stderr.lower()
    if "host key verification failed" in detail or "host identification has changed" in detail:
        reason = "The home peer's saved SSH identity could not be verified. Do not bypass this identity check."
    elif "connection closed" in detail or "connection reset" in detail:
        reason = ("The home peer closed the SSH connection before allowing commands to run. "
                  "No administrator password was requested or submitted. An account restriction or SSH service "
                  "problem may cause this; this message alone cannot distinguish them. "
                  "Check the selected account directly on the home computer before retrying.")
    elif "permission denied" in detail:
        reason = ("The home peer did not accept password-free SSH access for the selected account. "
                  "Restore access for that account; this script will not try another account or password.")
    elif "timed out" in detail or "no route" in detail or "connection refused" in detail:
        reason = "The home peer's SSH service is unreachable. Check its network connection and Remote Login setting."
    else:
        reason = f"The home peer's SSH connection check failed (exit {result.returncode}). Check Remote Login on that Mac."
    raise SetupFailure(f"{reason}\nNo setup started on either computer. You can use --only local for this laptop.")


def run_step(command: list[str], label: str, remainder: str, apply: bool) -> None:
    # Inherit the terminal: passwords are read only by sudo, never by Python or a pipe.
    try:
        result = subprocess.run(command, check=False, timeout=900 if apply else 90)
    except subprocess.TimeoutExpired:
        raise SetupFailure(f"{label} exceeded its time limit. {remainder} "
                           "Some changes may have occurred; check service status before retrying.") from None
    except OSError:
        raise SetupFailure(f"{label} could not start its required local tool. {remainder}") from None
    if result.returncode:
        raise SetupFailure(f"{label} did not finish (exit {result.returncode}). {remainder} "
                           "Review the error immediately above. No automatic retry was attempted; "
                           "this step may have made changes before failing.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", required=True, help="Explicit owner account and host for the second Mac.")
    parser.add_argument("--certificate", required=True, help="Reviewed owner signing certificate fingerprint.")
    parser.add_argument("--certificate-sha256", required=True, help="Reviewed certificate SHA-256 fingerprint.")
    parser.add_argument("--apply", action="store_true", help="Perform setup; otherwise show both plans only.")
    parser.add_argument("--only", choices=("both", "local", "peer"), default="both",
                        help="Choose which computer to set up; default: both, home peer first.")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+@[a-zA-Z0-9.-]+", args.peer) or args.peer.startswith("-"):
        raise RuntimeError("Use an explicit SSH account and host.")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", args.certificate):
        raise RuntimeError("Use an exact signing certificate fingerprint.")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.certificate_sha256):
        raise RuntimeError("Use an exact SHA-256 certificate fingerprint.")
    owner = args.peer.split("@", 1)[0]
    if owner == "root":
        raise RuntimeError("The peer must use an ordinary owner account.")
    script = Path(__file__).with_name("setup_macos.py").resolve()
    options = ["--trust-certificate", args.certificate, "--certificate-sha256", args.certificate_sha256]
    options += ["--apply"] if args.apply else []
    if args.apply and not sys.stdin.isatty():
        raise RuntimeError("Run this command in your Terminal so macOS can ask for owner approval.")
    # The remote runtime and script have already been copied and hash-checked by deployment.
    remote_directory = f"/Users/{owner}/.local/share/supgang-owner-setup"
    remote = [f"{remote_directory}/uv", "run", "--offline", "--no-python-downloads", "--python",
              "/usr/bin/python3", "--script", f"{remote_directory}/setup_macos.py", *options]
    if args.only != "local":
        print("Checking the home peer's SSH access first (no password, no setup changes).", flush=True)
        check_connection(args.peer)
        print(f"Home peer setup: any administrator password prompt is for account {owner} on the HOME PEER, "
              "not this laptop.", flush=True)
        remainder = "The laptop's setup has not started." if args.only == "both" else "Local setup was not selected."
        run_step([*ssh_command(args.peer, args.apply), shlex.join(remote)], "Home peer setup", remainder, args.apply)
        print("Home peer setup completed." if args.apply else "Home peer preview passed.", flush=True)
    if args.only != "peer":
        print("Laptop setup: any administrator password prompt now belongs to THIS LAPTOP.", flush=True)
        remainder = ("The home peer's completed step is unchanged." if args.only == "both"
                     else "The home peer was not contacted.")
        run_step([sys.executable, str(script), *options], "Laptop setup", remainder, args.apply)
        print("Laptop setup completed." if args.apply else "Laptop preview passed.", flush=True)
    if args.apply:
        print("Selected setup steps completed. Reboot, signed updates through the firewall, and "
              "outside-home connectivity still need separate tests.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Setup interrupted. A started step may have made changes; check service status before retrying.",
              file=sys.stderr)
        raise SystemExit(130) from None
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, RuntimeError) else "A required local tool could not run. Setup is incomplete."
        print(message, file=sys.stderr)
        raise SystemExit(1) from None
