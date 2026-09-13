#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Review and apply Supgang boot startup and exact-runtime firewall approval.

Apache-2.0. Run without --apply to inspect the plan. This is local automation,
not part of the network service; no password or private key is read or stored.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time

LABEL = "org.agenxy.supgang"
LAUNCHCTL = "/bin/launchctl"
FIREWALL = "/usr/libexec/ApplicationFirewall/socketfilterfw"
DAEMONS = Path("/Library/LaunchDaemons")
MAX_DEFINITION = 32768


def safe_ancestor(path: Path, meta: os.stat_result, uid: int) -> bool:
    sticky_library = path == Path("/Library") and meta.st_uid == 0 and meta.st_mode & 0o1000
    return (stat.S_ISDIR(meta.st_mode) and meta.st_uid in (0, uid) and not meta.st_mode & 0o002
            and (not meta.st_mode & 0o020 or bool(sticky_library)))


def root_support() -> Path:
    parent = Path("/Library/Application Support")
    for directory in (Path("/Library"), parent):
        if not safe_ancestor(directory, directory.lstat(), 0):
            raise RuntimeError("The system support directory is unsafe.")
    directory = parent / "org.agenxy.supgang-owner-setup"
    directory.mkdir(mode=0o700, exist_ok=True)
    if not safe_ancestor(directory, directory.lstat(), 0):
        raise RuntimeError("The setup recovery directory is unsafe.")
    return directory


def checked(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=45, check=False, **kwargs)
    if result.returncode:
        # Tool output may include private paths or system state; keep errors bounded.
        raise RuntimeError(f"{Path(argv[0]).name} did not complete (exit {result.returncode}).")
    return result


def safe_read(path: Path, uid: int, maximum: int) -> bytes:
    for ancestor in reversed(path.parents):
        meta = ancestor.lstat()
        if not safe_ancestor(ancestor, meta, uid):
            raise RuntimeError("A setup path has an unsafe parent directory.")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        meta = os.fstat(source.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != uid or meta.st_mode & 0o022:
            raise RuntimeError("A setup file has unsafe ownership or permissions.")
        data = source.read(maximum + 1)
        if not data or len(data) > maximum:
            raise RuntimeError("A setup file is empty or exceeds its size limit.")
    return data


def validate_installed(owner: pwd.struct_passwd) -> None:
    state = Path(owner.pw_dir) / "Library/Application Support" / LABEL
    supervisor = state / "bin/supgang"
    safe_read(supervisor, owner.pw_uid, 128 * 1024 * 1024)
    owner_command(owner, ["doctor", "--json"])


def build_definition(agent: object, owner: pwd.struct_passwd) -> dict[str, object]:
    if owner.pw_uid == 0:
        raise RuntimeError("Supgang must run as an ordinary owner account.")
    if not isinstance(agent, dict):
        raise RuntimeError("The existing service definition is invalid.")
    state = Path(owner.pw_dir) / "Library/Application Support" / LABEL
    executable = state / "bin/supgang"
    args = agent.get("ProgramArguments")
    prefix = [str(executable), "--json", "--state-dir", str(state), "supervise"]
    if not isinstance(args, list) or args[:5] != prefix:
        raise RuntimeError("The existing service does not use the expected owner state and supervisor.")
    remaining = args[5:]
    if remaining[:1] == ["--anchor"]:
        remaining = remaining[1:]
    if remaining[:1] == ["--router-mapping"]:
        remaining = remaining[1:]
        if remaining:
            raise RuntimeError("Gateway mapping cannot be combined with fixed endpoints.")
    if remaining and not (len(remaining) == 2 and remaining[0] == "--endpoints"
                          and isinstance(remaining[1], str) and Path(remaining[1]).is_absolute()):
        raise RuntimeError("The existing service has unsupported arguments.")
    return {
        "Label": f"{LABEL}.{owner.pw_uid}",
        "ProgramArguments": args,
        "UserName": owner.pw_name,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "ThrottleInterval": 5,
        "Umask": 63,
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
    }


def owner_command(owner: pwd.struct_passwd, args: list[str]) -> subprocess.CompletedProcess[str]:
    environment = {"HOME": owner.pw_dir, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
    identity = {"user": owner.pw_uid, "group": owner.pw_gid, "extra_groups": []} if os.getuid() == 0 else {}
    command = str(Path(owner.pw_dir) / "Library/Application Support" / LABEL / "bin/supgang")
    return checked([command, *args], env=environment, **identity)


def manager_loaded(target: str) -> bool:
    return subprocess.run([LAUNCHCTL, "print", target], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=10, check=False).returncode == 0


def wait_for_stopped(owner: pwd.struct_passwd) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            status = json.loads(owner_command(owner, ["status", "--json"]).stdout)
            if status.get("service") == "stopped":
                return
        except (RuntimeError, json.JSONDecodeError):
            pass
        time.sleep(0.5)
    raise RuntimeError("The outgoing service did not stop; refusing to start a duplicate.")


def write_definition(path: Path, data: bytes) -> None:
    # All destination ancestors are root-owned; replacement cannot follow a user symlink.
    for directory in (Path("/Library"), DAEMONS):
        meta = directory.lstat()
        if not safe_ancestor(directory, meta, 0):
            raise RuntimeError("The system service directory is unsafe.")
    if path.exists() or path.is_symlink():
        safe_read(path, 0, MAX_DEFINITION)
    fd, temporary = tempfile.mkstemp(prefix=f".{LABEL}-", dir=root_support())
    try:
        with os.fdopen(fd, "wb") as destination:
            os.fchmod(destination.fileno(), 0o644)
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(DAEMONS, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def approve_runtime(owner: pwd.struct_passwd, fingerprint: str | None, certificate_sha256: str | None,
                    apply_changes: bool = True) -> None:
    state = Path(owner.pw_dir) / "Library/Application Support" / LABEL
    supervisor = state / "bin/supgang"
    active = json.loads(safe_read(state / "updates/active.json", owner.pw_uid, MAX_DEFINITION))
    digest = active.get("digest", "")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError("The active release digest is invalid.")
    runtime = state / "updates/slots" / digest / "supgang"
    if active.get("executable") != str(runtime):
        raise RuntimeError("The active release path does not match its digest.")
    image = safe_read(runtime, owner.pw_uid, 128 * 1024 * 1024)
    if hashlib.sha256(image).hexdigest() != digest:
        raise RuntimeError("The active runtime does not match its protected digest.")
    del image
    for executable in (supervisor, runtime):
        checked(["/usr/bin/codesign", "--verify", "--strict", str(executable)])
        if fingerprint:
            requirement = f'=identifier "org.agenxy.supgang.runtime" and certificate root = H"{fingerprint}"'
            checked(["/usr/bin/codesign", "--verify", "--strict", "-R", requirement, str(executable)])
    if fingerprint:
        with tempfile.TemporaryDirectory(prefix="supgang-certificate-") as directory:
            prefix = str(Path(directory) / "certificate")
            checked(["/usr/bin/codesign", "-d", f"--extract-certificates={prefix}", str(runtime)])
            certificate = Path(prefix + "0")
            if sorted(Path(directory).iterdir()) != [certificate]:
                raise RuntimeError("Owner trust accepts only a single self-issued certificate, not a commercial chain.")
            # SHA-1 here identifies the preapproved certificate, as in macOS designated requirements.
            # Update authenticity and executable integrity use signatures and SHA-256.
            if hashlib.sha1(certificate.read_bytes(), usedforsecurity=False).hexdigest() != fingerprint.lower():
                raise RuntimeError("The extracted owner certificate did not match the approved identity.")
            if certificate_sha256 and hashlib.sha256(certificate.read_bytes()).hexdigest() != certificate_sha256.lower():
                raise RuntimeError("The owner certificate did not match its approved SHA-256 fingerprint.")
            checked(["/usr/bin/security", "verify-cert", "-c", str(certificate), "-r", str(certificate),
                     "-p", "codeSign", "-L", "-q"])
            if apply_changes:
                checked(["/usr/bin/security", "add-trusted-cert", "-d", "-r", "trustRoot", "-p", "codeSign",
                         "-k", "/Library/Keychains/System.keychain", str(certificate)])
    if not apply_changes:
        print("Verified the installed release, code signature, and selected certificate without changing permissions.")
        return
    for executable in (supervisor, runtime):
        checked([FIREWALL, "--add", str(executable)])
        checked([FIREWALL, "--unblockapp", str(executable)])
    print("Approved the verified supervisor and active runtime in the firewall.", flush=True)


def apply(owner: pwd.struct_passwd, definition: dict[str, object], fingerprint: str | None,
          certificate_sha256: str | None) -> None:
    destination = DAEMONS / f"{LABEL}.{owner.pw_uid}.plist"
    system_target = f"system/{LABEL}.{owner.pw_uid}"
    # Validate owner state and current runtime before any manager changes.
    validate_installed(owner)
    approve_runtime(owner, fingerprint, certificate_sha256)
    agent = Path(owner.pw_dir) / "Library/LaunchAgents" / f"{LABEL}.plist"
    recovery = Path(owner.pw_dir) / "Library/Application Support" / LABEL / "owner-setup"
    if not recovery.exists():
        recovery.mkdir(mode=0o700)
        os.chown(recovery, owner.pw_uid, owner.pw_gid)
    if not safe_ancestor(recovery, recovery.lstat(), owner.pw_uid):
        raise RuntimeError("The owner recovery directory is unsafe.")
    backup = recovery / "login-service.plist"
    previous_system = safe_read(destination, 0, MAX_DEFINITION) if destination.exists() else None
    previous_target = next((target for domain in ("gui", "user")
                            if manager_loaded(target := f"{domain}/{owner.pw_uid}/{LABEL}")), None)
    moved_agent = agent.exists()
    if moved_agent:
        if backup.exists():
            raise RuntimeError("A previous login-service backup exists; inspect it before repeating migration.")
        os.rename(agent, backup)
    try:
        for domain in ("gui", "user"):
            target = f"{domain}/{owner.pw_uid}/{LABEL}"
            if manager_loaded(target):
                checked([LAUNCHCTL, "bootout", target])
        if manager_loaded(system_target):
            checked([LAUNCHCTL, "bootout", system_target])
        # Stop and readiness commands execute as the approved owner, never as root.
        wait_for_stopped(owner)
        write_definition(destination, plistlib.dumps(definition, sort_keys=False))
        checked([LAUNCHCTL, "enable", system_target])
        checked([LAUNCHCTL, "bootstrap", "system", str(destination)])
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            try:
                status = json.loads(owner_command(owner, ["service", "status", "--json"]).stdout)
                if status.get("running") and status.get("startup") == "system-boot":
                    print("Supgang is running as its owner under the system boot manager.", flush=True)
                    owner_command(owner, ["service", "restart", "--json"])
                    print("Verified an unattended restart through the owner-only control socket.", flush=True)
                    return
            except (RuntimeError, json.JSONDecodeError):
                pass
            time.sleep(1)
        raise RuntimeError("The boot service did not become ready. The previous definition is preserved.")
    except Exception:
        try:
            if manager_loaded(system_target):
                checked([LAUNCHCTL, "bootout", system_target])
            if previous_system is not None:
                write_definition(destination, previous_system)
                checked([LAUNCHCTL, "bootstrap", "system", str(destination)])
            elif destination.exists():
                # This exact definition was created in this invocation; retain it for inspection.
                os.replace(destination, root_support() / f"failed-{owner.pw_uid}-{time.time_ns()}.plist")
            if moved_agent:
                os.rename(backup, agent)
                if previous_target:
                    checked([LAUNCHCTL, "bootstrap", previous_target.rsplit("/", 1)[0], str(agent)])
            print("Restored previous startup. Explicit certificate and firewall approvals remain; peer identity is preserved.",
                  file=sys.stderr)
        except (RuntimeError, OSError, subprocess.TimeoutExpired):
            print("Setup and startup rollback both need attention. Saved definitions and identity are preserved.",
                  file=sys.stderr)
        raise


def stop_or_remove(owner: pwd.struct_passwd, remove: bool) -> None:
    # Fixed labels only. Stopping must not depend on parsing a damaged definition.
    for target in (f"system/{LABEL}.{owner.pw_uid}", f"gui/{owner.pw_uid}/{LABEL}",
                   f"user/{owner.pw_uid}/{LABEL}"):
        if manager_loaded(target.rsplit("/", 1)[0]):
            checked([LAUNCHCTL, "disable", target])
            if manager_loaded(target):
                checked([LAUNCHCTL, "bootout", target])
    if remove:
        paths = ((DAEMONS / f"{LABEL}.{owner.pw_uid}.plist", 0),
                 (Path(owner.pw_dir) / "Library/LaunchAgents" / f"{LABEL}.plist", owner.pw_uid))
        for destination, uid in paths:
            if destination.exists() or destination.is_symlink():
                safe_read(destination, uid, MAX_DEFINITION)
                saved = root_support() / f"removed-{owner.pw_uid}-{time.time_ns()}.plist"
                os.rename(destination, saved)
    if remove:
        print("Supgang boot and login startup are removed. Identity and peer history are preserved; "
              "removed definitions are saved for recovery.")
    else:
        print("Supgang is stopped and boot startup is disabled. Use --uninstall to remove login startup "
              "even for an account that is not signed in. Identity and peer history are preserved.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--apply", action="store_true", help="Approve firewall access and migrate to boot startup.")
    actions.add_argument("--stop", action="store_true", help="Stop the boot service and keep it disabled across reboot.")
    actions.add_argument("--uninstall", action="store_true", help="Disable boot startup and save its definition for recovery.")
    parser.add_argument("--trust-certificate", help="Exact 40-character owner code-signing certificate fingerprint.")
    parser.add_argument("--certificate-sha256", help="Exact SHA-256 fingerprint of the approved self-issued certificate.")
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise RuntimeError("This setup tool is for macOS; Linux uses its native service manager.")
    if args.trust_certificate and not re.fullmatch(r"[0-9a-fA-F]{40}", args.trust_certificate):
        raise RuntimeError("Use an exact 40-character certificate fingerprint.")
    if args.trust_certificate and (not args.certificate_sha256
                                  or not re.fullmatch(r"[0-9a-fA-F]{64}", args.certificate_sha256)):
        raise RuntimeError("Owner certificate trust also requires its exact SHA-256 fingerprint.")
    uid = int(os.environ["SUDO_UID"]) if os.getuid() == 0 else os.getuid()
    owner = pwd.getpwuid(uid)
    agent = Path(owner.pw_dir) / "Library/LaunchAgents" / f"{LABEL}.plist"
    system = DAEMONS / f"{LABEL}.{uid}.plist"
    if args.stop or args.uninstall:
        print("Plan: disable Supgang boot and login startup while preserving peer identity and address history.", flush=True)
    else:
        source = safe_read(agent, uid, MAX_DEFINITION) if agent.exists() else safe_read(system, 0, MAX_DEFINITION)
        definition = build_definition(plistlib.loads(source), owner)
        print("Plan: start Supgang at boot as the existing owner, preserve its network settings and identity, "
              "approve only its verified runtime in the firewall, and verify an unattended restart.", flush=True)
        print("No router changes, password collection, private-key exports, or privileged network service are involved.",
              flush=True)
    if not (args.apply or args.stop or args.uninstall):
        validate_installed(owner)
        approve_runtime(owner, args.trust_certificate, args.certificate_sha256, apply_changes=False)
        print("Review the script, then add --apply to perform this setup.")
        return
    if os.getuid() != 0:
        # The password prompt belongs to sudo in the user's terminal; this process never reads it.
        # macOS owns this interpreter. Do not elevate a package-manager interpreter
        # that another local account could replace. Isolated mode ignores Python environment hooks.
        print("macOS now needs administrator approval on THIS computer. The prompt identifies its account and host. "
              "If macOS reports an account lock, stop rather than retrying passwords.", flush=True)
        result = subprocess.run(["/usr/bin/sudo", "-p", "Supgang approval on %h (account %p) password: ",
                                 "--", "/usr/bin/python3", "-I", str(Path(__file__).resolve()),
                                 *sys.argv[1:]], check=False)
        if result.returncode:
            print("Administrator approval or the approved setup command did not finish on this computer. "
                  "Read macOS's message above; no automatic retry was made.", file=sys.stderr)
        raise SystemExit(result.returncode)
    lock_path = f"/var/run/{LABEL}.setup.{uid}.lock"
    lock = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock, "rb+") as held_lock:
        metadata = os.fstat(held_lock.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise RuntimeError("The owner setup lock is unsafe.")
        try:
            fcntl.flock(held_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another Supgang owner setup is already running.") from None
        if args.stop or args.uninstall:
            stop_or_remove(owner, args.uninstall)
        else:
            apply(owner, definition, args.trust_certificate, args.certificate_sha256)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print(f"Supgang setup stopped: {error} Your peer identity is preserved.", file=sys.stderr)
        raise SystemExit(1) from None
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        print("Supgang setup stopped because a file, account, or system tool could not be validated. "
              "Your peer identity is preserved.", file=sys.stderr)
        raise SystemExit(1) from None
