#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Adversarial, non-privileged tests for the one-time macOS setup boundary. Apache-2.0."""

import importlib.util
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("setup_macos", Path(__file__).with_name("setup_macos.py"))
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.owner = pwd.struct_passwd(("member", "*", 501, 20, "", "/Users/member", "/bin/zsh"))
        state = "/Users/member/Library/Application Support/org.agenxy.supgang"
        self.args = [state + "/bin/supgang", "--json", "--state-dir", state, "supervise"]

    def test_no_owner_argument_can_turn_the_network_service_into_root(self):
        root = pwd.struct_passwd(("root", "*", 0, 0, "", "/var/root", "/bin/sh"))
        with self.assertRaises(RuntimeError):
            setup.build_definition({"ProgramArguments": self.args}, root)
        result = setup.build_definition({"ProgramArguments": self.args, "UserName": "root",
                                         "Program": "/tmp/other", "MachServices": {"other": True}}, self.owner)
        self.assertEqual(result["UserName"], "member")
        self.assertNotIn("Program", result)
        self.assertNotIn("MachServices", result)
        self.assertNotIn("EnvironmentVariables", result)
        self.assertNotIn("GroupName", result)
        self.assertEqual(result["Umask"], 0o077)

    def test_command_and_state_substitution_fail_closed(self):
        for position in (0, 2, 3, 4):
            changed = self.args.copy()
            changed[position] = "/tmp/other"
            with self.assertRaises(RuntimeError):
                setup.build_definition({"ProgramArguments": changed}, self.owner)
        for suffix in (["--anchor", "--anchor"], ["--router-mapping", "--endpoints", "/tmp/other"],
                       ["--endpoints", "relative"], ["--other"]):
            with self.assertRaises(RuntimeError):
                setup.build_definition({"ProgramArguments": self.args + suffix}, self.owner)

    def test_network_policy_is_preserved(self):
        for suffix in ([], ["--anchor"], ["--router-mapping"], ["--anchor", "--router-mapping"],
                       ["--anchor", "--endpoints", "/Users/member/endpoints.json"]):
            result = setup.build_definition({"ProgramArguments": self.args + suffix}, self.owner)
            self.assertEqual(result["ProgramArguments"], self.args + suffix)
            self.assertTrue(result["RunAtLoad"])
            self.assertTrue(result["KeepAlive"])

    def test_sticky_root_library_is_safe_but_shared_writable_ancestors_are_not(self):
        import stat
        def metadata(mode, uid=0):
            return os.stat_result((stat.S_IFDIR | mode, 0, 0, 0, uid, 80, 0, 0, 0, 0))
        self.assertTrue(setup.safe_ancestor(Path("/Library"), metadata(0o1775), 501))
        self.assertFalse(setup.safe_ancestor(Path("/Library"), metadata(0o775), 501))
        self.assertFalse(setup.safe_ancestor(Path("/Library"), metadata(0o1777), 501))
        self.assertFalse(setup.safe_ancestor(Path("/Library/LaunchDaemons"), metadata(0o1775), 501))

    def test_bounded_reads_reject_symlinks_fifos_and_writable_files(self):
        # Use an owner-controlled home parent; shared temporary ancestors must also be rejected.
        with tempfile.TemporaryDirectory(prefix=".supgang-setup-test-", dir=Path.home()) as directory:
            root = Path(directory)
            file = root / "file"
            file.write_bytes(b"safe")
            file.chmod(0o600)
            self.assertEqual(setup.safe_read(file, os.getuid(), 4), b"safe")
            link = root / "link"
            link.symlink_to(file)
            with self.assertRaises((OSError, RuntimeError)):
                setup.safe_read(link, os.getuid(), 4)
            fifo = root / "fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(RuntimeError):
                setup.safe_read(fifo, os.getuid(), 4)
            with self.assertRaises(RuntimeError):
                setup.safe_read(file, os.getuid(), 3)
            file.chmod(0o666)
            with self.assertRaises(RuntimeError):
                setup.safe_read(file, os.getuid(), 4)

    def test_stop_disables_every_loaded_domain_without_reading_a_definition(self):
        with patch.object(setup, "manager_loaded", return_value=True), \
             patch.object(setup, "checked") as commands, patch.object(setup, "safe_read") as reads, \
             patch.object(setup, "bootout") as stopped:
            setup.stop_or_remove(self.owner, False)
        reads.assert_not_called()
        calls = [call.args[0] for call in commands.call_args_list]
        for target in ("system/org.agenxy.supgang.501", "gui/501/org.agenxy.supgang",
                       "user/501/org.agenxy.supgang"):
            self.assertIn([setup.LAUNCHCTL, "disable", target], calls)
            stopped.assert_any_call(target)

    def test_bootout_waits_for_the_job_to_disappear_before_returning(self):
        with patch.object(setup, "checked") as command, \
             patch.object(setup, "manager_loaded", side_effect=[True, True, False]) as loaded, \
             patch.object(setup.time, "sleep"):
            setup.bootout("system/org.agenxy.supgang.501")
        self.assertEqual(loaded.call_count, 3)
        command.assert_called_once_with([setup.LAUNCHCTL, "bootout", "system/org.agenxy.supgang.501"])

    def test_a_manager_query_failure_is_not_evidence_of_job_removal(self):
        for code, expected in ((0, True), (113, False)):
            with patch.object(setup.subprocess, "run", return_value=subprocess.CompletedProcess([], code)):
                self.assertEqual(setup.manager_loaded("system/org.agenxy.supgang.501"), expected)
        with patch.object(setup.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaisesRegex(RuntimeError, "absence.*not established"):
                setup.manager_loaded("system/org.agenxy.supgang.501")

    def test_bootout_fails_when_launchd_never_releases_the_job(self):
        with patch.object(setup, "checked"), patch.object(setup, "manager_loaded", return_value=True), \
             patch.object(setup.time, "monotonic", side_effect=[0, 31]):
            with self.assertRaisesRegex(RuntimeError, "did not remove"):
                setup.bootout("system/org.agenxy.supgang.501")

    def test_definition_rename_uses_the_destination_directory_and_preserves_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "service.plist"
            path.write_bytes(b"old")
            with path.open("rb") as old, patch.object(setup, "DAEMONS", Path(directory)), \
                 patch.object(setup, "validate_ancestor"), patch.object(setup, "safe_read"), \
                 patch.object(setup, "descriptor_acl"):
                setup.write_definition(path, b"new")
                self.assertNotEqual(os.fstat(old.fileno()).st_ino, path.stat().st_ino)
                self.assertEqual(old.read(), b"old")
                self.assertEqual(path.read_bytes(), b"new")
                self.assertEqual(path.stat().st_mode & 0o777, 0o644)
                self.assertEqual(list(Path(directory).iterdir()), [path])
                with patch.object(setup.os, "replace", side_effect=OSError("injected failure")):
                    with self.assertRaises(OSError):
                        setup.write_definition(path, b"failed")
                self.assertEqual(path.read_bytes(), b"new")
                self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_migration_waits_until_the_outgoing_runtime_stops_answering(self):
        from subprocess import CompletedProcess
        replies = [CompletedProcess([], 0, '{"service":"running"}'),
                   CompletedProcess([], 0, '{"service":"stopped"}')]
        with patch.object(setup, "owner_command", side_effect=replies) as query, \
             patch.object(setup.time, "sleep"):
            setup.wait_for_stopped(self.owner)
        self.assertEqual(query.call_count, 2)

    def test_signatures_are_verified_before_any_owner_command(self):
        events = []
        with patch.object(setup, "safe_read", return_value=b"binary"), \
             patch.object(setup, "approve_runtime", side_effect=lambda *a, **k: events.append("verify")), \
             patch.object(setup, "owner_command", side_effect=lambda *a: events.append("execute")):
            setup.validate_installed(self.owner, "a" * 40, "b" * 64)
        self.assertEqual(events, ["verify", "execute"])
        for entry in (lambda: setup.validate_installed(self.owner),
                      lambda: setup.apply(self.owner, {}, None, None)):
            with patch.object(setup, "safe_read", return_value=b"binary"), \
                 patch.object(setup, "approve_runtime", side_effect=RuntimeError("bad signature")), \
                 patch.object(setup, "owner_command") as execute:
                with self.assertRaises(RuntimeError):
                    entry()
                execute.assert_not_called()

    @unittest.skipUnless(sys.platform == "darwin", "macOS descriptor ACL regression")
    def test_acl_writable_supervisor_or_parent_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory(prefix=".supgang-acl-test-", dir=Path.home()) as directory:
            home = Path(directory)
            owner = pwd.struct_passwd(("fixture", "*", os.getuid(), os.getgid(), "", str(home), "/bin/zsh"))
            supervisor = home / "Library/Application Support" / setup.LABEL / "bin/supgang"
            supervisor.parent.mkdir(parents=True, mode=0o700)
            supervisor.write_bytes(b"not executable")
            supervisor.chmod(0o700)
            for target, acl in ((supervisor, "everyone allow write"),
                                (supervisor.parent, "everyone allow add_file,delete_child")):
                subprocess.run(["/bin/chmod", "+a", acl, str(target)], check=True)
                try:
                    with patch.object(setup, "owner_command") as execute, \
                         patch.object(setup, "approve_runtime") as approve:
                        with self.assertRaises(RuntimeError):
                            setup.validate_installed(owner)
                        execute.assert_not_called()
                        approve.assert_not_called()
                finally:
                    subprocess.run(["/bin/chmod", "-N", str(target)], check=True)
            subprocess.run(["/bin/chmod", "+a", "everyone deny delete", str(supervisor)], check=True)
            try:
                self.assertEqual(setup.safe_read(supervisor, os.getuid(), 32), b"not executable")
                with patch.object(setup, "owner_command") as execute, patch.object(setup, "approve_runtime"):
                    setup.validate_installed(owner)
                    execute.assert_called_once()
            finally:
                subprocess.run(["/bin/chmod", "-N", str(supervisor)], check=True)

    @unittest.skipUnless(sys.platform == "darwin", "macOS descriptor ACL regression")
    def test_fresh_artifact_acl_is_cleared_before_use(self):
        with tempfile.TemporaryDirectory(prefix=".supgang-new-acl-test-", dir=Path.home()) as directory:
            artifact = Path(directory) / "file"
            with artifact.open("xb+") as stream:
                artifact.chmod(0o600)
                subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(artifact)], check=True)
                with self.assertRaises(RuntimeError):
                    setup.descriptor_acl(stream.fileno())
                setup.descriptor_acl(stream.fileno(), clear_new=True)
                setup.descriptor_acl(stream.fileno())

    @unittest.skipUnless(sys.platform == "darwin", "macOS lock ancestor ACL regression")
    def test_setup_lock_rejects_replaceable_parent_and_retains_exclusion(self):
        with tempfile.TemporaryDirectory(prefix=".supgang-lock-test-", dir=Path.home()) as directory:
            parent = Path(directory)
            lock = parent / "setup.lock"
            subprocess.run(["/bin/chmod", "+a", "everyone allow delete_child", str(parent)], check=True)
            try:
                with self.assertRaises(RuntimeError):
                    setup.open_setup_lock(lock, os.getuid())
                self.assertFalse(lock.exists())
            finally:
                subprocess.run(["/bin/chmod", "-N", str(parent)], check=True)
            first = setup.open_setup_lock(lock, os.getuid())
            try:
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    setup.open_setup_lock(lock, os.getuid())
            finally:
                os.close(first)
            os.close(setup.open_setup_lock(lock, os.getuid()))


if __name__ == "__main__":
    unittest.main()
