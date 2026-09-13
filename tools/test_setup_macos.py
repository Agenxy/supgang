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
             patch.object(setup, "checked") as commands, patch.object(setup, "safe_read") as reads:
            setup.stop_or_remove(self.owner, False)
        reads.assert_not_called()
        calls = [call.args[0] for call in commands.call_args_list]
        for target in ("system/org.agenxy.supgang.501", "gui/501/org.agenxy.supgang",
                       "user/501/org.agenxy.supgang"):
            self.assertIn([setup.LAUNCHCTL, "disable", target], calls)
            self.assertIn([setup.LAUNCHCTL, "bootout", target], calls)

    def test_migration_waits_until_the_outgoing_runtime_stops_answering(self):
        from subprocess import CompletedProcess
        replies = [CompletedProcess([], 0, '{"service":"running"}'),
                   CompletedProcess([], 0, '{"service":"stopped"}')]
        with patch.object(setup, "owner_command", side_effect=replies) as query, \
             patch.object(setup.time, "sleep"):
            setup.wait_for_stopped(self.owner)
        self.assertEqual(query.call_count, 2)


if __name__ == "__main__":
    unittest.main()
