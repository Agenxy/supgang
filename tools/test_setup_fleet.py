#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Offline regression tests for fleet setup failures. Apache-2.0."""

import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("fleet", Path(__file__).with_name("setup_fleet.py"))
fleet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fleet)


class FleetTests(unittest.TestCase):
    def arguments(self, *extra):
        return ["setup_fleet.py", "--peer", "member@example.invalid", "--certificate", "a" * 40,
                "--certificate-sha256", "b" * 64, *extra]

    def test_connection_failure_is_explained_without_claiming_a_lockout(self):
        result = subprocess.CompletedProcess([], 255, "", "Connection closed by private-host port 22")
        with patch.object(fleet.subprocess, "run", return_value=result) as run:
            with self.assertRaises(fleet.SetupFailure) as failure:
                fleet.check_connection("member@example.invalid")
        message = str(failure.exception)
        self.assertIn("before allowing commands", message)
        self.assertIn("No setup started on either computer", message)
        self.assertNotIn("private-host", message)
        run.assert_called_once()
        command = run.call_args.args[0]
        for option in ("BatchMode=yes", "NumberOfPasswordPrompts=0", "ConnectionAttempts=1",
                       "StrictHostKeyChecking=yes"):
            self.assertIn(option, command)
        self.assertEqual(command[-1], "/usr/bin/true")

    def test_known_failure_categories(self):
        for stderr, expected in (("Host key verification failed", "saved SSH identity"),
                                 ("Permission denied (publickey)", "password-free SSH"),
                                 ("Connection refused", "unreachable")):
            result = subprocess.CompletedProcess([], 255, "", stderr)
            with patch.object(fleet.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(fleet.SetupFailure, expected):
                    fleet.check_connection("member@example.invalid")

    def test_preflight_failure_prevents_all_setup_steps(self):
        with patch.object(sys, "argv", self.arguments()), \
             patch.object(fleet, "check_connection", side_effect=fleet.SetupFailure("closed")), \
             patch.object(fleet, "run_step") as setup, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(fleet.SetupFailure):
                fleet.main()
        setup.assert_not_called()

    def test_timeout_does_not_retry(self):
        with patch.object(fleet.subprocess, "run", side_effect=subprocess.TimeoutExpired("ssh", 15)) as run:
            with self.assertRaisesRegex(fleet.SetupFailure, "15 seconds"):
                fleet.check_connection("member@example.invalid")
        run.assert_called_once()

    def test_local_only_never_contacts_the_peer(self):
        with patch.object(sys, "argv", self.arguments("--only", "local")), \
             patch.object(fleet, "check_connection") as check, \
             patch.object(fleet, "run_step") as steps, contextlib.redirect_stdout(io.StringIO()):
            fleet.main()
        check.assert_not_called()
        steps.assert_called_once()
        self.assertEqual(steps.call_args.args[1], "Laptop setup")

    def test_peer_success_then_local_failure_preserves_partial_progress(self):
        with patch.object(sys, "argv", self.arguments()), patch.object(fleet, "check_connection"), \
             patch.object(fleet, "run_step", side_effect=[None, fleet.SetupFailure("failed")]) as steps, \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(fleet.SetupFailure):
                fleet.main()
        self.assertEqual(steps.call_count, 2)
        self.assertIn("home peer's completed step is unchanged", steps.call_args.args[2])

    def test_partial_step_failure_does_not_claim_no_changes(self):
        with patch.object(fleet.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as run:
            with self.assertRaises(fleet.SetupFailure) as failure:
                fleet.run_step(["example"], "Home peer setup", "Laptop setup has not started.", True)
        self.assertIn("may have made changes", str(failure.exception))
        self.assertIn("Laptop setup has not started", str(failure.exception))
        self.assertNotIn("capture_output", run.call_args.kwargs)
        self.assertNotIn("input", run.call_args.kwargs)

    def test_invalid_sha256_fails_before_connecting(self):
        args = self.arguments()
        args[-1] = "bad"
        with patch.object(sys, "argv", args), patch.object(fleet, "check_connection") as check:
            with self.assertRaisesRegex(RuntimeError, "SHA-256"):
                fleet.main()
        check.assert_not_called()

    def test_apply_requires_a_terminal_before_connecting(self):
        with patch.object(sys, "argv", self.arguments("--apply")), \
             patch.object(sys.stdin, "isatty", return_value=False), \
             patch.object(fleet, "check_connection") as check:
            with self.assertRaisesRegex(RuntimeError, "Terminal"):
                fleet.main()
        check.assert_not_called()

    def test_peer_only_does_not_start_local_setup(self):
        with patch.object(sys, "argv", self.arguments("--only", "peer")), \
             patch.object(fleet, "check_connection"), patch.object(fleet, "run_step") as steps, \
             contextlib.redirect_stdout(io.StringIO()):
            fleet.main()
        steps.assert_called_once()
        self.assertEqual(steps.call_args.args[1], "Home peer setup")
        self.assertNotIn("--apply", steps.call_args.args[0][-1])

    def test_step_timeout_reports_uncertain_changes_without_retry(self):
        with patch.object(fleet.subprocess, "run", side_effect=subprocess.TimeoutExpired("ssh", 900)) as run:
            with self.assertRaisesRegex(fleet.SetupFailure, "Some changes may have occurred"):
                fleet.run_step(["example"], "Home peer setup", "Laptop setup has not started.", True)
        run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
