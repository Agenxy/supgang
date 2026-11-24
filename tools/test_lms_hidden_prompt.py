#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""The escrow prompt must appear only after terminal echo is disabled. Apache-2.0."""

import errno
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import termios
import time
import unittest


ROOT = Path(__file__).resolve().parent.parent
PROMPT = b"Escrow passphrase (hidden): "
TEST_ONLY_PASSPHRASE = b"test-only-terminal-response"


class LmsHiddenPromptTest(unittest.TestCase):
    def test_prompt_hides_input_before_a_fast_response(self):
        binary = Path(os.environ.get("SUPGANG_TEST_BIN", ROOT / "target" / "debug" / "supgang"))
        self.assertTrue(binary.is_file(), "the workspace test stage must build supgang first")
        with tempfile.TemporaryDirectory(prefix="supgang-lms-prompt-") as directory:
            path = Path(directory) / "malformed.age"
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as file:
                file.write(b"test-only-malformed-age-file")

            master, slave = pty.openpty()
            process = subprocess.Popen(
                [str(binary), "--json", "lms-escrow-verify", "test-root", "--from", str(path)],
                stdin=slave,
                stdout=slave,
                stderr=slave,
                close_fds=True,
            )
            output = bytearray()
            try:
                deadline = time.monotonic() + 15
                while PROMPT not in output and time.monotonic() < deadline:
                    readable, _, _ = select.select([master], [], [], 0.2)
                    if readable:
                        try:
                            chunk = os.read(master, 4096)
                            self.assertLessEqual(len(output) + len(chunk), 16_384, "verifier output exceeded test bound")
                            output.extend(chunk)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                    if process.poll() is not None:
                        break
                self.assertIn(PROMPT, output, "verifier did not reach the hidden input prompt")
                modes = termios.tcgetattr(slave)[3]
                self.assertFalse(modes & termios.ECHO, "prompt appeared while echo was enabled")
                self.assertFalse(modes & termios.ICANON, "prompt appeared while canonical input was enabled")
                os.write(master, TEST_ONLY_PASSPHRASE + b"\n")

                while process.poll() is None and time.monotonic() < deadline:
                    readable, _, _ = select.select([master], [], [], 0.2)
                    if readable:
                        try:
                            chunk = os.read(master, 4096)
                            self.assertLessEqual(len(output) + len(chunk), 16_384, "verifier output exceeded test bound")
                            output.extend(chunk)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                self.assertEqual(process.poll(), 3, "verifier did not refuse the malformed test file promptly")
                self.assertNotIn(TEST_ONLY_PASSPHRASE, output, "hidden input was echoed")
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                os.close(master)
                os.close(slave)

    def test_derive_public_hides_input_and_refuses_wrong_length_master(self):
        binary = Path(os.environ.get("SUPGANG_TEST_BIN", ROOT / "target" / "debug" / "supgang"))
        self.assertTrue(binary.is_file(), "the workspace test stage must build supgang first")
        prompt = b"Master secret hex (hidden): "
        short_master = b"00112233445566778899aabbccddeeff"

        master_fd, slave_fd = pty.openpty()
        process = subprocess.Popen(
            [str(binary), "--json", "lms-derive-public", "primary"],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
        )
        output = bytearray()
        try:
            deadline = time.monotonic() + 15
            while prompt not in output and time.monotonic() < deadline:
                readable, _, _ = select.select([master_fd], [], [], 0.2)
                if readable:
                    try:
                        chunk = os.read(master_fd, 4096)
                        self.assertLessEqual(len(output) + len(chunk), 16_384, "derive output exceeded test bound")
                        output.extend(chunk)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                if process.poll() is not None:
                    break
            self.assertIn(prompt, output, "derive-public did not reach the hidden input prompt")
            modes = termios.tcgetattr(slave_fd)[3]
            self.assertFalse(modes & termios.ECHO, "prompt appeared while echo was enabled")
            self.assertFalse(modes & termios.ICANON, "prompt appeared while canonical input was enabled")
            os.write(master_fd, short_master + b"\n")

            while process.poll() is None and time.monotonic() < deadline:
                readable, _, _ = select.select([master_fd], [], [], 0.2)
                if readable:
                    try:
                        chunk = os.read(master_fd, 4096)
                        self.assertLessEqual(len(output) + len(chunk), 16_384, "derive output exceeded test bound")
                        output.extend(chunk)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
            self.assertEqual(process.poll(), 3, "derive-public did not refuse a non-32-byte master")
            self.assertNotIn(short_master, output, "hidden master hex was echoed")
            self.assertIn(b"64 hexadecimal characters", output)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            os.close(master_fd)
            os.close(slave_fd)

    def test_share_verify_hides_passphrase_prompts(self):
        binary = Path(os.environ.get("SUPGANG_TEST_BIN", ROOT / "target" / "debug" / "supgang"))
        self.assertTrue(binary.is_file(), "the workspace test stage must build supgang first")
        with tempfile.TemporaryDirectory(prefix="supgang-lms-share-prompt-") as directory:
            first = Path(directory) / "a.share.age"
            second = Path(directory) / "b.share.age"
            for path in (first, second):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(b"test-only-malformed-share-age-file")

            master_fd, slave_fd = pty.openpty()
            process = subprocess.Popen(
                [
                    str(binary),
                    "--json",
                    "lms-share-verify",
                    "primary",
                    "--share",
                    str(first),
                    "--share",
                    str(second),
                ],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            output = bytearray()
            try:
                deadline = time.monotonic() + 15
                prompt1 = b"Passphrase for share 1 ("
                while prompt1 not in output and time.monotonic() < deadline:
                    readable, _, _ = select.select([master_fd], [], [], 0.2)
                    if readable:
                        try:
                            chunk = os.read(master_fd, 4096)
                            self.assertLessEqual(len(output) + len(chunk), 16_384, "share verify output exceeded bound")
                            output.extend(chunk)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                    if process.poll() is not None:
                        break
                self.assertIn(prompt1, output, "share-verify did not reach first hidden prompt")
                modes = termios.tcgetattr(slave_fd)[3]
                self.assertFalse(modes & termios.ECHO, "prompt appeared while echo was enabled")
                self.assertFalse(modes & termios.ICANON, "prompt appeared while canonical input was enabled")
                os.write(master_fd, TEST_ONLY_PASSPHRASE + b"\n")

                prompt2 = b"Passphrase for share 2 ("
                while prompt2 not in output and time.monotonic() < deadline:
                    readable, _, _ = select.select([master_fd], [], [], 0.2)
                    if readable:
                        try:
                            chunk = os.read(master_fd, 4096)
                            self.assertLessEqual(len(output) + len(chunk), 16_384, "share verify output exceeded bound")
                            output.extend(chunk)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                    if process.poll() is not None:
                        break
                self.assertIn(prompt2, output, "share-verify did not reach second hidden prompt")
                os.write(master_fd, TEST_ONLY_PASSPHRASE + b"\n")

                while process.poll() is None and time.monotonic() < deadline:
                    readable, _, _ = select.select([master_fd], [], [], 0.2)
                    if readable:
                        try:
                            chunk = os.read(master_fd, 4096)
                            self.assertLessEqual(len(output) + len(chunk), 16_384, "share verify output exceeded bound")
                            output.extend(chunk)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                self.assertEqual(process.poll(), 3, "share-verify did not refuse malformed test files")
                self.assertNotIn(TEST_ONLY_PASSPHRASE, output, "hidden passphrase was echoed")
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                os.close(master_fd)
                os.close(slave_fd)

    def test_ceremony_verify_reentry_retries_wrong_passphrase_then_accepts_or_aborts(self):
        probe = Path(
            os.environ.get(
                "SUPGANG_VERIFY_PROMPT_PROBE",
                ROOT / "target" / "debug" / "examples" / "lms_share_verify_prompt",
            )
        )
        self.assertTrue(probe.is_file(), "the workspace test stage must build lms_share_verify_prompt first")
        fixture_hex = (
            ROOT / "crates" / "supgang" / "tests" / "fixtures" / "age-reference-scrypt-v1.hex"
        ).read_text(encoding="utf-8").strip()
        fixture_bytes = bytes.fromhex(fixture_hex)
        good_pass = b"test-only-age-reference-passphrase-2026"
        wrong_pass = b"test-only-wrong-passphrase-attempt"
        prompt = b"Re-enter Medium A passphrase to verify (hidden): "

        with tempfile.TemporaryDirectory(prefix="supgang-lms-retry-prompt-") as directory:
            share_file = Path(directory) / "nc0-product-primary.share.age"
            fd = os.open(share_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(fixture_bytes)

            # Case 1: one wrong entry followed by the correct entry succeeds.
            master_fd, slave_fd = pty.openpty()
            process = subprocess.Popen(
                [str(probe), "A", str(share_file)],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            output = bytearray()
            try:
                deadline = time.monotonic() + 60
                while output.count(prompt) < 1 and time.monotonic() < deadline:
                    readable, _, _ = select.select([master_fd], [], [], 0.2)
                    if readable:
                        try:
                            output.extend(os.read(master_fd, 4096))
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                    if process.poll() is not None:
                        break
                self.assertEqual(output.count(prompt), 1, "first verify prompt did not appear")
                modes = termios.tcgetattr(slave_fd)[3]
                self.assertFalse(modes & termios.ECHO, "first prompt appeared with echo enabled")
                self.assertFalse(modes & termios.ICANON, "first prompt appeared with canonical mode enabled")
                os.write(master_fd, wrong_pass + b"\n")

                while output.count(prompt) < 2 and time.monotonic() < deadline:
                    readable, _, _ = select.select([master_fd], [], [], 0.2)
                    if readable:
                        try:
                            output.extend(os.read(master_fd, 4096))
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                    if process.poll() is not None:
                        break
                self.assertEqual(output.count(prompt), 2, "second verify prompt did not appear after wrong entry")
                self.assertIn(b"try again (2 attempt(s) left)", output)
                modes = termios.tcgetattr(slave_fd)[3]
                self.assertFalse(modes & termios.ECHO, "second prompt appeared with echo enabled")
                os.write(master_fd, good_pass + b"\n")

                while process.poll() is None and time.monotonic() < deadline:
                    readable, _, _ = select.select([master_fd], [], [], 0.2)
                    if readable:
                        try:
                            output.extend(os.read(master_fd, 4096))
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                self.assertEqual(process.poll(), 0, "correct passphrase on 2nd attempt did not succeed")
                self.assertNotIn(wrong_pass, output, "wrong passphrase was echoed")
                self.assertNotIn(good_pass, output, "good passphrase was echoed")
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                os.close(master_fd)
                os.close(slave_fd)

            # Case 2: three wrong entries aborts with exact post-write guidance.
            master_fd, slave_fd = pty.openpty()
            process = subprocess.Popen(
                [str(probe), "A", str(share_file)],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            output = bytearray()
            try:
                deadline = time.monotonic() + 60
                for attempt in range(1, 4):
                    while output.count(prompt) < attempt and time.monotonic() < deadline:
                        readable, _, _ = select.select([master_fd], [], [], 0.2)
                        if readable:
                            try:
                                output.extend(os.read(master_fd, 4096))
                            except OSError as error:
                                if error.errno != errno.EIO:
                                    raise
                        if process.poll() is not None:
                            break
                    self.assertEqual(output.count(prompt), attempt, f"prompt {attempt} did not appear")
                    os.write(master_fd, wrong_pass + b"\n")

                while process.poll() is None and time.monotonic() < deadline:
                    readable, _, _ = select.select([master_fd], [], [], 0.2)
                    if readable:
                        try:
                            output.extend(os.read(master_fd, 4096))
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                self.assertEqual(process.poll(), 3, "3rd wrong passphrase did not abort")
                self.assertIn(
                    b"files are written; verify them with lms-share-verify; do not rerun on these media",
                    output,
                )
                self.assertNotIn(wrong_pass, output, "wrong passphrase was echoed")
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                os.close(master_fd)
                os.close(slave_fd)

    def test_piped_stdout_is_refused_even_when_stdin_and_stderr_are_a_tty(self):
        binary = Path(os.environ.get("SUPGANG_TEST_BIN", ROOT / "target" / "debug" / "supgang"))
        self.assertTrue(binary.is_file(), "the workspace test stage must build supgang first")
        with tempfile.TemporaryDirectory(prefix="supgang-lms-stdout-tty-") as directory:
            a = Path(directory) / "a"
            b = Path(directory) / "b"
            c = Path(directory) / "c"
            for d in (a, b, c):
                d.mkdir()
            master_fd, slave_fd = pty.openpty()
            process = subprocess.Popen(
                [
                    str(binary),
                    "lms-share-ceremony",
                    "--medium-a",
                    str(a),
                    "--medium-b",
                    str(b),
                    "--medium-c",
                    str(c),
                    "--i-confirm-offline",
                ],
                stdin=slave_fd,
                stdout=subprocess.PIPE,
                stderr=slave_fd,
                close_fds=True,
            )
            output = bytearray()
            try:
                deadline = time.monotonic() + 15
                while process.poll() is None and time.monotonic() < deadline:
                    readable, _, _ = select.select([master_fd], [], [], 0.2)
                    if readable:
                        try:
                            output.extend(os.read(master_fd, 4096))
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                while True:
                    readable, _, _ = select.select([master_fd], [], [], 0.1)
                    if not readable:
                        break
                    try:
                        chunk = os.read(master_fd, 4096)
                        if not chunk:
                            break
                        output.extend(chunk)
                    except OSError:
                        break
                self.assertEqual(process.poll(), 3, "piped stdout was not refused")
                self.assertIn(b"interactive owner terminal", output)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()
                os.close(master_fd)
                os.close(slave_fd)


if __name__ == "__main__":
    unittest.main()
