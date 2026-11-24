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


if __name__ == "__main__":
    unittest.main()
