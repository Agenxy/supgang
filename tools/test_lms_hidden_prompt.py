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


if __name__ == "__main__":
    unittest.main()
