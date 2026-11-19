#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Offline recovery-key tests against RFC 8032 and the sign-v1 vector. Apache-2.0."""

import contextlib
import errno
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import recovery_key

VECTOR = Path(__file__).resolve().parent.parent / "docs/vectors/sign-v1/agenxy-launcher-install.json"

# RFC 8032 section 7.1, tests 1-3: (seed, public key, message, signature).
RFC8032 = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


class RecoveryKeyTests(unittest.TestCase):
    def test_rfc8032_vectors(self) -> None:
        for seed, public, message, signature in RFC8032:
            seed_bytes, message_bytes = bytes.fromhex(seed), bytes.fromhex(message)
            self.assertEqual(recovery_key.public_key(seed_bytes).hex(), public)
            self.assertEqual(recovery_key.sign(seed_bytes, message_bytes).hex(), signature)
            self.assertTrue(recovery_key.verify(bytes.fromhex(public), message_bytes, bytes.fromhex(signature)))
            altered = bytearray(bytes.fromhex(signature))
            altered[0] ^= 1
            self.assertFalse(recovery_key.verify(bytes.fromhex(public), message_bytes, bytes(altered)))

    def test_frame_and_signature_match_the_rust_sign_v1_vector(self) -> None:
        vector = json.loads(VECTOR.read_text(encoding="utf-8"))
        framed = recovery_key.framed_message(vector["context"], bytes.fromhex(vector["message_sha256"]))
        self.assertEqual(framed.hex(), vector["framed_message"])
        public = bytes.fromhex(vector["public_key"])
        self.assertEqual(recovery_key.fingerprint(public), vector["fingerprint"])
        self.assertTrue(recovery_key.verify(public, framed, bytes.fromhex(vector["signature"])))
        self.assertFalse(
            recovery_key.verify(
                public,
                recovery_key.framed_message("other.context", bytes.fromhex(vector["message_sha256"])),
                bytes.fromhex(vector["signature"]),
            )
        )

    def test_seal_round_trip_and_tamper_refusal(self) -> None:
        seed = bytes(range(32))
        document = recovery_key.seal("launcher-recovery", seed, "correct horse battery", bytes(32))
        self.assertNotIn(seed.hex(), json.dumps(document))
        opened, public = recovery_key.unseal(document, "correct horse battery")
        self.assertEqual(opened, seed)
        self.assertEqual(public, recovery_key.public_key(seed))
        with self.assertRaises(ValueError):
            recovery_key.unseal(document, "wrong passphrase!!")
        for field, value in [
            ("sealed_seed", "00" * 32),
            ("label", "other-label"),
            ("public_key", recovery_key.public_key(bytes(32)).hex()),
        ]:
            altered = dict(document, **{field: value})
            if field == "public_key":
                altered["fingerprint"] = recovery_key.fingerprint(bytes.fromhex(value))
            with self.assertRaises(ValueError):
                recovery_key.unseal(altered, "correct horse battery")
        with self.assertRaises(ValueError):
            recovery_key.parse(dict(document, kdf=dict(document["kdf"], n=1 << 30)))

    def test_context_grammar_matches_supgang_sign(self) -> None:
        for bad in ["", "Upper", "space here", "x" * 65, "nul\0"]:
            with self.assertRaises(ValueError):
                recovery_key.framed_message(bad, bytes(32))

    def test_verifier_refuses_torsion_and_noncanonical_points(self) -> None:
        identity = b"\x01" + bytes(31)
        order_two = (recovery_key.P - 1).to_bytes(32, "little")
        noncanonical = recovery_key.P.to_bytes(32, "little")
        base = recovery_key._compress(recovery_key.G)
        forged = base + (1).to_bytes(32, "little")
        # Before the subgroup checks, the identity key accepted this for
        # every message and the order-two key accepted it for this message.
        self.assertFalse(recovery_key.verify(identity, b"any message", forged))
        self.assertFalse(recovery_key.verify(order_two, b"torsion", forged))
        challenge = recovery_key._hash_scalar(identity + base + b"torsion R")
        self.assertFalse(recovery_key.verify(base, b"torsion R", identity + challenge.to_bytes(32, "little")))
        for weak in (identity, order_two):
            self.assertFalse(recovery_key.verify(weak, b"any message", forged))
            self.assertFalse(recovery_key.verify(base, b"any message", weak + bytes(32)))
        self.assertFalse(recovery_key.verify(noncanonical, b"any message", forged))
        self.assertFalse(recovery_key.verify(base, b"any message", noncanonical + bytes(32)))

    def test_unsupported_directory_sync_warns_after_file_sync(self) -> None:
        real_fsync = os.fsync
        synced_file = False

        def sync_or_refuse_directory(fd: int) -> None:
            nonlocal synced_file
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EINVAL, "directory sync unsupported")
            real_fsync(fd)
            synced_file = True

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "recovery.json"
            output, error = io.StringIO(), io.StringIO()
            with (
                patch.object(recovery_key, "_require_terminal"),
                patch.object(recovery_key.getpass, "getpass", return_value="correct horse battery"),
                patch.object(recovery_key.os, "fsync", side_effect=sync_or_refuse_directory),
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(error),
            ):
                self.assertEqual(recovery_key._generate(SimpleNamespace(label="recovery", out=path, json=False)), 0)
            self.assertTrue(synced_file)
            self.assertIn("public key", output.getvalue())
            self.assertIn("fingerprint", output.getvalue())
            self.assertIn("warning: this volume does not support directory sync", error.getvalue())
            self.assertEqual(recovery_key.parse(recovery_key._read(path))[0], "recovery")

    def test_public_json_contains_only_public_fields(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "recovery.json"
            generated = io.StringIO()
            with (
                patch.object(recovery_key, "_require_terminal"),
                patch.object(recovery_key.getpass, "getpass", return_value="correct horse battery"),
                contextlib.redirect_stdout(generated),
            ):
                self.assertEqual(recovery_key._generate(SimpleNamespace(label="recovery", out=path, json=True)), 0)
            created = json.loads(generated.getvalue())
            self.assertEqual(
                set(created),
                {"schema", "status", "label", "public_key", "fingerprint"},
            )
            self.assertEqual(created["schema"], "supgang.recovery-public-key/v1")
            self.assertEqual(created["label"], "recovery")
            shown = io.StringIO()
            with contextlib.redirect_stdout(shown):
                self.assertEqual(recovery_key._public(SimpleNamespace(key=path, json=True)), 0)
            displayed = json.loads(shown.getvalue())
            self.assertEqual(displayed, dict(created, authenticated=False))
            plain = io.StringIO()
            with contextlib.redirect_stdout(plain):
                self.assertEqual(recovery_key._public(SimpleNamespace(key=path, json=False)), 0)
            self.assertTrue(plain.getvalue().startswith("public key   "))
            self.assertNotIn("label", plain.getvalue())
            for output in (generated.getvalue(), shown.getvalue()):
                for private_field in ("sealed_seed", "mac", "kdf"):
                    self.assertNotIn(private_field, output)


if __name__ == "__main__":
    unittest.main()
