#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Offline checks for the read-only, address-redacting gateway probe. Apache-2.0."""

import unittest

from probe_gateway import classify_response


class ProbeTests(unittest.TestCase):
    def test_success_never_exports_reported_address(self) -> None:
        packet = bytes([0, 128, 0, 0, 0, 0, 0, 1, 8, 8, 8, 8])
        self.assertEqual(classify_response("nat-pmp", packet),
                         {"status": "answered", "result_code": 0, "reported_global_ipv4": True})

    def test_shared_or_private_mapping_is_not_public(self) -> None:
        for address in (bytes([10, 0, 0, 1]), bytes([100, 64, 0, 1])):
            self.assertFalse(classify_response("nat-pmp", bytes([0, 128, 0, 0]) + bytes(4) + address)
                             ["reported_global_ipv4"])

    def test_truncation_and_wrong_protocol_fail_closed(self) -> None:
        for protocol in ("pcp", "nat-pmp"):
            for packet in (b"", bytes(2), bytes(24), bytes(128)):
                self.assertEqual(classify_response(protocol, packet), {"status": "invalid-response"})

    def test_pcp_announce_preserves_error_code_without_claiming_mapping(self) -> None:
        self.assertEqual(classify_response("pcp", bytes([2, 128, 0, 2]) + bytes(20)),
                         {"status": "answered", "result_code": 2})


if __name__ == "__main__":
    unittest.main()
