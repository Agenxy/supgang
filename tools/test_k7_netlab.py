#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""The dedicated probe must stay independent and contain no live peer state."""

import json
from pathlib import Path
import unittest


class K7NetlabContractTests(unittest.TestCase):
    def setUp(self):
        self.deck = json.loads(
            (Path(__file__).resolve().parents[1] / "lab/k7/probe.spec7").read_text()
        )
        self.node = self.deck["nodes"][0]["kassette"]

    def test_single_on_demand_disposable_guest(self):
        self.assertEqual(self.deck["id"], "supgang-netlab-probe")
        self.assertEqual(len(self.deck["nodes"]), 1)
        self.assertEqual(self.deck["placement"], {"mobility": "pinned", "per_host_max_runners": 1})
        self.assertNotIn("autoscale", self.deck)
        self.assertEqual(self.node["provider"], "apple_container")
        self.assertEqual(self.node["isolation"], {"kind": "ephemeral_container"})
        self.assertFalse(self.node["detach"])
        self.assertFalse(self.node["keep_container"])
        self.assertEqual(self.node["restart_policy"], "no")

    def test_no_host_state_or_other_deck_connections(self):
        for field in ("env_inherit", "volumes", "publish", "publish_sockets"):
            self.assertEqual(self.node[field], [])
        self.assertEqual(self.node["env"], {})
        self.assertEqual(self.node["services"], {})
        self.assertFalse(self.node["ssh_agent"])
        self.assertEqual(self.deck["panels"], [])
        self.assertEqual(self.deck["connections"], [])
        self.assertNotIn("fs", self.node)
        self.assertEqual(self.node["labels"], ["supgang.lab=infrastructure-probe", "supgang.lab.peer-count=0"])

    def test_explicit_bounded_resource_request(self):
        self.assertEqual(self.node["limits"], {
            "cpu": 1, "memory_bytes": 268435456,
            "disk_bytes": 1073741824, "wall_time_seconds": 30,
        })
        self.assertTrue(self.node["read_only_rootfs"])
        self.assertTrue(self.node["no_dns"])

    def test_namespaces_are_required_not_optional(self):
        self.assertEqual(self.node["entrypoint"], "/usr/bin/unshare")
        self.assertEqual(self.node["command"], [
            "--user", "--map-root-user", "--net", "--mount", "--pid",
            "--fork", "--kill-child=KILL", "--mount-proc",
            "/usr/bin/cat", "/proc/net/dev", "/proc/self/uid_map",
        ])

    def test_image_has_a_public_verifiable_digest_not_a_private_loader_label(self):
        self.assertEqual(self.node["image"],
            "docker.io/library/debian@sha256:7215f78f35ffe58fe13f244fac9c4f21326d55187271fbb3e1a8aa5cc7e387ab")


if __name__ == "__main__":
    unittest.main()
