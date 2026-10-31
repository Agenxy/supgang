#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Read-only PCP/NAT-PMP check of the OS-selected local gateway. Apache-2.0.

Sends one query per protocol. Never creates or removes a port mapping, follows
a discovery URL, contacts a public reflector, or prints any network address.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import struct
import subprocess
import sys


def selected_gateway() -> ipaddress.IPv4Address:
    """Use OS routing, never a guessed address or an untrusted discovery URL."""
    if sys.platform == "darwin":
        result = subprocess.run(["/sbin/route", "-n", "get", "default"], check=True,
                                capture_output=True, text=True, timeout=3)
        candidates = [line.split(":", 1)[1].strip() for line in result.stdout.splitlines()
                      if line.strip().startswith("gateway:")]
    elif sys.platform.startswith("linux"):
        result = subprocess.run(["ip", "-j", "-4", "route", "get", "192.0.2.1"], check=True,
                                capture_output=True, text=True, timeout=3)
        candidates = [entry["gateway"] for entry in json.loads(result.stdout) if "gateway" in entry]
    else:
        raise ValueError("unsupported platform")
    if len(candidates) != 1:
        raise ValueError("no single IPv4 gateway")
    gateway = ipaddress.IPv4Address(candidates[0])
    private_ranges = [ipaddress.IPv4Network(prefix) for prefix in
                      ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    if not any(gateway in prefix for prefix in private_ranges):
        raise ValueError("gateway is not an RFC 1918 address; no probe sent")
    return gateway


def classify_response(protocol: str, response: bytes) -> dict[str, object]:
    """An unauthenticated gateway answer is a hint, never proven reachability."""
    if protocol == "nat-pmp":
        if len(response) != 12 or response[:2] != bytes([0, 128]):
            return {"status": "invalid-response"}
        result = int.from_bytes(response[2:4], "big")
        address = ipaddress.IPv4Address(response[8:12])
        return {"status": "answered", "result_code": result,
                "reported_global_ipv4": result == 0 and address.is_global}
    if protocol == "pcp":
        if len(response) != 24 or response[:3] != bytes([2, 128, 0]):
            return {"status": "invalid-response"}
        return {"status": "answered", "result_code": response[3]}
    raise ValueError("unknown protocol")


def probe(gateway: ipaddress.IPv4Address, protocol: str) -> dict[str, object]:
    """Bound receive time and length; connected UDP pins replies to the gateway."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            channel.settimeout(2)
            channel.connect((str(gateway), 5351))
            local = ipaddress.IPv4Address(channel.getsockname()[0])
            client = b"\x00" * 10 + b"\xff\xff" + local.packed
            payload = bytes([0, 0]) if protocol == "nat-pmp" else struct.pack("!BBHI16s", 2, 0, 0, 0, client)
            channel.send(payload)
            return classify_response(protocol, channel.recv(128))
    except TimeoutError:
        return {"status": "no-response-within-two-seconds"}
    except ConnectionRefusedError:
        return {"status": "connection-refused"}
    except OSError as error:
        return {"status": "socket-error", "errno": error.errno}


def main() -> int:
    """Emit a redacted, machine-readable result without changing network settings."""
    try:
        gateway = selected_gateway()
    except (OSError, ValueError, subprocess.SubprocessError, KeyError, TypeError):
        print(json.dumps({"schema": "supgang.gateway-probe/v1", "status": "gateway-unavailable",
                          "queries_sent": 0, "router_changes": False}))
        return 1
    print(json.dumps({"schema": "supgang.gateway-probe/v1", "status": "complete",
                      "pcp": probe(gateway, "pcp"), "nat_pmp": probe(gateway, "nat-pmp"),
                      "router_changes": False, "public_services_contacted": 0}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
