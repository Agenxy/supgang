# Service tunnel: one-session WAN acceptance runbook

Status: prepared, not executed. Request 52763 milestone 3 requires owner gateway setup and tether.
The [starvation record](2026-10-12-background-class-starvation.md) identifies the installed artifact.
On 12 October the mapped IPv4 was published from the gateway's own status value and confirmed in
the laptop's fresh signed record; the gateway forward itself is still not configured.

## Before changing the laptop's network

Keep the home computer on its normal network and confirm the current LAN connection.
The owner configures only UDP 44330 on the home gateway: an IPv6 rule to the home computer's
selected stable global address, and an IPv4 UDP forward to its reserved LAN IPv4 for IPv4 fallback.
Do not expose TCP 22 or disable the gateway firewall. The exact IPv6 fields still need owner capture;
PCP/NAT-PMP support has not been verified. Supply is coordinating those owner steps.

For IPv4 forwarding, the owner places the current public IPv4 UDP socket, ending in `:44330`,
in the prepared empty 0600 file on Solis:

```text
~/Library/Application Support/org.agenxy.supgang/wan-acceptance/mapped-endpoint.txt
```

The file is empty until the owner supplies the actual gateway value. No endpoint has been published
by preparing it. Enter the address through an editor or private file transfer, not command arguments.
Then, on Solis:

```sh
supgang endpoint add-mapped --from-file "$HOME/Library/Application Support/org.agenxy.supgang/wan-acceptance/mapped-endpoint.txt"
```

That command validates the protected file and global IPv4 socket, signs a new contact and gossips it
over the current authenticated LAN connection. The receiver must confirm that this specific mapped
IPv4 candidate arrived in the fresh device-signed record before roaming. Use a private capture of
the resolved record for this comparison; do not put its address in ordinary logs or receipts.
An already present public IPv6 candidate alone is not evidence that the new IPv4 candidate arrived.

On the laptop:

```sh
supgang doctor --peer solis
```

The peer check must report a signed public endpoint and fresh expiry. It deliberately does not
claim WAN reachability. Confirm the intended endpoint, live peer and signed-record freshness before
moving; a gateway rule by itself does not update Supgang's signed address record.

## Phone-tether session

The owner moves only the laptop to the phone tether. Verify that its active route/source network is
different from the home LAN; record that evidence without recording peer addresses. Keep the home
computer's service and network running. Allow a bounded reconnect window and inspect live peer
state, not a cached record or advertised candidate alone.

Run SSH with strict existing host-key trust and no multiplex reuse:

```sh
ssh -o 'ProxyCommand=supgang connect solis ssh' \
    -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o ControlMaster=no -o ControlPath=none -o ConnectTimeout=12 solis
```

The acceptance agent will verify the approved remote account, installed/active artifact digest,
authenticated QUIC path and increasing counters, then repeat a bounded exact byte/EOF fixture.
Capture whether the successful path uses IPv4 or IPv6. One working family does not prove the other.
No direct TCP fallback, new host-key acceptance, third-party relay or automatic router edit is allowed.

If SSH or reconnection fails, retain the proof gap and diagnose route, record freshness, gateway
rule, family support and authenticated-session status. Do not mark WAN acceptance complete from
LAN SSH, a UDP checker, the peer doctor check or a successful source gate.

## After the session

Save a redacted separate-network acceptance or failure record and report milestone 3 through Dibs.
Keep the intended `ssh` exposure unless the owner requests removal. The original SSH alias remains
usable without the ProxyCommand override. Lost edges plus changed or expired remembered addresses
still require an owner-carried fresh contact or a separately configured reachable owned anchor.
