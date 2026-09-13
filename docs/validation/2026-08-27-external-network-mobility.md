# External-network mobility and WAN retry validation

Date: 2026-08-27  
Build: `0.2.0-alpha.10` corrective source  
Verdict: **WAN recovery not accepted**

This run moved Laptop A to an IPv4 network with a different default gateway
and no direct route to Home B's private address. Machine names, addresses,
account names, and hive identifiers are intentionally omitted from this public
record.

## What passed

- The installed background service, command, and active A/B slot were the same
  owner-signed artifact.
- Strict mode reported zero hosted discovery, account, telemetry, DNS, or
  vendor-relay dependencies.
- Laptop A's original service definition was found to contain a fixed endpoint
  file from the home-network setup. Reinstalling it in automatic mode preserved
  the hive state and replaced the stale interface advertisement with the
  current interface address.
- Home B's remembered mapped IPv4 endpoint was route-compatible and selected
  ahead of its off-link private and unavailable IPv6 candidates.
- The installed runtime emitted UDP handshake traffic on the outside network.
- The full repository gate passed after the corrective work: formatting,
  locked all-target checks, warnings-as-errors Clippy, 175 core tests, the
  repository policy test, and documentation.

## What failed

- Laptop A received no UDP bytes from Home B during the observation windows.
- No mutually authenticated QUIC session formed.
- Home B's signed endpoint sequence did not advance.
- The outside gateway did not expose a usable automatic PCP, NAT-PMP, or UPnP
  mapping for Laptop A. This does not prevent outbound dialing, but it means
  the laptop itself is not independently reachable through that gateway.
- Peer-carried update delivery could not be exercised because no authenticated
  connection existed. The installed hive also has no pinned TUF release root,
  so update authorization remains intentionally disabled.

## Corrective changes

The laptop's background service now uses automatic interface refresh and
best-effort gateway discovery instead of the home-only endpoint file. The file
was retained on disk but is no longer referenced by the service manager.

The background-service readiness wait was increased from 10 to 30 seconds.
During the first real reconfiguration, the operating-system service manager
and update supervisor took slightly longer than the old bound to expose the
owner-only control socket; the command reported a timeout even though the
healthy service appeared seconds later. The longer bound remains finite and
exceeds the payload supervisor's own bounded readiness probe.

## Remaining physical gate

The outside evidence proves correct mobile address refresh, candidate
selection, and UDP transmission. It cannot distinguish among a stale home
public address, missing or lost gateway forwarding, home host-firewall
rejection, and return-path filtering on the outside network. The next home-side
run must verify the gateway's current public address and UDP lease or forward,
observe packets arriving at Home B, and confirm the installed firewall identity.
Only then should another outside-network run be used to require a persistent
authenticated session, bilateral signed-record convergence, and peer-carried
update delivery.

This run does not satisfy Supgang's WAN acceptance gate.
