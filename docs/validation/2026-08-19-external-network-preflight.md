# External-network preflight and failed two-host acceptance

Date: 2026-08-19

Result: **not accepted end to end**

This record deliberately separates laptop-side correctness from the product's required physical
Laptop A-to-Home B wide-area acceptance. No public or private IP address is retained here.

## Live topology

- Laptop A moved from the home LAN to one external network with globally routed IPv6, then to a
  second external network with IPv4 only.
- Home B's last authenticated signed record contained its home-LAN address and direct public IPv6
  candidates, but no router-mapped public IPv4 candidate.
- The current external network has no physical globally routed IPv6 source. Its tunnel interfaces
  are excluded by automatic policy and were not used as a hidden third-party dependency.
- The home gateway did not provide PCP, NAT-PMP, or UPnP mapping during the home-side preflight. Its
  manual UDP forwarding configuration requires local access and the gateway's physical access code.

There is therefore no common route in the current topology: Laptop A can originate IPv4, while
Home B has only off-link LAN and public IPv6 addresses in its signed record. Connection is
information-theoretically impossible until Home B advertises a reachable mapped IPv4 address,
Laptop A returns to an IPv6-capable network and the IPv6 firewall admits it, or a user-owned third
node provides a surviving path.

## Evidence that passed

- The managed Laptop A service survived both network changes and replaced its signed interface
  record. Its sequence advanced from the home baseline through both roaming events.
- Installed Laptop A `0.2.0-alpha.7` has SHA-256
  `a53b2297d233f189de2ffae3e4143f8a20f8cfd642b86e949a590be5aa2aa0a6`.
- The full repository gate passed: formatting, all-target compilation, warnings-as-errors Clippy,
  107 tests, documentation, dependency policy, and the 700-line Rust source ceiling.
- The installed launchd service recovered after its exact service-manager-owned process was killed;
  a new process bound UDP port 44330 and answered the protected local control socket.
- A separate disposable live service proved that an owner-only `mapped` endpoint is preserved in
  the signed record, receives mapped-route priority, and reports `router-mapped-unverified` without
  claiming an authenticated connection.
- A mapped endpoint paired with a loopback-only listener was rejected before the service started.
- On the IPv4-only external network, the compact CLI says `no address can be tried from this
  network`. The detailed and JSON views retain every signed address while marking each one route
  incompatible. The dial scheduler excludes those candidates until the physical network changes.

## Evidence that did not pass

- No authenticated QUIC session formed between Laptop A and Home B outside the home LAN.
- On the first external network, which did provide public IPv6, no session formed through at least
  one secondary retry window. This is consistent with gateway IPv6 filtering but is not packet-level
  proof of the gateway's decision.
- Home B still runs the earlier compatible alpha build because Laptop A left the LAN before the
  corrective artifact could be copied and installed.
- The home gateway's manual UDP forward to Home B is not configured.
- Home B has therefore not signed or gossiped a mapped public IPv4 candidate, and the two machines
  do not yet run the identical artifact.

## Required next acceptance run

1. Regain direct access to the home LAN using only the authorized local account on Home B.
2. Install the exact Laptop A alpha artifact on Home B and verify its SHA-256 digest.
3. Create an owner-only endpoint file on Home B with its LAN address, its direct public IPv6
   address, and the gateway's current public IPv4 address classified as `mapped`.
4. Configure the home gateway to forward UDP 44330 to Home B and confirm the host firewall permits
   the installed Supgang binary.
5. Install the Home B launchd service with `supgang service install --endpoints PATH`, then verify
   restart recovery and LAN convergence before roaming again.
6. Move Laptop A to an IPv4-only external network. Acceptance requires an authenticated connection,
   Home B's mapped IPv4 to become peer-verified, bilateral signed-record convergence, and recovery
   after terminating each service once.

The manual public IPv4 candidate is a current reachability anchor, not a stable-address guarantee.
If the gateway's public address later changes and no authenticated path or other user-owned peer
survives, a two-node fleet cannot communicate the replacement address without an out-of-band path.
