# Physical WAN acceptance failure

Date: 2026-08-17

Verdict: **FAIL**

## Purpose

Test the primary Supgang use case: one enrolled computer leaves the home network and reconnects to
another enrolled computer that remains there, without a hosted service or third-party relay.

## Topology

- Laptop A ran Supgang from an outside IPv4 network.
- Home B remained on the home network.
- Both computers already held each other's signed contact and remembered address history.
- Addresses are intentionally redacted from this repository record.

## Observations

1. Laptop A detected its interface change and advanced its local signed endpoint sequence.
2. Laptop A had no IPv6 default route on the outside network.
3. Laptop A retained Home B's previously signed private and public candidates.
4. The service continued sending UDP: its transmitted byte count increased by about 16.8 KiB during
   observation while its received byte count did not increase.
5. The remembered private home-network address was unreachable from the outside network.
6. No remembered public candidate completed an authenticated session.
7. `active_peers` remained zero and Laptop A received no newer Home B endpoint record.
8. The CLI described the saved Home B record as `fresh`, which represented signature expiry rather
   than a live connection and was misleading for this test.

## Root cause

Version 0.1.0 could enumerate interfaces, retain signed candidates, retry known addresses, and learn
a caller's public source address after a successful connection. It did not create or maintain an
inbound path through a home NAT. No automatic router mapping, coordinated hole punching, or owned
relay existed in that release. Remembering a router's public address was therefore insufficient.

## Corrective release gate

A later build must not be described as wide-area tested until all of the following pass with the
installed command on both physical computers:

1. Home B requests and maintains a usable home-gateway mapping, or the test records the exact
   sovereign path used instead.
2. Laptop A, from a separate outside network, completes pinned TLS and mutual device authentication
   with Home B.
3. Both CLIs report the live session as `connected`, separately from saved-address validity.
4. Laptop A's new signed address record reaches Home B, and Home B gossips it to any other
   reachable authorized member.
5. A network change removes the prior mapped and observed candidates from the current signed record
   and replaces them without losing bounded recovery history.
6. Service restart, lease renewal, orderly shutdown, and host-firewall behavior are exercised.
7. No hosted resolver, STUN service, vendor relay, account, or telemetry endpoint participates.

The corrective source tree includes automatic PCP, NAT-PMP, and UPnP mapping plus honest connection
status, but this physical gate remains pending until Home B is reachable for installation and the
two-network rerun succeeds.

## Corrective build probe

The corrective release build was run on Laptop A's outside network with an isolated state directory
and UDP port, then installed over the user's normal command and restarted cleanly. Both runs reached
the same result after the bounded gateway check:

- router mapping: not available on this network;
- Internet reachability: local network only;
- Home B: not connected;
- service remained responsive through human and JSON `status`, `peers`, and `doctor` requests.

The installed binary matched the tested release-build digest. This validates failure reporting and
the unavailable-mapping path only. It does not satisfy the physical WAN gate because the home-side
Home B build and gateway could not be reached from the outside network. An SSH attempt to the
remembered private Home B address timed out, as expected across the network boundary.
