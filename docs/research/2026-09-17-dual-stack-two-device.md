# Two-device IPv4 and IPv6 recovery

Date: 2026-09-17

Status: implementation, controlled experiments, and successful native IPv4 recovery on an existing fleet.
Exactly two devices remain the baseline. A relay, public reflector, VPN, or discovery service does
not count as a solution to that baseline, even if it is already installed on the test computers.

## What the outside-network investigation established

The laptop's physical interface has IPv4 but no usable native IPv6 route. The stationary device's
current signed public candidates are IPv6. Its private IPv4 candidate is off-link. A fresh service
restart followed by 90 one-second status samples produced no connection. The process remained healthy.

The initial 90-second observation was too short. Inspection of verified history found a mapped
public IPv4 endpoint behind six IPv6-only dial records. The old scheduler selected a historical
record only every fourth retry, then filtered for route compatibility. It spent most windows on
unusable IPv6 records. After roughly six minutes, the service reached the older IPv4 address and
completed fresh authentication. OS routing used the physical Wi-Fi interface, not an overlay.
Runtime diagnostics showed the actual IPv4 remote socket and increasing traffic in both directions.

The final installed correction recovered after three restarts in 12.35, 15.34, and 13.24 seconds,
then passed 120 consecutive connected samples with traffic in both directions. It races address
families across record boundaries even when the OS permits both families but only one works.
See the [physical validation](../validation/2026-09-17-external-ipv4-recovery.md) for the exact
installed artifact, test conditions, and remaining acceptance gates.

This is a scheduling defect with a usable remembered endpoint, not evidence that missing IPv4
discovery caused this particular failure. It also does not establish how the earlier mapping was
created or whether it depends on existing router configuration. No router changes were made in
this investigation. Fresh zero-configuration discovery remains a separate acceptance condition.
An IPv4 address alone does not identify a NAT's external UDP port or demonstrate inbound access.

## Applicable methods and their prerequisites

| Method | What it supplies | Two-device boundary |
| --- | --- | --- |
| Interleaved IPv4/IPv6 attempts | Avoids delaying a usable family behind a batch of broken paths | Needs candidates; does not discover missing addresses |
| PCP or NAT-PMP on the attached gateway | Temporary mapping and a gateway-reported external tuple | Needs gateway support and owner consent; a lease is not proof of outside reachability |
| Gateway public-address query | Possible IPv4 locator without changing router settings | Does not discover an arbitrary translated UDP port or open a path |
| Authenticated observation by the other device | Actual source address and port seen on that connection | Requires a first connection; IPv6 observation does not reveal IPv4 NAT state |
| Simultaneous outbound attempts | Opens some stateful filters and NAT mappings | Needs usable destination tuples, appropriate NAT behavior, and overlapping attempts |
| QUIC migration or multipath | Preserves or adds paths while sufficient connection state exists | Cannot manufacture an unknown destination or translate between address families |
| TCP fallback | Adds an option on networks that block UDP but permit the chosen TCP path | Still needs a reachable endpoint; port 443 alone does not traverse NAT |
| NAT64 / 464XLAT | Uses a translator supplied by the network | Not a client-only way for arbitrary IPv4-only networks to reach IPv6-only peers |

The family-fairness recommendation follows [RFC 8421](https://datatracker.ietf.org/doc/html/rfc8421).
The candidate and observation distinctions follow [ICE](https://www.rfc-editor.org/info/rfc8445/).
The NAT prerequisites are described in [RFC 5128](https://www.rfc-editor.org/rfc/rfc5128.html).
Gateway protocols are specified in [PCP](https://www.rfc-editor.org/info/rfc6887/) and
[NAT-PMP](https://www.rfc-editor.org/rfc/rfc6886.html).
[NAT64](https://www.rfc-editor.org/rfc/rfc6146.html) is network translation infrastructure, not
an address-family capability that installing Supgang can provide by itself.

## Current state of the art

The August 2026 [QUIC Address Discovery draft](https://datatracker.ietf.org/doc/html/draft-ietf-quic-address-discovery-01)
moves address observation into encrypted QUIC frames. It is work in progress. Supgang already
exchanges device-signed observations within authenticated sessions, but does not implement that
transport extension. Neither approach discovers the other device before any packet can reach it.

The [multipath QUIC draft](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21)
adds simultaneous paths and explicitly leaves address discovery and management out of scope.
It is worth evaluating for path preservation, not as a missing-IPv4 discovery mechanism.

[Iroh's traversal design](https://docs.iroh.computer/concepts/nat-traversal) uses a relay for initial
contact and address exchange before attempting direct connectivity. Its success rates cannot be
transferred to a relay-free Supgang fleet. Replacing Quinn without replacing those prerequisites
would not solve the observed failure. Retain the pinned Rust/Quinn stack for these bounded changes;
no production dependency or wire protocol change is needed for them.

## Implemented and tested in this pass

- Candidate batches retain the first preference, place the other family second when available,
  and rotate the remaining addresses. The existing four-attempt bound is unchanged. A regression
  test failed before this change because IPv4 was absent from an IPv6-heavy first batch.
- Route-ineligible addresses are removed before selection. The batch spans eligible current and
  historical records, retaining the original signed contact and TLS pin for each individual attempt.
  The preferred current address participates every round; historical addresses rotate without
  starving either family. An eligible interface is a possibility check, not proof a route works.
- Owner-facing peer JSON includes optional `connection` diagnostics: the actual authenticated
  remote socket and sent/received datagram counters. This is runtime information, never copied
  into signed candidates or durable reachability state. Older replies without the field still read.
  A connection address alone does not identify the physical route; inspect the OS route as well.
- A live connection's actual address stays visible after a short-lived address report expires,
  without turning runtime information into durable signed reachability. IPv4-mapped IPv6 spellings
  are canonicalized for display, family selection, deduplication, and loopback rejection; original
  signed bytes remain unchanged.
- An in-memory, bounded UDP translation fixture carries real QUIC ciphertext and production mutual
  device authentication between exactly two endpoints. The fixture translates private host ports
  to different external ports and models address-and-port-dependent filtering.
- Tests authenticate two translated IPv4 peers sending toward known tuples, and a translated
  client initiating toward a known public peer. They check peer identity and the observed translated
  socket. A dual-stack dialer reaches IPv4 while the earlier IPv6 candidates are blackholed,
  including candidates bound to different historical transport keys.
- Negative tests run both receivers and dialers: stale mapping ports and blocked UDP cannot produce
  a successful session within the observation window.
- A valid but different fleet member claiming the expected server's public TLS key cannot substitute
  for the expected device identity. The candidate-specific race still requires the device proof.
  The five translation and identity cases passed ten successive runs: 50 successful test executions.

These are controlled tests, not measurements of real NAT success rates. They do not model arbitrary
destination-dependent mapping, CGNAT, every packet-loss pattern, or physical Linux gateways.
[Patchbay](https://github.com/n0-computer/patchbay) is a separate Linux network-namespace option for
those integration cases; it is not needed as a production dependency.

`tools/probe_gateway.py` sends one PCP ANNOUNCE and one NAT-PMP public-address request to the
OS-selected RFC 1918 gateway. It changes no leases or settings, contacts no public reflector, and
redacts addresses. On the outside network, neither protocol replied within its two-second budget.
This means no answer was obtained, not proof that the protocols are permanently unsupported.
Its response-classification tests run offline with `uv run --script tools/test_probe_gateway.py`.

## Remaining work and acceptance

1. Validate first-contact IPv4 discovery on a fresh two-device installation, without an already
   remembered mapped endpoint, through an allowed local-gateway mechanism, direct interface, or
   already reachable peer. Keep address-only hints distinct from mapped endpoints. Do not guess
   that an observed TCP port or the internal UDP port is the external UDP port.
2. While a native connection exists, evaluate alternate-family path establishment and keep useful
   authenticated observations as bounded recovery hints. Durable observation history needs its own
   replay, expiry, revocation, and migration design; it is not implemented by the scheduling change.
   Later September hardening adds a separate, bounded locally signed successful-route journal;
   this does not turn a transient report into current device authority or retroactively validate
   the earlier installed artifact.
3. Repeat physical two-device tests on IPv4-only, IPv6-capable, and dual-stack networks. Verify the
   actual OS route, fresh authentication, record exchange, restart recovery, and sustained activity.
   Exclude accidental overlay paths from native-WAN acceptance.
4. Install matching artifacts on both physical acceptance peers before a fleet milestone is complete.
   Linux acceptance and the independently requested security review remain separate gates.

If neither device has a usable common-family locator, the gateways provide no way to obtain one,
and no communication path survives, the strict two-device system has no source for that missing
information. More retries, a different language, and a newer transport do not remove that condition.
Report it plainly while continuing bounded recovery; do not hide an external service behind a
claim that the two-device baseline has been solved.
