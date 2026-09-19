# External-network IPv4 recovery validation

Date: 2026-09-17

Scope: exactly two existing physical macOS peers, with the roaming computer on an IPv4-only
outside network. No router change, relay, public reflector, hosted discovery service, or additional
peer was introduced. This validates recovery through a remembered mapped address; it does not
establish how that earlier mapping was created or validate fresh zero-configuration discovery.

## Diagnosis

The first 90-second observation ended without a connection. The current signed peer record
contained an off-link private IPv4 address and public IPv6 addresses, but no public IPv4 address.
Read-only inspection of verified history found a mapped public IPv4 socket behind six IPv6-only
dial records. The old scheduler visited a historical record only once every four retry rounds,
then filtered its addresses. Unusable records therefore consumed retry windows.

An instrumented build using that old scheduler eventually authenticated over native IPv4, roughly
six minutes after restart. Its actual connection socket, bidirectional datagram counters, and
the OS route through the physical Wi-Fi interface establish more than a cached connected flag.
The initial failure did not justify concluding that the transport lacked a working IPv4 path.

## Implemented correction

Route-ineligible addresses are filtered before scheduling. Candidate racing spans both current
and historical records, preserving each address's signed contact and expected transport key.
The latest eligible preference stays in every batch; the other family takes the second position
when available; remaining addresses rotate. The existing maximum of four attempts is unchanged.

This also addresses dual-stack networks whose IPv6 route exists but does not work: the older IPv4
option is not deferred until all IPv6 history has been visited. Historical data remains a dial
hint, never fresh reachability. Successful admission still requires fresh mutual device proof,
current authorization, and the synchronization exchange.

## Installed artifact

The final local CLI and active protected runtime slot have SHA-256:

`2f61ca0c79ead89f018b42fe715fcac077a83fb6d4bb07f9cc995c809a0de0ec`

`make install` was followed by `service refresh`. The existing owner-approved signing identity
was retained and strict signature verification passed. No Apple developer subscription or new
firewall approval was required. The normal command path, help, doctor, active-slot record, and
running executable path were checked outside the repository.

Doctor verified protected identity and authoritative state for two members, with strict mode and
zero public dependencies. At refresh it reported disabled local automatic mapping. After connection,
it reported the peer-observed address without claiming an independently tested inbound path.
It also reports owner-only file identity storage rather than hardware-backed storage.

The remote artifact was last verified as
`c1c3699cfcb28d65eb1369eb0d65dc2c24505a88d4e218987d10b1f28abda178`.
Its executable hash could not be reread during this run because authorized WAN SSH timed out.
Thus this is compatibility and recovery evidence against the existing peer, not a completed
matching-artifact fleet deployment.

## Physical restart tests

An intermediate correction recovered after three restarts in 15.32, 14.28, and 13.28 seconds,
then passed 120 consecutive one-second connected samples. Counters increased by 60 received
and 56 sent datagrams. Those results apply to the intermediate artifact, not the final hash above.

The final artifact recovered after three restarts in **12.35, 15.34, and 13.24 seconds**. Every
attempt authenticated the expected peer over native IPv4 through the physical Wi-Fi interface.
The subsequent check passed **120/120 consecutive connected samples**, with incoming datagrams
increasing by **50** and outgoing datagrams by **49**. The identity and remote socket stayed the
same throughout. The connection remained usable beyond the configured 45-second idle timeout.

The test timer begins when the restart command returns. Every recovery must complete within
45 seconds, retain the expected peer identity, expose an authenticated IPv4 connection, and use
the physical Wi-Fi route. The stability test requires 120 connected samples with the same peer
and remote socket, plus increasing incoming and outgoing datagram counters. Datagram counters
are evidence of transport activity, not lossless delivery or application receipt counts.

## Controlled and source validation

- Full quality gate passed: formatting, all-target workspace check, all-feature warnings-fatal
  Clippy, 233 core tests, three ACL tests, repository policy, and documentation generation.
- Five real-QUIC translation and identity cases passed ten consecutive runs, for 50 executions.
  They include two translated IPv4 peers sending bilaterally, outbound access to a known public
  peer, blackholed IPv6 with a working IPv4 fallback, changed or blocked UDP mappings, and a
  valid different device claiming the real server's public transport key.
- The in-memory NAT fixture supplies the external tuples and carries production QUIC and device
  authentication. It does not test public-address discovery or arbitrary NAT success rates.
- A regression fixture contains six newer IPv6-only records and one older IPv4 record. It checks
  IPv4-only, IPv6-only, dual-stack, and no-interface selection; original per-address authority;
  the preferred path in every mixed batch; and eventual attempts for all eligible addresses.
- IPv4-mapped IPv6 observations deduplicate to one address and cannot bypass loopback rejection.
  Canonical display does not alter the original signed bytes.
- A live connection remains visible after address-report expiry without falsely refreshing the
  signed record. The ordinary peer view prefers its freshly observed public IPv4 address.
- Four offline gateway-probe tests passed. The read-only live PCP and NAT-PMP queries received
  no answer within two seconds each; this does not prove permanent gateway incompatibility.

## Open acceptance conditions

- Evidence comes from authenticated application state and OS routing, not a packet-capture audit
  or a fresh inspection of the stationary network's router configuration.
- First-contact discovery without a previously usable mapped address remains unproven. No claim
  is made that a network's missing common-family locator can be recovered without an information
  source, or that all NAT and firewall combinations permit direct communication.
- Physical dual-stack impairment, physical Linux, and a matching final build on both acceptance
  peers remain separate gates. The prior external IPv6 validation used the earlier installed build.
- WAN SSH reachability is separate from Supgang reachability. Update trust is still unprovisioned
  locally (`trusted: false`), so remote update activation was not attempted or reported as passed.
- The requested independent Opus review was attempted but blocked by an expired OAuth session;
  no review report was produced. These tests do not substitute for that review.

See the [research and method comparison](../research/2026-09-17-dual-stack-two-device.md).
No public release was made during this validation.
