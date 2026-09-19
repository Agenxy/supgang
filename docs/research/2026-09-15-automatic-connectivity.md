# Automatic connectivity without router configuration

Date: 2026-09-15

Status: research recommendation; no transport migration or WAN acceptance claimed.
This supplements the M1 decision in [stack-and-prior-art.md](stack-and-prior-art.md).

## Recommendation

Support exactly two devices with no helper as the baseline product and acceptance track. Prioritize
direct reachability, connection preservation, and recovery across network changes. Additional
owner-operated devices can provide introductions and encrypted relay fallback as the fleet grows;
they are optional resilience improvements, not prerequisites for supported operation.
Evaluate Iroh 1.2.0 against this two-device baseline before deciding whether to replace Quinn.
Keep Supgang's signed records, membership, revocation, and durable-state rules independent of it.

This is an architectural recommendation, not evidence that Iroh is faster, smaller, or safer than
the existing implementation. Those comparisons require a bounded prototype and measurements.

The existing implementation has gateway mapping and authenticated introductions over established
QUIC sessions. Its documentation still lists an owned control relay as future work. An introducer
cannot help disconnected devices unless they can first reach it. More retries and address history
do not supply that missing connection.

## Two-device baseline

The following is required design work, not a claim of implemented or universally working behavior.

1. Pair the two devices directly. Exchange authenticated identity and bounded current/historical
   contact information, without requiring a third service or a helper enrollment step.
2. Test both connection directions over available IPv4 and IPv6 paths. A device with a reachable
   address can receive the other's outbound connection; neither role needs a permanently fixed IP.
   Prefer an already working path and continuously exchange address changes while it exists.
3. Preserve useful transport state across short disruptions. Test QUIC migration, interface changes,
   sleep/resume, socket continuity, and bounded keepalives. A roaming client can reconnect to a
   still-reachable stationary peer and deliver its new record. A same-LAN connection alone does not
   prove that such an outside path exists.
4. Where a coordination path survives, exchange observed socket addresses and coordinate direct
   attempts. Where it does not, evaluate bounded prearranged retry windows against previously
   authorized candidates. Scheduling can align attempts but cannot discover an unknown public NAT
   mapping; do not label scheduled retries as general serverless hole punching.
5. Treat automatic gateway leases as a distinct, optional capability. They can avoid manual router
   administration when an existing gateway supports them, but they do change temporary gateway
   state. Preserve owner consent, restrict requests to the attached gateway, and never silently
   enable router features. Failure of mapping must not terminate other recovery attempts.
6. Retain useful offline results with explicit age and verification status. Continue bounded recovery
   automatically. Never show an old public address as a confirmed current or reachable address.

No public STUN service, vendor relay, hidden test server, or extra machine may participate in a
test reported as two-device acceptance. The two endpoints can report each other's observed public
addresses after an outside connection exists; that observation cannot bootstrap the first connection.
Local pairing need not reveal the router's public IPv4 address or external UDP mapping.

The [NAT traversal analysis in RFC 5128](https://www.rfc-editor.org/rfc/rfc5128.html) explains the
dependence of hole punching on address exchange and NAT behavior. Two peers can work without a
third server when a usable path or sufficient prior contact information exists. If both have only
unreachable or unknown endpoints and no surviving channel, automatic recovery remains conditional.
This is a limitation to diagnose and measure, not grounds for excluding two-device users.

First acceptance must include a physical two-device roam, with no helper and no manual router
changes, on a topology demonstrated to permit direct connectivity. Also test restrictive cases and
report their exact failure conditions. Neither a helper-assisted pass nor a LAN pass satisfies this
gate. Do not imply that a pass on one compatible network establishes universal two-device support.

## What can be automatic

| Available infrastructure | Proposed behavior | Limitation |
| --- | --- | --- |
| Two devices, usable direct addresses | Connect directly; refresh addresses after network changes | A path must survive or become discoverable |
| Two devices behind NAT, with a surviving coordination path | Coordinate simultaneous outbound connection attempts | NAT and firewall behavior can prevent success |
| One reachable owner-operated helper | Both devices connect outward; exchange encrypted records through it; attempt direct upgrade | Helper availability and outbound access are dependencies |
| Two independent reachable helpers | Maintain redundant contact paths and fail over automatically | Shared outages or loss of every locator can still disconnect the fleet |
| No reachable direct path or helper | Show remembered addresses and a clear connectivity warning | Software cannot guarantee recovery from a complete network partition |

A helper can be an existing eligible fleet member. It does not have to be a purchased server or
have a permanently fixed IP. However, at least one current helper locator must remain obtainable.
Changing every helper address while all connections are gone recreates the original problem.
Electing a helper is useful only after verifying that other devices can reach it.

No home router changes are required when both devices can make outbound connections to a reachable
helper. That does not mean there is no infrastructure requirement: the helper needs an accessible
listener. Putting it behind another equally restrictive router does not solve the problem.

## Evidence and alternatives

[Tailscale's traversal design](https://tailscale.com/blog/nat-traversal-improvements-pt-1) establishes
a relayed path while attempting direct connectivity, retaining relaying when necessary. The useful
prior art is that connection strategy; Supgang must not depend on Tailscale's service.

[Iroh's relay design](https://docs.iroh.computer/concepts/relays) combines connection coordination
with end-to-end encrypted forwarding and supports direct-path upgrades and multiple relays.
Its self-hosted relay source is available independently of its commercial service.

[libp2p](https://libp2p.io/docs/hole-punching/) offers another coherent option: AutoNAT, relay
reservations, Circuit Relay v2, and RTT-synchronized DCUtR. It still requires reachable peers for
coordination. For Supgang's narrow address plane, adopting the broader protocol suite would need
a demonstrated benefit over the smaller integration boundary proposed here.

[ICE](https://www.rfc-editor.org/rfc/rfc8445.html) with
[TURN](https://www.rfc-editor.org/rfc/rfc8656.html) is the standards-based alternative. A self-hosted
[coturn](https://github.com/coturn/coturn) deployment supplies relay infrastructure, but Supgang would
still need candidate gathering, signaling, authentication integration, and transport selection.
Retaining Quinn and adding a narrowly scoped HTTPS control channel is also viable; it trades a
smaller imported stack for more connectivity and recovery code maintained by this project.

A [2026 DCUtR measurement study](https://arxiv.org/abs/2604.12484) examined over 4.4 million attempts
and reported approximately 70% conditional hole-punching success after prerequisite discovery and
relay reservation succeeded. That is not a Supgang forecast or an end-to-end availability figure.
It reinforces the need to measure fallback success separately from direct-path success.

## Why revisit Iroh now

The [current 1.2.0 release](https://github.com/n0-computer/iroh/releases/tag/v1.2.0) uses noq 1.3.0
and adds configurable fallback nameservers. The
[tagged manifest](https://github.com/n0-computer/iroh/blob/v1.2.0/iroh/Cargo.toml) offers Apache-2.0
as a licensing option, uses Rust 2024, and declares Rust 1.91 as its minimum compiler.

This is worth comparing with the earlier rejected noq spike, but a version number is not a security
verdict. The manifest permits a prerelease Ed25519 dependency range and enables gateway mapping and
a private-Apple-API datapath by default. Audit the actual resolved lockfile and start with an explicit
minimal feature set, preserving Supgang's reviewed crypto policy and portable platform boundary.

The [July 2026 n0 QUIC NAT-traversal draft](https://datatracker.ietf.org/doc/draft-bruynooghe-n0-quic-nat-traversal/)
is an individual Internet-Draft describing an implementation, not a finalized IETF standard.
[Iroh 1.1.0's security fixes](https://www.iroh.computer/blog/iroh-1-1-0) included a malicious relay
packet CPU loop and malformed-address panic. The prototype must include regression and resource
exhaustion tests rather than assuming upstream handles every hostile-input boundary.

## Sovereign integration requirements

These are proposed Supgang acceptance requirements, not claims that default Iroh satisfies them.

1. Start from an explicit endpoint configuration. The
   [tagged presets](https://github.com/n0-computer/iroh/blob/v1.2.0/iroh/src/endpoint/presets.rs)
   show that `N0` installs vendor relay and DNS-based lookup services. Use `Empty` with an explicitly
   configured crypto provider, or a reviewed `Minimal` configuration. Set only owner-approved
   relays and lookup mechanisms. Audit builder defaults in addition to the preset.
2. Reject unapproved relay destinations at the connection boundary, including destinations learned
   from peer records. Disable public discovery, public fallback DNS, and unapproved external
   probes. Test failure paths with external destinations blocked; inspect actual traffic.
3. Provision helper trust with pairing. The
   [TLS configuration](https://github.com/n0-computer/iroh/blob/v1.2.0/iroh-relay/src/tls.rs) supports
   explicitly supplied trust roots. Use owner-controlled certificate trust with normal identity
   verification; never copy examples that disable certificate checking. Prove certificate renewal
   and helper address changes without depending on a public CA or DNS publisher.
4. Close relay access by default. The
   [self-hosted relay documentation](https://github.com/n0-computer/iroh/blob/v1.2.0/iroh-relay/README.md)
   defaults to allowing everyone and provides endpoint-ID allowlists. Bind relay admission to
   owner-authorized membership, including revocation of existing sessions. Do not distribute a
   fleet-wide administrator secret or put bearer tokens in URLs.
5. Treat relays as untrusted forwarders. Preserve end-to-end peer authentication and signed records;
   cryptographically bind any new transport identity to the existing device identity. A relay can
   observe connection metadata, delay traffic, or drop it; encryption does not prevent those actions.
6. Bound relay traffic, queues, connection counts, probe destinations, retries, and handshakes.
   Retain replay protection and disable early data for state-changing operations. A compromised
   peer must not turn other members into arbitrary-address scanners or amplification sources.

## Connection and product behavior

Proposed behavior, to be implemented and measured:

- Pair once. Carry authorized helper identities and current locators in the pairing material.
  Discover eligible existing fleet members automatically; explain when none can provide outside
  connectivity. Installing another ordinary client must not silently claim to create a helper.
- Prefer confirmed local connectivity. Race bounded IPv4 and IPv6 direct candidates alongside a
  helper path. Do not wait through every stale address before using a working fallback.
- Use an outbound TLS/WebSocket relay path on TCP 443 where permitted; attempt direct QUIC paths
  in parallel. A dual-stack helper can carry encrypted messages between IPv4-only and IPv6-only
  clients without claiming a direct path exists between their different address families.
- Wake on network changes and resume, refresh authenticated contacts, and use adaptive keepalives
  and bounded backoff. Preserve configurable address history, initially 16 entries per peer.
- Measure public UDP mappings through the actual sending socket. An observed TCP address or a
  mapping observed toward one destination does not prove a reusable public UDP endpoint.
- Keep PCP/NAT-PMP an optional owner-enabled optimization on trusted networks. Do not silently
  enable UPnP or require any mapping protocol for the relay path to work.
- Show one clear result per device: connected directly, connected through your helper, or offline
  with a last-seen time. Keep protocol names and candidate lists in diagnostics.

The documented relay transport uses HTTPS/WebSockets, while direct connectivity uses UDP.
See [Iroh's network requirements](https://docs.iroh.computer/about/faq). TCP 443 is widely useful,
but captive portals, proxy restrictions, relay blocking, or lack of Internet access still matter.
Do not describe it as universally permitted or as bypassing network policy.

Address lookup must work over the helper even when direct connectivity never succeeds. A current
public IP is useful information, but it may identify a shared NAT gateway and may not accept inbound
SSH. Display address freshness and access status separately. Never display a helper's address as
the device's address. General SSH forwarding or a VPN is a separate feature, not implied by a
successful address lookup.

An optional encrypted, expiring mailbox could later preserve updates while recipients are offline.
That would be additional Supgang storage/protocol work, not a built-in durable Iroh relay property.
Replay checks, size bounds, deletion, and freshness semantics would need a separate design.

## Implementation and acceptance sequence

1. Establish the two-device/no-helper baseline above and test transport candidates against it.
   Then add a separately labeled helper-assisted track: two clients and an owner-operated relay,
   exchanging new signed records with direct UDP disabled. Preserve existing identity and
   membership semantics before considering migration. A relay is a third participating machine
   in this track, even if the test harness runs all three processes on one host.
2. Test closed membership, revoked sessions, forged contacts, malformed frames, resource limits,
   relay substitution, DNS rebinding, and certificate failure. Prove no public-service fallback.
3. Exercise restricted NATs, destination-dependent mappings, double NAT, UDP blocking, mixed address
   families, relay failure, sleep/resume, and simultaneous address changes. Linux namespace-based
   [Patchbay](https://github.com/n0-computer/patchbay) is a candidate test harness; it does not replace
   physical macOS/Linux acceptance.
4. Measure connection and recovery latency, idle CPU, memory, wakeups, traffic, binary size, and
   relay bandwidth against the current build. Record distributions and conditions, not an invented
   universal success percentage. Test redundant helpers in separate failure domains.
5. Install reviewed artifacts on physical acceptance devices. Verify fresh signed updates in both
   directions across separate networks, including an IPv4-only network and a UDP-blocked case.
   Confirm relay fallback, subsequent direct upgrade where possible, and recovery after roaming.

Two-device recovery is the first product requirement. Owner-controlled fallback connectivity extends
coverage as the fleet grows. The library choice is secondary to proving both tracks independently,
retaining sovereignty, and explaining topology limits before the user relies on outside access.
