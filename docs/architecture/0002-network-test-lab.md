# Network test lab: K7 orchestration, real peers, measured networks

Status: layer 1 (in-process simulation) implemented 2026-10-12; the kernel and macOS lanes remain proposed. Reviewed 2026-09-18.

## Purpose

Develop and reproduce outside-home failures without physically moving a laptop.
The macOS development workflow must run on a Mac and exercise native macOS
Supgang binaries, not infer macOS correctness from Linux tests. Linux remains a
first-class test target. No lab component becomes a Supgang runtime dependency.

The smallest product topology has exactly two Supgang processes. Virtual routers,
test controllers, and guest-management channels are test equipment, not additional
Supgang members, introducers, address brokers, or relays.

## Layers

| Layer | Runs | Proves | Status |
| --- | --- | --- | --- |
| 1. In-process simulation | `cargo test`, every platform, in the gate | The production service's decisions against modeled gateways | Implemented |
| 2. Linux kernel lab | Namespaces, nftables, netem in a Linux guest | The same against real kernel NAT, conntrack and impairment | Planned below |
| 3. macOS guests | K7 packet attachment | Native macOS stack behaviour | Planned below |
| 4. Physical acceptance | Owner hardware and real networks | A specific gateway, ISP and carrier | Required per milestone |

Each layer narrows a different gap; none substitutes for the one below it. In particular, a
simulated gateway is a declared model. Whether the owner's real gateway behaves like a given model
is a separate measured fact, and physical acceptance remains the only evidence for it.

### Layer 1: deterministic in-process simulation

`crates/supgang/src/simnet` is a test-only network. Sites have an IPv4 side that is public or
translated by a gateway with RFC 4787's independent mapping and filtering axes
(endpoint-independent, address-dependent, address-and-port-dependent), port preservation,
sequential or seeded-random allocation, idle timeouts, hairpinning and static two-way forwards,
and an IPv6 side that is open or an RFC 6092 stateful firewall with pinholes. Hosts roam between
sites or go offline; gateways renumber; seeded loss applies at uplinks. Every discarded datagram is
counted by reason, so a scenario asserts which gateway refused a path. Calibration tests in
`simnet/tests.rs` pin each modeled behaviour with raw datagrams before any QUIC runs over it.

`service/tests/sim_harness.rs` runs the production `service_loop` for each simulated computer on
its own thread and runtime, with its own state directory, control socket, and a simulated socket
through quinn's `AsyncUdpSocket`. A test-only thread-local view answers that computer's interface
and route questions (`network::simulated`); production builds do not contain it. Identity,
admission, scheduling, gossip, record signing and tunnels are the real code. Scenarios in
`service/tests/scenarios.rs` pair two computers at home, move the laptop to a hotel or a phone
hotspot, and assert either the expected authenticated path with tunnel bytes intact, or honest
unreachability with the refusing gateway identified.

Known limits: scenarios run in real time with one-second retry rounds, so behaviour that depends
on hours of wall-clock time (record expiry after sleep) is not yet covered; the model has no
NAT64/464XLAT, captive portals, port-restricted egress, latency or MTU; and routes are by family,
not by prefix. These are model extensions, not reasons to trust a scenario beyond its model.

## Reuse decision

Use K7 as the lab's orchestration layer: declarative decks, bounded jobs, guest
lifecycle, image provenance, resource accounting, output collection, and teardown.
Operate it through its public CLI/SDK/API, not private daemon calls or direct helper
invocations. Do not construct a second daemon or change the operator's K7 identity.

K7 is not itself the packet-impairment engine. Reuse the Linux kernel's network
namespaces, veth, nftables/conntrack, and iproute2/netem for the modeled routers.
Implement only the integration and test-specific assertions that existing tools
do not provide. Pin the kernel, guest image, tools, scenario, and Supgang artifact;
record hashes and actual versions in every result.

Quarters is optional user-state separation for native process tests and developer
commands. Its baseline preserves host networking and permissions; it cannot prove
network isolation. Do not start another K7 authority inside a Quarter. Supgang
state still uses new owner-only identities and explicit state directories.

Remap belongs in a separate optional integration suite: consume the peer's verified
address, resolve a test hostname, exercise DNS cache changes, and confirm stale
names cannot mask discovery failure. Baseline Supgang tests use literal addresses
and must pass with no Remap installation. Never change the developer's ordinary
DNS mappings or resolver to run the lab.

## What current K7 provides, and what it does not establish

Source review used K7 revision `823b38eda23e7fdf28d958e12989a51e716dc768`:

- `runtime/src/providers/macos/apple_container_provider.cxx` selects `native-nat`
  regardless of the kassette network string. Its provider tests assert that
  behavior. The helper's additional modes are not automatically public capabilities.
- `runtime/src/platform/macos/vz_helper.swift` attaches `VZNATNetworkDeviceAttachment`
  in both ordinary macOS and Linux VM configuration builders.
- `runtime/src/k7d/dispatch/dispatch_deck_run.cpp` rejects mixed-provider isolated
  decks involving Apple containers. Local-provider isolation is not a packet-level
  security boundary.
- VM lifecycle and CI guest orchestration exist. A reported running guest, schema
  validation, or an `isolated` flag is not proof of an air-gapped packet topology.

These are an integration gap, not a reason to bypass K7 or weaken Supgang's checks.
Do not repurpose existing CI guests, restart the shared runtime, or change global
provider defaults to accommodate this suite.

## Native macOS path

Proposed composition, to be proven through K7:

```text
                       K7 controller on the Mac
                      /          |           \
              management    lifecycle     evidence
                    /            |             \
      macOS peer A VM ---- isolated packet lab ---- macOS peer B VM
                                  |
                      Linux router/test appliance
                     namespaces + nftables + netem
```

Each macOS peer runs the real Supgang executable with independent identity,
filesystem, interface configuration, and operating-system network stack. The
packet lab represents two independent access networks and the intervening network.
It must not connect peer traffic to the physical host LAN or Internet.

Apple's `VZFileHandleNetworkDeviceAttachment` exposes a VM interface as connected
datagram-socket Ethernet frames. It is a candidate for a K7-owned private packet
attachment, avoiding a default NAT adapter, a physical bridge, and host firewall
changes. Apple documents that this attachment does not need the
`com.apple.vm.networking` entitlement. This is not a waiver of the Virtualization
entitlement, normal signing, guest licensing, or other platform requirements.

The extension belongs in K7's schema and native provider, not in a Supgang-specific
helper that bypasses K7 authority. It needs an explicit attachment capability,
private bounded frame channels, ownership validation, guest-device readback,
failure propagation, and lifetime-bound cleanup. Reject unsupported attachments;
never substitute NAT, host mode, or a user-owned remote machine.

Management must remain separate from the network under test. A guest agent may
configure the synthetic interface, start/stop a peer, and collect evidence. It
must not carry Supgang traffic, inject a newly learned contact, or reveal another
peer's changed address after the scenario starts. A management NIC, if present,
must not be visible as a usable Supgang route. Prefer a non-IP guest channel and
verify its availability for each guest type rather than assuming Linux and macOS
have identical facilities.

## Linux and fast development paths

For Linux kernel coverage, two real Linux Supgang processes can run in separate
network namespaces inside one K7-managed Linux guest, each with its own private
state. Routers live in additional network namespaces. A process-shared kernel is
an explicit fidelity limit; separate-guest runs cover kernel independence.

Keep the existing in-process real-QUIC tests for fast scheduling, identity, and
candidate regressions. They are model tests, not evidence of real kernel NAT,
macOS interface-change notifications, firewall approvals, or guest isolation.

Patchbay 0.7.0 was evaluated as an alternative orchestration library. Its published
lab defaults use `198.18.0.0/15` and `2001:db8::/32` for simulated public networks.
Supgang correctly rejects these as globally routable endpoints. An integration
must configure suitable isolated fixtures without relaxing production address
validation. Do not assume unreleased Patchbay changes or router-mapping support.

## Required test contract

1. Create fresh identities and pair through the ordinary public CLI while the
   initial topology permits contact. Freeze the setup channel before transitions.
2. Record the exact two peer identities, executable hashes, topology hash, seed,
   guest/kernel versions, enabled test features, and time/clock assumptions.
3. Calibrate the topology independently before starting Supgang. Measure the
   specified mapping and filtering behavior using bounded test traffic, prove
   no alternative route exists, and check all expected guest interfaces.
4. Require both peers to authenticate the expected identity and report the actual
   connection tuple. Compare transport counters over time and require a newly
   signed record or application-level change to propagate. A ping, process count,
   stale signed record, or `connected` sample alone cannot pass.
5. Change the actual interface, route, mapping, or link. No direct state edits,
   new peer-address imports, public reflectors, hidden overlays, or introducers
   are allowed to make a two-device scenario pass.
6. Assert both outcomes: recovery within a stated deadline where the topology
   permits it, and continued honest unreachability when every path is blocked.
   Timeouts, missing capabilities, skipped scenarios, and invalid calibration
   are failures of the requested gate, not successes.
7. Stop only resources created for the run. Prove process, attachment, mapping,
   temporary-state, and network cleanup. Preserve bounded diagnostics on failure.

Synthetic globally classified addresses are permitted only after structural
isolation is proven. Such addresses are not reserved for test use on real networks.
Never probe their real owners to check isolation. Use topology/device inspection
and counters on every modeled boundary. Packet captures are disabled by default;
any explicitly requested capture contains only disposable lab identities and has
an enforced size, access, and retention limit.

Seeds reproduce configured loss/corruption choices, not a bit-for-bit replay of
kernel scheduling. Record the realized events and run repeated seeds. Fully
deterministic scheduler/model tests remain a distinct layer.

## Initial scenario matrix

| Scenario | Required evidence |
| --- | --- |
| IPv4-only and IPv6-only | Correct family is actually used by both peers |
| Dual stack with either family blackholed | Usable family is not starved; failed family is observed |
| Public peer plus translated peer | Translated tuple is independently observed and authenticated |
| Two reachable remembered translated tuples | Bilateral attempts and measured mapping/filter semantics |
| Laptop moves after initial pairing | Identity persists; no contact injection; new signed record propagates |
| Mapping expires or external port changes | Stale tuple fails; recovery uses only permitted knowledge |
| Loss, delay, reorder, and reduced MTU | Impairment counters advance; recovery and resource bounds hold |
| Peer restart and simultaneous restart | Durable history survives; no test-only rendezvous service |
| Every path blocked or both tuples unknowable | No false connected/public-reachable claim or external fallback |
| Unauthorized peer or wrong transport identity | No authenticated session or durable authority change |

Gateway mapping tests require an actual pinned PCP/NAT-PMP/UPnP implementation
inside the lab, such as MiniUPnPd, plus renewal, rejection, expiry, and dishonest
reply cases. Do not label generic NAT rules as gateway-protocol coverage. Remote
update failure tests need separate signed test metadata and no production root.

## Acceptance boundaries

This document selects the integration direction; it does not claim a working
K7-backed Supgang network lab. The first implementation gate is K7 packet-attachment
support plus isolation calibration, followed by actual two-peer scenarios. Do not
wire a supposedly required WAN CI gate until it executes the real workload and
rejects a deliberately broken recovery build.

Guest tests supplement, not replace, physical macOS checks for sleep/wake, Wi-Fi
roaming, Local Network privacy, owner signing, firewall identity, and ISP/router
behavior. Report Linux, macOS-guest, and physical-WAN results separately.

## Primary references

- [K7](https://github.com/kassettes/kassette), with the source revision above.
- [Apple packet-level VM attachment](https://developer.apple.com/documentation/virtualization/vzfilehandlenetworkdeviceattachment).
- [Apple Containerization](https://github.com/apple/containerization), an open-source
  Linux guest implementation on macOS, not an emulator of the macOS network stack.
- [Linux network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html).
- [iproute2 netem](https://man7.org/linux/man-pages/man8/tc-netem.8.html), including
  random seeds and kernel timer limitations.
- [Patchbay](https://github.com/n0-computer/patchbay).
- [MiniUPnPd](https://github.com/miniupnp/miniupnp/tree/master/miniupnpd).
