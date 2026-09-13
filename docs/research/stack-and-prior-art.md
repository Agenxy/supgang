# Stack and prior-art research

Date: 2026-08-20

Status: M1 decision record with corrective WAN traversal review

## Result

The review found no maintained open-source utility that meets Supgang's complete constraint set:
stable identity-to-changing-address resolution, no public or vendor infrastructure, no required
fixed anchor, no VPN data plane, and recovery through only the user's devices.

The implemented M1 stack is Rust 1.97.1 with Quinn 0.11.11, rustls 0.23.43, AWS-LC, Tokio 1.53.1,
Ed25519 Dalek 3.0.0, and canonical Minicbor 2.3.0. Every direct version is exact and the lockfile is
committed. `noq` remains research input, not a shipping dependency.

Rust is the best choice for this project at the current boundary because:

- the deliverable is one low-idle, unprivileged macOS and Linux binary;
- memory safety matters on hostile network and filesystem input;
- the strongest current QUIC, TLS, Ed25519, zeroization, and platform-I/O options compose in one
  type system;
- role-specific key types, canonical wire types, and warnings-fatal policy are enforceable at
  compile time;
- there is no garbage collector or language runtime to package;
- a future Swift UI or narrow native key-store binding can sit above the portable Rust core.

Rust does not make protocol design automatically safe. Dependency build scripts, native AWS-LC,
unsafe code inside dependencies, cancellation, parsing, and filesystem durability still require
explicit review and tests.

## The irreducible boundary

Suppose every member changed address, all old mappings and connections expired, local discovery
cannot cross sites, and no member is reachable at any remembered address. There is no edge over
which a new record can travel. Recovery then requires at least one later event:

- a remembered endpoint becomes reachable;
- an authenticated connection survives or migrates;
- two members meet on one network;
- a member gains reachable IPv6 or an explicit router mapping;
- a user-owned introducer remains reachable;
- the user carries a new signed record across the cut.

Therefore the honest guarantee is conditional: valid state converges while authenticated paths span
the topology. No protocol can guarantee automatic convergence after every path disappears without
introducing some external rendezvous point.

## Prior art

### Iroh

[Iroh](https://github.com/n0-computer/iroh) provides key-addressed QUIC, address discovery, direct
paths, hole punching, and relay fallback. Default discovery and relays use n0 infrastructure. It can
be configured, but its full dependency and protocol surface is much wider than this address plane.
Iroh remains the strongest behavioral reference for later NAT work.

### Syncthing

[Syncthing](https://github.com/syncthing/syncthing) demonstrates local discovery, global discovery,
relay fallback, device identities, and clear operational status. Its default global discovery and
relay services are third-party infrastructure unless replaced, and its file synchronization data
plane is unrelated.

### rust-libp2p and its consumers

[rust-libp2p](https://github.com/libp2p/rust-libp2p) supplies Kademlia, mDNS, Identify, AutoNAT,
Circuit Relay v2, and DCUtR. Projects such as
[Anywherelan](https://github.com/anywherelan/awl) and
[EdgeVPN](https://github.com/mudler/edgevpn) use this family successfully. Internet discovery still
needs bootstrap reachability and relays still need reachable operators. The dependency surface and
VPN features exceed Supgang's M1 need.

### WGMesh

[WGMesh](https://wgmesh.dev/) is close to the original user problem because it distributes WireGuard
endpoints. Discovery uses a DHT, and WireGuard plus TUN management expands privilege and data-plane
scope.

### Pkarr

[Pkarr](https://github.com/pubky/pkarr) is useful prior art for signed mutable records addressed by a
public key. Publication uses the public BitTorrent DHT, which violates strict operation.

### Yggdrasil, cjdns, and full mesh VPNs

These systems prove that self-certifying overlay identities and peer routing work. They still need
initial peers or routing infrastructure and carry a general network overlay. Supgang deliberately
stops at authenticated endpoint knowledge.

The lesson is not that DHTs, DNS, STUN, and relays are poor designs. They supply the path that solves
the network cut. Supgang's strict mode obtains any such path only from user-owned members and reports
when none exists.

## Corrective WAN traversal decision

The 2026 review kept the narrow Quinn transport and implemented a layered policy instead of adding
the full ICE, libp2p, or Iroh graphs:

1. Prefer a directly attached private address when both computers share its prefix.
2. Race up to four independently signed current or historical candidates with short spacing.
3. Ask the attached gateway for a renewable mapping through PCP or NAT-PMP. UPnP is disabled because
   its unauthenticated discovery can redirect the client to an attacker-selected LAN HTTP service.
4. Align bilateral retry windows by hive so both firewalls see outbound UDP at nearly the same time.
5. When a third authenticated member sees both computers, exchange its directly observed source
   sockets and attempt a direct QUIC path from the already bound service port.
6. Let an owner designate one reachable Supgang member as an inbound-oriented anchor, retaining up
   to 64 authenticated device connections for signed-record gossip and direct-path coordination.
7. Keep a future user-owned control relay as the fallback for networks that block direct UDP. It is
   not necessary to learn current signed addresses when both devices can already reach the anchor.

This matches the proven structure in ICE and current peer-to-peer systems: gather several candidate
types, use a side channel to coordinate connectivity checks, prefer direct paths, and retain a relay
for paths that cannot be punched. Supgang deliberately substitutes authenticated user-owned members
for public STUN, coordination, and relay fleets. The libp2p DCUtR design directly informed the
observed-address exchange and synchronized QUIC attempt. RFC 8489 also makes the relevant boundary
explicit: discovering a NAT mapping is a tool, not a complete traversal solution.

The implementation does not claim full ICE interoperability or guaranteed traversal. It has no
public STUN oracle, hard-NAT birthday search, NAT64 synthesis, or general packet relay. Those methods
increase reachability but either require reachable infrastructure, add substantial attack and
dependency surface, or create traffic-amplification responsibilities. They remain measured,
user-owned options rather than hidden defaults.

## Transport decision

### Quinn selected for M1

Quinn is a focused, mature Rust QUIC implementation with a small replaceable API surface. M1 needs
socket binding, TLS configuration, bidirectional session streams, one-way revocation notices,
connection identity export, and strict resource budgets. Quinn provides those without bundling a
public discovery or relay system.

Supgang configures:

- Quinn 0.11.11 with Tokio and rustls/AWS-LC only;
- TLS 1.3 and exact `supgang/1` ALPN;
- disabled client and server early data;
- a signed hash pin for the self-signed transport certificate;
- four bidirectional and two unidirectional streams;
- 64 KiB stream and 256 KiB connection receive windows;
- 45-second idle timeout and 15-second keepalive;
- application mutual authentication bound to a TLS exporter.

### Why `noq` was not selected

`noq` 1.1.1 offered attractive multipath, QUIC address discovery, observed-address, and coordinated
NAT experiments. It was also new, carried a larger graph in the spike, and based important behavior
on developing protocol work. None of those features removes the need to build identity, membership,
revocation, durable registers, and conditional recovery correctly first.

The decision is not permanent. Later NAT work can compare current Quinn, `noq`, and Iroh under the
same loss, migration, simultaneous-change, resource, and dependency tests. Durable Supgang records
do not expose transport-library types.

## Core dependencies and roles

| Component | Exact version | Narrow role |
| --- | ---: | --- |
| Rust | 1.97.1 | Edition 2024 compiler and standard library |
| Quinn | 0.11.11 | QUIC transport only |
| rustls | 0.23.43 | TLS 1.3 configuration and exporter |
| rcgen | 0.14.9 | Local self-signed transport identity generation |
| Tokio | 1.53.1 | Single-thread runtime, Unix socket, signals, bounded channels, timeouts |
| Ed25519 Dalek | 3.0.0 | Root and device signatures |
| Minicbor | 2.3.0 | Canonical bounded CBOR primitives |
| SHA-2 | 0.11.0 | Identifiers, pins, journal checksums |
| getrandom | 0.4.3 | Operating-system entropy |
| rustix | 1.1.4 | Safe file ownership, mode, and type inspection |
| nix | 0.31.3 | Same-UID Unix peer credentials on macOS and Linux |
| Clap | 4.6.6 | Typed non-interactive CLI |
| Serde / serde_json | 1.0.229 / 1.0.151 | Versioned local JSON output and control responses |

The code uses a purpose-built checksum journal instead of a database. At this scale, the journal is
smaller, audit-friendly, append-before-publish, and able to make recovery policy explicit. The peer
cache compacts atomically at 8 MiB.

## Alternatives

### Go

Go is the runner-up. It offers simple static distribution, excellent concurrency tooling, and mature
libp2p. Selecting libp2p would bring a substantially wider stack; reimplementing the narrow secure
transport and platform boundaries would give up the strongest current Rust ecosystem advantage.
Garbage collection is not disqualifying, but it is unnecessary for this small persistent daemon.

### Swift

Swift is a good future choice for a native macOS UI and Keychain integration, not for the portable
protocol owner. Linux parity and the relevant QUIC ecosystem would be weaker.

### C, C++, or Zig

They can produce excellent small binaries, but manual memory-safety exposure is the wrong trade for
hostile parsers and a security-critical background service. Zig's ecosystem for QUIC, TLS, and
cross-platform secret providers is not yet competitive for this project.

## Remaining acceptance work

Before a production release, the selected stack still needs:

- a fresh zero-finding RustSec and permissive-licence result for the release lockfile;
- macOS arm64 plus Linux arm64 and x86-64 live protocol acceptance;
- coverage-guided decoder fuzzing and a retained regression corpus;
- long-running packet, stream, unreachable-address, and peer-fanout load tests;
- network-namespace proof that strict mode has no unexpected egress;
- measured binary size, resident memory, idle CPU, wakeups, and keepalive traffic;
- current transport comparison before hard-NAT prediction or a control relay is added;
- signed reproducible release artifacts, checksums, provenance, and SBOM.

## Primary sources

- [Agenxy values](https://github.com/Agenxy/.github/blob/main/VALUES.md)
- [Agenxy engineering standards](https://github.com/Agenxy/.github/blob/main/ENGINEERING.md)
- [Quinn documentation](https://docs.rs/quinn/0.11.11/quinn/)
- [rustls documentation](https://docs.rs/rustls/0.23.43/rustls/)
- [rustls AWS-LC key-exchange groups](https://docs.rs/rustls/0.23.43/rustls/crypto/aws_lc_rs/kx_group/)
- [Tokio signal handling](https://docs.rs/tokio/1.53.1/tokio/signal/)
- [nix peer credentials](https://docs.rs/nix/0.31.3/nix/sys/socket/fn.getpeereid.html)
- [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 8445: Interactive Connectivity Establishment](https://www.rfc-editor.org/rfc/rfc8445)
- [RFC 8489: Session Traversal Utilities for NAT](https://www.rfc-editor.org/rfc/rfc8489)
- [RFC 8656: Traversal Using Relays around NAT](https://www.rfc-editor.org/rfc/rfc8656)
- [RFC 6887: Port Control Protocol](https://www.rfc-editor.org/rfc/rfc6887)
- [libp2p Direct Connection Upgrade through Relay](https://github.com/libp2p/specs/blob/master/relay/DCUtR.md)
- [Tailscale NAT traversal design](https://tailscale.com/blog/how-nat-traversal-works)
- [Tailscale 2025 NAT traversal improvements](https://tailscale.com/blog/nat-traversal-improvements-pt-1/)
- [RFC 10024: hybrid TLS 1.3 key agreement](https://www.rfc-editor.org/info/rfc10024)
- [Iroh endpoint concepts](https://docs.iroh.computer/concepts/endpoints)
- [Iroh address lookup](https://docs.iroh.computer/concepts/address-lookup)
- [Iroh relays](https://docs.iroh.computer/concepts/relays)
- [`noq` 1.1.1 release](https://github.com/n0-computer/noq/releases/tag/noq-v1.1.1)
