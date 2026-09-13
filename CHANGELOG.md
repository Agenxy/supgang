# Changelog

All notable project changes are recorded here.

## Unreleased

The corrective source reports version `0.2.0-alpha.10` so it cannot be mistaken for the published
`0.1.0` build that failed physical WAN acceptance.

- Keep anchor-mode peers in synchronized outbound recovery instead of making them receive-only.
  This preserves the relay-free chance of crossing compatible NAT and firewall topologies.
- Allow macOS installs to apply an explicitly selected owner-controlled code-signing identity.
- Reject macOS update slots that do not satisfy the active installation's approved designated
  requirement, and validate that boundary again at activation and supervisor handoff.
- Correct macOS login startup to use the Aqua session. Legacy Background registrations are
  reported as requiring repair because they did not restore after reboot.
- Add reviewed owner setup for a system boot job that runs as the ordinary owner, with
  explicit approval of the verified supervisor and runtime in the macOS firewall.
- Observe a new runtime instance before completing unattended restart. Preserve the approved
  signing identity during local refresh and bound interrupted update probations across reboot.
- Refresh an installed service's executable and active slot without replacing its endpoint,
  anchor, or router-mapping settings.
- Preflight background-manager restart readiness before arming an update, disarm a pending update
  after a failed restart, and reject or clear stale slots so an install cannot roll backward later.

### Added

- Added explicitly owner-enabled renewable UDP port mapping through PCP or NAT-PMP in automatic
  endpoint mode, with global-address validation, rate-limited signed updates, explicit unverified
  provenance, network-change replacement, default-off policy, and best-effort orderly lease deletion. UPnP is
  disabled because its unauthenticated discovery can redirect the client to another LAN service.
- Added live connection, router-mapping, and Internet-path status to the CLI, local control API, and
  MCP output. Saved signed addresses are no longer described as fresh when no session exists.
- Added native per-user background service management through launchd on macOS and systemd on
  Linux. Installation starts the service, waits for its authenticated local control channel, keeps
  ordinary output disabled, and preserves identity and peer history on removal.
- Background-service installation accepts a validated owner-only endpoint file for networks where
  the user manages a firewall opening or port forward but the gateway offers no automatic mapping
  protocol.
- Added authenticated peer-assisted UDP traversal. A connected member can exchange the source
  sockets it directly observes for two other connected members, after which both targets attempt a
  direct QUIC path from the service socket.
- Added an explicit user-owned anchor role through `supgang anchor` and
  `supgang service install --anchor`. It retains at most 64 authenticated neighbors for signed
  record exchange and direct-path coordination without becoming a hosted service or traffic relay.
- Added a bounded, local standard-I/O MCP server with read-only `fleet`, `resolve`, and `status`
  tools, exact 2025-11-25 and 2026-07-28 protocol support, structured output schemas, and explicit
  safety annotations.
- Added file-carried and authenticated-peer-carried TUF updates with explicit local root pinning,
  persistent metadata rollback state, exact platform targets, bounded streaming, content-addressed
  owner-only slots, and stable JSON status.
- Persisted the latest verified TUF root as the next trust anchor before target staging, retained
  one protected previous generation, and rejected bootstrap-key revival after a legitimate
  rotation.
- Made root-authorized peer updates durable across temporary disconnection and service restart.
  At most four exact prepared bundles are retained for 24 hours, protected from outbox eviction,
  re-authorized only after an authenticated peer reconnects, and removed after acceptance,
  rejection, revocation, or expiry.
- Added a protected A/B supervisor for launchd and systemd service installations. It retains the
  last known-good payload, requires a candidate to remain locally healthy through a probation
  window, and rolls back failed candidates without replacing the supervisor itself.
- Recorded a redacted two-physical-host macOS run covering enrollment, direct authenticated QUIC,
  signed-record convergence, bilateral restart recovery, contact tamper rejection, and address
  privacy.

### Changed

- Reclassified 0.1.0 as a failed wide-area acceptance: it passed local-network two-host validation
  but did not reconnect Laptop A and Home B after Laptop A moved to an outside network.
- Prioritized user-owned relay and gateway-mapped candidates over global-looking virtual-interface
  addresses when a peer is not on an attached local prefix.
- Excluded tunnel, container, peer-to-peer, and virtual bridge interfaces from automatic address
  publication. Deliberately selected overlay addresses remain available through `--endpoints`.
- Replaced address-bearing `publish` and `run` arguments with one bounded owner-only endpoint
  configuration file, and removed the listen address from ordinary startup JSON.
- Route selection now checks the laptop's current physical-network address families before calling
  a peer address preferred or spending a retry on it. Signed but unusable addresses remain visible
  and are described as unavailable from the current network.
- Up to four ranked candidates are raced with 125 ms spacing. Bilateral recovery uses hive-aligned
  wall-clock windows, and the secondary direction now probes once per four rounds.
- Both endpoints now retain the same authenticated reverse-direction connection as a fallback. A
  preferred connection can deterministically replace it during simultaneous dialing, and outbound
  fallback connections remain usable for a user-owned anchor.

### Security

- Split unauthenticated inbound work from the reserved outbound recovery pool, capped Quinn's
  pending handshakes and buffer memory, added IPv4 and IPv6-prefix admission windows, and made peer
  connection teardown cancel every sibling listener even when the event queue is saturated.
- Moved duplicate and capacity admission ahead of all peer-driven durable mutations. Authenticated
  public-address updates are coalesced and limited to four per five minutes.
- Added atomic authoritative-state compaction with a device-signed snapshot checkpoint, bounded
  peer-directory equivocation evidence, and restart tests from a near-full journal.
- Bound offline enrollment to the separately confirmed joining node and hive identities before any
  mutation.
- Background services now execute an owner-only protected copy of the installed binary and reject
  replaceable ancestor directories for state, executable, service-definition, and endpoint paths.
- Secret-key loads now read through exact fixed ceilings and clear the temporary identity and
  transport-key buffers immediately after decoding; trailing growth fails closed.
- Router mapping is isolated behind one module and accepts only globally routed results. A mapped
  address remains explicitly unverified until an authorized peer completes pinned TLS and mutual
  device authentication.
- RustSec continues to deny every vulnerability, unsoundness, yanked crate, and maintenance warning
  except the documented `RUSTSEC-2024-0436` notice for the stable compile-time macro used by Linux
  `netlink-packet-core`.
- The dependency licence gate allows BSD-2-Clause and one exact MPL-2.0 exception for the UPnP
  client's `attohttpc` 0.30.1 dependency. MPL notices and covered source availability are explicit
  release obligations.
- MCP request, response, and structured-result sizes are independently capped. Offline MCP reads
  use validating snapshots that never create or repair durable state, and the server exposes no
  HTTP listener, authentication token, subprocess bridge, or network client.
- Protected artifact reads now open nonblocking and no-follow before validating metadata, so FIFOs
  and other special files fail closed instead of stalling a command before validation.
- Safe owner-only stale control sockets now mean the service is stopped, allowing offline commands
  to read state after an unclean service exit without weakening socket ownership checks.
- Endpoint configuration rejects unsafe permissions, symlinks, unknown fields, duplicates, invalid
  address classifications, and candidate sets beyond the eight-entry protocol ceiling.
- Owner-declared gateway forwards retain `mapped` provenance instead of masquerading as direct
  interfaces, preserving their higher retry priority and accurate Internet-path status.
- Mapped endpoints are rejected when the service listens only on loopback, and compact output never
  marks an address preferred when the current physical network cannot route its address family.
- Peer-assisted traversal frames are canonical and capped at 256 bytes. They are accepted only on
  mutually authenticated sessions, rate-limited per connection, and cannot change durable state.
  A received offer schedules at most one attempt after a recent local recovery choice for that
  stable peer, only globally routed sockets enter the attempt scheduler, and the attempt still
  requires the signed transport pin and mutual device proof.
- Authenticated revocation frames are intake-paced, and long-lived connection supervisors are
  tracked and canceled with the service instead of being detached from shutdown accounting.
- Remote updates are authorized by the hive root for one authenticated issuer, receiver, bundle
  digest, exact length, durably single-use nonce, and short validity window. The receiver treats the peer as an untrusted courier and
  independently enforces its separate TUF root, expiry, threshold, target hash, platform, executable
  format, and monotonic version policy. Update transfer and state mutation are serialized across
  peers and processes, with bounded inbox, outbox, metadata, target, stream, and slot resources.
- Remote update receipt now verifies and stages only; activation requires a separate local owner
  command. Fair admission follows short authorization preflight, body transfer does not hold the
  update lock, and temporary receiver failures preserve the sender's durable queue.
- Protected files and directories now reject non-owner extended ACL grants through descriptor-based
  macOS and Linux checks, and new protected objects have inherited ACL state removed before use.
- Authoritative journals now maintain a durable checksummed head witness that detects committed-tail
  truncation. Whole-state snapshot rollback still requires an external monotonic witness.

## 0.1.0 - 2026-08-16

### Added

- Rust 2024 workspace, Apache-2.0 licence, exact dependency pins, and typed repository gate.
- Stable hive and device identities with domain-separated Ed25519 roles.
- Recipient-generated offline join requests and root-signed membership bundles.
- Canonical bounded endpoint, contact, session, gossip, and revocation protocols.
- Crash-safe authoritative journal, exclusive state ownership, and atomic peer-cache compaction.
- TLS 1.3 QUIC transport with certificate pins, disabled 0-RTT, exporter-bound mutual
  authentication, deterministic connection direction, and strict resource limits.
- Foreground macOS and Linux service with graceful signal handling and an owner-only local control
  socket.
- Direct signed contact bootstrap, bounded peer reconciliation, exact-node resolution, and
  authenticated global-source observation.
- Permanent monotonic device revocation with immediate acknowledged notice, disconnect, target
  persistence, and restart refusal.
- Versioned JSON for automation and address-redacted ordinary peer status.
- Repository-backed architecture, prior-art research, threat model, security policy, and CI.

### Known limitations

- No automatic LAN rendezvous, NAT hole punching, router mapping, or owned relay.
- No native key store, root recovery, generation recovery, or external rollback witness.
- No service package, GUI, manpage, or completion bundle.
- Live multi-process acceptance is complete on macOS only in this snapshot.
