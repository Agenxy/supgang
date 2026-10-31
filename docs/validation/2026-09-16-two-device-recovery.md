# Two-device direct recovery

Date: 2026-09-16

Scope: corrective development build. Exactly two participating application peers; no relay,
public STUN, hosted discovery, router configuration change, or additional fleet member.
This record does not claim physical WAN acceptance.

## Implemented

- Both disconnected devices attempt direct recovery in every existing fleet-aligned retry window.
  Identity ordering still resolves competing connections, but no longer suppresses one direction
  for three out of four rounds. Each service still schedules one remembered peer per round and
  keeps the existing four-candidate, timeout, and pending-session limits. This increases attempts
  from the previously suppressed side; it does not change the configured retry interval.
- Candidate batches preserve the first preference and rotate the remaining slots. The previous
  fixed prefix could exclude a usable fifth or later address forever. Rotation is driven by visits
  to each current or historical hint, not by a phase that skips the same addresses on every visit.
- A changed local interface set cancels and drains incoming and outgoing handshakes that captured
  the old contact or route.
  A fresh signed contact is created before subsequent attempts. Connections whose remote address
  is no longer route-compatible are invalidated immediately instead of blocking recovery until an
  idle timeout. Route-compatible connections are retained. Enumeration failure does not falsely
  declare an existing path unusable.

No new dependency, unauthenticated discovery packet, address prediction, authority relaxation, or
wire-format change was introduced. Remembered candidates still pass the existing signed-record,
revocation, conflict, destination-scope, and transport-pin checks. A newly established session must
provide fresh device proofs and contacts before its results enter peer state.

## Tests

The original scheduler failed the new regression requiring both disconnected identities to
participate in the same recovery window. The corrected scheduler passes it.

Candidate coverage tests exercise list sizes from zero through 128, checking the fixed batch
bound, stable first preference, absence of duplicates, and eventual coverage of every address.

A real-QUIC test uses exactly two application endpoints with test-only UDP socket filters. Each
filter rejects packets from a source until its endpoint has sent to that exact address and port.
The test first proves a one-sided attempt is blocked. With both sides attempting, QUIC Retry,
certificate pinning, mutual device proofs, and signed-contact synchronization complete in both
directions. It then verifies that an unchanged route retains the connection and an incompatible
replacement network invalidates its authorization and makes it eligible for recovery.

The filters run inside the test process. They are simulated network boundaries, not a third
Supgang peer or deployed relay. The fixture supplies known socket addresses and does not model
address translation, unknown external mappings, mapping lifetime, or a physical roaming event.
The real-QUIC filtered test also passed ten consecutive runs while the optimized build compiled.

A separate test verifies that network-change cancellation drains all three handshake lanes,
leaves no cancelled task results to fail the service's normal completion loop, and releases its
outbound scheduling slot.

The complete quality gate passed after the final source changes: repository policy, formatting,
all-target checks, warnings-fatal Clippy, 224 core tests, three filesystem ACL tests, one repository
policy test, and warnings-fatal documentation generation. No gates were weakened.

## Installation

Both physical macOS devices now run the same owner-signed artifact. Strict signature verification
passed before remote activation. The ordinary CLI, protected supervisor, and active slot on both
devices match this SHA-256:

`c1c3699cfcb28d65eb1369eb0d65dc2c24505a88d4e218987d10b1f28abda178`

Process inspection confirms both services execute that slot. Service refresh preserved identity,
configuration, and the existing login/boot startup choices. Both reconnected without an owner
prompt. CLI help and doctor ran outside the repository; doctor continues to warn about unverified
Internet reachability and the absence of hardware-backed key storage.

After reconnection, each device completed 120 consecutive status samples at one-second intervals:
120 healthy responses and 120 connected samples on each side. Both received newer signed peer
records than their pre-installation snapshots and preferred a compatible local address while
retaining a public alternative. This establishes the observed two-minute LAN stability, not
long-duration availability, physical roaming, or outside-network connectivity.

## Limits and remaining acceptance

The [IETF NAT traversal analysis](https://datatracker.ietf.org/doc/html/rfc5128) distinguishes
coordinated outbound attempts from discovering the peer's external endpoint. Shared retry windows
do not discover unknown addresses or guarantee compatibility with arbitrary filtering or NAT.
Likewise, [QUIC migration](https://www.rfc-editor.org/rfc/rfc9000.html#section-9) is not a promise
that an arbitrary peer can change networks while every old route disappears.

The required physical acceptance remains two devices on separate networks exchanging fresh signed
records and securely delivering an update, without manual router changes or any third participant.
The home gateway's automatic-mapping service remains inaccessible. These changes do not claim to
discover its public IPv4 mapping or bridge an IPv4-only network to an IPv6-only destination.

The requested Claude Opus 5 review was attempted again but could not start because its saved OAuth
session expired. No independent reviewer verdict or public release is claimed.
