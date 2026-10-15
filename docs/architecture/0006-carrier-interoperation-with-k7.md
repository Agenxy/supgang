# ADR 0006: Carrier interoperation with K7

Status: Proposed. Owner direction recorded 2026-10-15; no protocol or API here is implemented.

## Direction

The owner, 2026-10-15:

> Supgang should be able to work over K7's network and vice versa depending on the circumstance.
> [...] This should be implemented so that security and independence is not compromised, both
> systems should have automatic fallbacks - this is a synergy/efficiency/performance
> optimization, correctness and security and self sufficiency should always be uncompromised.

Two cases follow. When a Supgang connection is the only route to a computer, K7 should reach its
nodes on that computer through it. When K7 already maintains a link or cluster to a computer,
Supgang should be able to use that link instead of opening a duplicate connection.

## Invariants

These hold in every mode and are acceptance criteria, not goals.

1. **Independence.** Each system works fully alone. Carrier use is chosen per connection,
   is never required, and falls back automatically to the system's own paths when a carrier
   fails, stalls or disappears. Removing either system must not break the other.
2. **End-to-end authentication over any carrier.** Supgang's device-key QUIC handshake and K7's
   mutual TLS with its own pins run unchanged inside a carrier. Neither system hands keys,
   session secrets or authorization to the other. A compromised carrier can delay or drop
   bytes; it cannot read, alter undetected, impersonate or authorize.
3. **Carrier claims are hints.** Addresses, reachability or identity a carrier reports never
   become Supgang's device-signed candidates or independently observed reachability, and never
   satisfy K7's pins. They only rank candidate paths.
4. **No recursion.** A system never selects a carrier path that is itself carried by that system.
   Each carrier path is labelled with its carrier chain, and a path containing the requesting
   system is refused.
5. **Bounded.** Streams, buffered bytes, datagram queues and setup attempts per carrier and per
   peer have fixed ceilings, as everywhere else in Supgang.
6. **Strict mode.** Using a carrier adds no public connection that Supgang would not otherwise
   make; a carrier's own network behaviour remains that system's responsibility and disclosure.

## K7 over Supgang

Today, `supgang expose k7 <port>` on the target and `supgang connect <peer> k7` as K7's
`proxy_command` carry K7's mTLS byte stream to a loopback listener. Each stream starts a process.

Proposed: a local, owner-only stream endpoint (on the existing control socket's authority) from
which K7 requests a stream to a named service on a named peer, multiplexed over the one existing
Supgang connection. K7 nodes behind the target, such as its VMs or containers, are reached
through one K7 gateway service on the target; K7 performs that routing and authentication, so
Supgang learns nothing of K7's internal topology. Service exposure stays explicit, named and
owner-approved on the target.

### Local stream endpoint, version 1 (shipped)

The owner-only control socket already provides the stream endpoint other local tools need, and
`supgang connect` and `supgang forward` use it. Its contract, for consumers such as Remap's
`supgang://peer/service` target:

- **Socket.** `<state>/control.sock`, by default
  `~/Library/Application Support/org.agenxy.supgang/control.sock` on macOS. The directory is
  owner-only. Both ends verify the peer's user identity (`LOCAL_PEERCRED` or `SO_PEERCRED`), so
  only the service's own user can open streams; the endpoint confers nothing beyond what that
  user can already do with `supgang connect`.
- **Request.** One frame: a 4-byte big-endian length, then `SUPGIPC1`, the byte `0x07`, the
  32-byte target node identity, and the 16-byte service name in ASCII padded with zero bytes.
  Peer names and tags resolve to node identities through the ordinary read-only commands
  (`supgang --json resolve <peer>` reports `node_id`).
- **Reply.** One frame: a 4-byte big-endian length, then JSON. `{"response":"connected"}` is
  followed on the same socket by the service's raw bytes in both directions until either side
  closes; half-close is carried. `{"response":"error","message":"..."}` ends the exchange. Callers
  key on the tag, never on message text.
- **Bounds.** The peer must have a live authorized session; streams are admitted against the
  per-peer and runtime tunnel limits (owner-configured, `supgang tunnel-limits`); setup times out
  after a few seconds; the target connects only to the loopback port its owner exposed under
  that name.
- **Security.** Bytes are opaque. A consumer that expects TLS keeps verifying its own pin inside
  the stream; the endpoint never terminates or inspects it.

Version 2 may add a request that names the peer and service in one typed frame; version 1 stays
supported while consumers depend on it.

## Supgang over K7

Supgang's transport is already a pluggable `quinn::AsyncUdpSocket` (the in-process simulator uses
the same seam). A K7 carrier becomes another socket implementation: K7 offers "datagram channel to
node X" through a local, owner-only interface; Supgang lists it as a candidate path of a new
`carrier` kind, ranked with its direct candidates, and runs its full handshake over it. Datagram
carriage is required so that two reliable transports are not stacked. If the K7 channel fails,
Supgang's ordinary candidates take over within the existing retry schedule.

## Sharing one connection

Where both systems connect the same two computers, one connection should carry both; keepalives
and congestion control then happen once. Which system owns the shared connection is decided per
pair by availability, with the other riding as a carrier, never by giving either system the
other's authority.

## Open decisions

- The local interfaces' exact form and authorization on each side, including how each verifies
  the other's executable identity (macOS code requirement, Linux peer credentials).
- How K7 names the node a datagram channel reaches, and how Supgang binds that name to a hive
  member without trusting K7's claim.
- Fairness and accounting when one connection carries both systems' traffic.
- Whether K7's gateway service on a target is one Supgang service or one per K7 node.

## Acceptance evidence required

Simulator scenarios in which each carrier is the only working path, then fails, with automatic
fallback inside a stated bound; negative tests in which a carrier forges addresses, identities or
reachability and is refused; a recursion test; and physical acceptance on two computers with K7
and Supgang each disabled in turn, proving the other still works alone.
