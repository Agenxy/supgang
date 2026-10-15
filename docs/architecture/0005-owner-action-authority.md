# ADR 0005: Owner action authority for Agenxy tools

Status: **Proposed for owner and consumer review; no protocol or API in this ADR is implemented**

Date: 2026-10-14

## Problem and boundary

The owner wants any of their authorized computers to request a security-sensitive action on
another one. Every Agenxy tool must keep its own identity, approval, and TLS mechanisms as the
default and work independently when Supgang is absent. Supgang is an optional provider that an
owner explicitly enables for identity, certificates, permissions, and authentication, without
requiring a separate in-person approval at every tool. Remap's proposed ADR-0022 needs this for
root-owned DNS reactivation; K7's owner-approval path is another consumer. Supgang
authorization can only narrow the consumer's own operation policy.

Today Supgang authenticates **devices**, not people. A current hive membership proves that a
device key belongs to the hive; it does not prove a human approved a particular action. ADR 0001
leaves delegated administration unimplemented. The device-certified keys in ADR 0003 prove
possession and bind a key to an audience; a device cannot grant itself owner authority by issuing
one. The closed root-step operation set has no owner-action grant, the root-signed member
revocation snapshot has no expiration, and peer streams have no owner-action type. Supgang's
same-UID control socket is not a privileged local handoff. None of the interface below may be
advertised as available until those gaps are closed and physically tested.

The root is the authority for grants. A member, a key with an `attest` certificate, a working
QUIC session, or arrival through a Supgang tunnel is **not** by itself an administrator. A
grant names the exact signer and consumer policy the owner approved. It does not claim fresh
human presence unless a separately specified key provider enforces it.

## Proposed grant

One common assertion format serves every consumer; grants remain separate by consumer. A
root-authorized, canonical grant records:

| Field | Meaning |
| --- | --- |
| `hive_id`, `grant_id` | Exact hive and a random, never-reused 16-byte grant identity. |
| `signer` | Exact enrolled public key and algorithm, bound to a device or owner credential with a possession proof. |
| `consumer_id` | Stable product identifier, such as `org.agenxy.remap`; no wildcard consumer. |
| `operations` | Sorted, bounded, closed set of consumer-defined operation identifiers. |
| `target_scope` | Tagged `node(NodeId)` or `hive_nodes(HiveId)`; no implicit wildcard or name lookup. |
| `not_before`, `not_after` | Bounded grant lifetime. |
| `issuer_head` | Root-chain predecessor and sequence needed for rollback and equivocation checks. |

Grant and grant-revocation are new **typed root operations**, with canonical payloads and the
same predecessor, sequence, fork, and durable-write rules as other root steps. The root or
approved threshold policy must issue them; a device authority manifest cannot. Grant
revocation is monotonic and independent of membership revocation. Revoking the signer device
also ends every grant attached to it. A `hive_nodes` grant is an explicit high-impact choice,
not the default. No grant delegates further grants in version 1. A target pins its hive root
and may apply a stricter local allowlist; remote actions cannot change that pin, enable the
mode, enlarge a grant, or alter the local verifier policy.

The owner must select which key represents an owner action. Version 1 should permit an
explicitly enrolled device key or a distinct certified subordinate key, but **only** when the
root grant names that exact key. Supgang must label file-held, synced, and hardware-held custody
honestly. The signer key never leaves its provider. A device key signature proves control of
that device key; user presence needs a separate policy and provider capability. A consumer
requiring fresh presence for an operation, such as K7's owner-touch policy, must verify that
the named signer/provider enforced presence for this exact target and operation. Until such
evidence has a defined, verified encoding, a Supgang assertion cannot replace that touch;
the consumer's native policy still applies.

## Proposed shared assertion

The wire object is a bounded, definite-length canonical CBOR array. Integers use shortest
encoding; decoders re-encode and compare. Unknown versions, algorithms, tags, duplicate or
trailing fields, and noncanonical bytes fail. Version 1 signs the exact payload bytes after
`supgang/owner-action/v1\0`; the outer envelope carries `[1, payload:bytes, signature:bytes]`.
The payload is this ordered array:

```text
[
  1, algorithm, hive_id:b32, signer_ref, grant_id:b16,
  target_node_id:b32, consumer_id:text, operation:text,
  request_digest:b32, nonce:b16, issued_at:u64, expires_at:u64
]
```

`signer_ref` has a distinct tag for a member device key and for an enrolled subordinate key,
and binds the signer `NodeId` and exact key identity. The grant fixes the acceptable algorithm;
the assertion cannot choose a weaker one. Algorithms and signature encodings must reuse the
strict Ed25519 and low-S P-256 rules already specified for certified keys. The target must
compare the fields to the pinned grant and to **its own** identity, rather than trusting a
name supplied in the request.

The digest is `SHA-256("supgang/action-request/v1\0" || canonical_consumer_request)`. Each
consumer defines one versioned, bounded canonical request encoding, which may be canonical JSON
or another unambiguous format. It includes the exact arguments and target-observed
preconditions checked immediately before the effect. For Remap DNS activation, that includes
the operation's arguments and the resolver plan the target last reported. For K7, its native
approval policy may narrow a Supgang grant and must bind
the exact operation it executes. A generic digest of a human-readable description is not
sufficient. The target rejects a changed plan or arguments even with a valid signature.

The assertion has a short validity interval; the consumer may impose a shorter one (Remap
proposes five minutes). The target checks time and clock reliability before acting. It records
the `(hive_id, signer_ref, nonce)` as spent in protected durable storage **before** invoking
the consumer operation. A bounded nonce ledger retains entries through expiry plus clock
skew, fails closed on exhaustion, and survives restart. The consumer operation remains
transactional and checks its own preconditions. No peer address, secret, request body, or
assertion bytes enter command arguments, ordinary logs, URLs, or crash reports.

## Precondition discovery

The requester needs authenticated access to the target's current precondition bytes before
signing a request digest. For Remap, the resolver plan may contain private upstream addresses.
The design must choose a bounded read-only observation exchange or a target-issued challenge
that returns those bytes and a fresh target nonce. Remap prefers the challenge. Either path
must authenticate the target, restrict disclosure to a device named by an applicable grant,
bound the returned bytes and challenge lifetime, and keep them out of ordinary logs. The
target must compare the signed preconditions to its own state immediately before the effect.
If a challenge is chosen, the assertion must sign its target nonce and precondition bytes;
issuing it cannot change durable authority state. A challenge may include target time so the
requester need not rely on its own clock, but it does not replace target-side assertion-expiry,
status-lease, or replay checks. The exact challenge encoding, one-use rule, and clock semantics
remain undecided.

## Revocation freshness

The present root-signed member list contains `serial` and `issued_at`, but no expiry or proof
that another member has not seen a newer revocation. Authenticated anti-entropy distributes
latest-known state; receipt time does not renew it. In particular, an old empty list cannot
become fresh merely because it arrived over a live session. The certified-key authority
manifest has its own `next_update` check, but it does not supply owner-grant or membership
freshness. Remap and K7 must not infer a freshness bound from either mechanism.

Version 1 therefore needs a root- or approved-threshold-signed **status lease** that binds
the hive, current root-chain head, member-revocation serial, grant-revocation serial, issuance,
and expiry. Its issuer must have the actual authority to state that no newer root operation is
effective as of issuance. A target retains monotonic heads and serials, refuses rollback or
equivocation, and requires a lease within the owner-approved maximum age at the moment it
executes an action. A live peer cannot extend a lease by relaying it. A partitioned target
fails closed when the lease expires. This gives a **bounded delay** before a new revocation
takes effect at a disconnected target, not instantaneous global revocation.

The owner must decide the maximum lease lifetime and which authorized signers can renew it
remotely while traveling; an at-home-only renewal path would defeat Remap's remote recovery
use case. A five-minute assertion expiry does **not** imply five-minute revocation freshness.
No numeric revocation bound is endorsed by this ADR yet; until the signing and availability
model is decided and implemented, Supgang owner-action mode remains unavailable.

## Delivery and local authority

A new typed, versioned, bounded peer stream carries one owner-action request on an already
authenticated Supgang QUIC session. Admission, frame size, queue length, per-peer concurrency,
timeouts, retries, and cancellation are explicit limits. No general RPC, peer-selected local
port, arbitrary forwarding, public listener, hosted service, or vendor relay is introduced.
Transport authenticates the sending **device** and supplies a route; it does not authorize the
action. The signed assertion can name a different enrolled signer only if the grant allows it.

The unprivileged Supgang service hands the bounded request and proof to a consumer-owned
verifier over an OS-approved authenticated local boundary. Remap needs a privileged helper;
K7's `k7d` can verify the proof itself through its Automation API. Supgang's existing same-UID
socket cannot be called a root-only channel, and an owner process cannot open a literal
mode-0600 root-owned socket without an explicit platform authorization path. macOS and Linux
adapters must state which process accepts the request, how that endpoint authenticates its
local caller, and how the consumer stores the nonce and verifier state. Remap proposes a macOS
XPC Mach service with an audit-token check against a pinned Supgang code requirement, which
depends on a stable Supgang signing identity; Linux may use `SO_PEERCRED` and a dedicated
Supgang service account. The consumer-owned verifier independently checks the pinned hive
root, membership or signer credential, root grant, signed status lease, both revocation sets,
canonical assertion signature, target, exact operation, digest, time, and spent nonce. It then
applies the consumer's own policy. It refuses any missing or stale
proof even if Supgang delivered the bytes successfully.

Local enabling of Supgang mode and trust-anchor changes remain owner-approved through the
consumer's existing native boundary. A missing Supgang installation does not break a tool's
native mode. Native modes use each consumer's own keys, schema, and domain separators; K7 may
use its own `k7/owner-action/v1` and `k7/action-request/v1` domains. Supgang mode has no hidden
fallback to an unauthenticated path.

## Decisions required before implementation

1. Which owner-held key providers and user-presence properties are required for version 1?
   How does a grant require and a verifier validate fresh presence for an exact action? Naming
   a key alone must not be described as a human signature.
2. What is the maximum status-lease lifetime, and which root or threshold signers may renew it
   **remotely** while the owner is away? Availability after expiry and the bound on revoked
   authority must be stated together.
3. Will a requester use read-only observation or a target-issued challenge to obtain current
   preconditions? Define authentication, disclosure scope, target nonce, time, and replay rules.
4. What are the exact per-grant lifetime, operation-count, request-size, concurrency, and
   clock-skew ceilings? Consumers may narrow them but cannot widen them.
5. Which macOS and Linux IPC mechanisms give each consumer verifier a verifiable caller
   without granting ordinary same-UID processes administrative authority?

The Supgang lead and owner must settle these before this ADR changes from Proposed. Remap
ADR-0022 and K7's Supgang authorization mode remain proposed consumers; neither should ship
against this draft's bytes or presume the missing grant, lease, or delivery APIs exist.

## Acceptance evidence required

- Canonical cross-tool fixtures and negative tests for every field, algorithm, scope,
  downgrade, equivocation, replay, clock error, revocation, stale lease, presence requirement,
  precondition challenge, and local policy.
- Durable crash/restart tests proving nonce consumption precedes side effects and rollback
  cannot silently restore spent authority.
- Consumer-verifier tests on macOS and Linux showing that a same-UID untrusted process and
  an ordinary hive member cannot request a privileged operation; K7 must also prove its
  owner-touch requirement still holds in Supgang mode.
- The complete Supgang quality gate, then identical installed artifacts on each configured
  physical peer and a cross-host action through Remap and K7 with their native policies intact.

Until this evidence exists, Supgang's current member authentication and service tunnel must
not be described as an owner-action authorization provider.
