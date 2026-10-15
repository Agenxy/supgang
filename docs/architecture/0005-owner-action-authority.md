# ADR 0005: Owner action authority for Agenxy tools

Status: **Proposed for owner and consumer review; no protocol or API in this ADR is implemented**

Date: 2026-10-14

Updated: 2026-10-15

## Problem and boundary

The owner wants any of their authorized computers to request a security-sensitive action on
another one. Every Agenxy tool must keep its own identity, approval, and TLS mechanisms as the
default and work independently when Supgang is absent. Supgang is an optional provider that an
owner explicitly enables for identity, certificates, permissions, and authentication, without
requiring a separate in-person approval at every tool. Remap's proposed ADR-0022 needs this for
root-owned DNS reactivation; K7's owner-approval path is another consumer. Supgang
authorization can only narrow the consumer's own operation policy.

The owner's travel use case includes administering K7 and Supgang itself from another computer
while Solis is unattended. A design that requires Touch ID or another presence prompt **on the
target** would leave the owner stuck. The owner's presence, where a consumer requires it, must
be established on a device the owner carries and bound to the exact remote action. Supgang
cannot satisfy an operating-system prompt reserved for a person at the target; the product's
remote path must avoid that prompt rather than claim to answer it.

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
| `presence` | Per-operation `required` or `policy`; the assertion cannot choose or downgrade it. |
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

The owner chose two modes for version 1. `required` needs a fresh signature from an enrolled
owner-presence key for **each** action. `policy` allows a root-issued standing grant for a
closed, bounded operation set without a prompt; lease-renewal requests and service refreshes
are candidates, not automatically allowed operations. A grant fixes the mode for each exact
operation. The consumer may demand presence even when the grant says `policy`, but cannot
treat an ordinary device signature as presence when the grant says `required`. `policy` still
requires a grant-named signer, an exact signed assertion, freshness, and replay protection.

The proposed `owner_presence_key` signer kind is a Secure Enclave P-256 key on a computer the
owner carries. It reuses ADR 0003's provider and strict low-S P-256 signature rules. Creation
must set a private-key-use access control that requires biometry or user presence for each
signature; implementation must demonstrate that no reused authentication context silently
authorizes another assertion. The hive root enrolls and certifies the exact public key and
claimed presence policy in an owner-reviewed ceremony. The enrolling device inspects its
local key policy. A target trusts that **root-signed enrollment claim**, not a self-reported
custody label or an attestation at signing time. ADR 0003 explicitly says a peer cannot infer
Secure Enclave residence from a signature. Apple's
[App Attest on macOS 27](https://developer.apple.com/videos/play/wwdc2026/201/) is a separate
app-integrity facility; no attestation of this CryptoKit owner-presence key or its per-signature
policy is implemented or assumed here. The optional `supgang-secure-enclave` helper is not
installed as part of today's Supgang release.

A consumer such as K7 that currently demands target-local touch needs an owner-approved
remote-presence policy with equivalent exact-action checks before it can accept this mode.
Version 1 must never require a Touch ID or Secure Enclave presence check on the target.

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
  request_digest:b32, challenge_digest:b32-or-null,
  nonce:b16, issued_at:u64, expires_at:u64
]
```

`signer_ref` has distinct tags for a member device key, an enrolled subordinate key, and an
enrolled `owner_presence_key`. It binds the signer `NodeId` and exact key identity. The grant
fixes the acceptable algorithm and per-operation presence mode; the assertion cannot choose
a weaker one. Algorithms and signature encodings must reuse the strict Ed25519 and low-S
P-256 rules already specified for certified keys. The target compares the fields to the
pinned grant and to **its own** identity, rather than trusting a name in the request.

The digest is `SHA-256("supgang/action-request/v1\0" || canonical_consumer_request)`. Each
consumer defines one versioned, bounded canonical request encoding, which may be canonical JSON
or another unambiguous format. It includes the exact arguments and target-observed
preconditions checked immediately before the effect. For Remap DNS activation, that includes
the operation's arguments and the resolver plan the target last reported. For K7, its native
approval policy may narrow a Supgang grant and must bind the exact operation it executes.
A generic digest of a human-readable description is not sufficient. The target rejects a
changed plan or arguments even with a valid signature. For `required`, `challenge_digest` is
`SHA-256("supgang/owner-action-challenge/v1\0" || canonical_challenge)`; for `policy` it is
null. The target rejects a mode/digest mismatch with the root grant, or a request digest that
does not match the canonical arguments and preconditions in the challenge.

The assertion has a short validity interval; the consumer may impose a shorter one (Remap
proposes five minutes). The target checks time and clock reliability before acting. It records
the `(hive_id, signer_ref, nonce)` as spent in protected durable storage **before** invoking
the consumer operation. A bounded nonce ledger retains entries through expiry plus clock
skew, fails closed on exhaustion, and survives restart. The consumer operation remains
transactional and checks its own preconditions. No peer address, secret, request body, or
assertion bytes enter command arguments, ordinary logs, URLs, or crash reports.

## Target-issued challenge and prompt

The owner chose a target-issued challenge for presence-required actions. The target's
consumer-owned verifier, a root helper where the operation needs one, issues a bounded
canonical challenge containing the exact operation, target identity, canonical arguments,
target-observed preconditions, fresh random nonce, and expiry. For Remap, the preconditions
may contain private resolver upstream addresses. The requester authenticates the target and
verifies the challenge matches its intended grant and action before asking for presence.
Only a device expressly authorized for that grant receives the challenge; no challenge
contents enter ordinary logs. Issuing a challenge cannot change durable authority state.

The laptop constructs its Touch ID or other presence prompt **only from parsed, validated
structured fields**. It never renders free text supplied by the target as an approval prompt.
The owner-presence key signs an assertion that commits to the complete canonical challenge
through `challenge_digest`; the assertion's nonce is the target nonce and its expiry cannot
exceed the challenge expiry. The target checks the signed challenge against its current state
immediately before the effect, then consumes the nonce durably before acting. Target time may
supply the assertion's time window without trusting the laptop clock. Target-side clock
reliability, lease freshness, and replay checks remain mandatory. Exact challenge bytes,
one-use storage, and clock semantics remain design work.

## Revocation freshness

The present root-signed member list contains `serial` and `issued_at`, but no expiry or proof
that another member has not seen a newer revocation. Authenticated anti-entropy distributes
latest-known state; receipt time does not renew it. In particular, an old empty list cannot
become fresh merely because it arrived over a live session. The certified-key authority
manifest has its own `next_update` check, but it does not supply owner-grant or membership
freshness. Remap and K7 must not infer a freshness bound from either mechanism.

Version 1 therefore needs a **status lease** signed by the root, approved threshold, or an
explicitly root-delegated status issuer. It binds the hive, current root-chain head,
member-revocation serial, grant-revocation serial, issuance, and expiry. Its issuer must have
the actual authority and current-state evidence to state that no newer root operation is
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

The owner chose to permit the presence key on the traveling laptop to authorize remote lease
renewal when an exact root grant allows it. A separate `policy` grant may permit a bounded
unattended renewal request with its own signer. Neither request by itself proves that no
newer revocation exists. The lease issuer must still be the root, an approved threshold, or
a separately root-delegated status authority with authenticated current-head evidence.
Its availability and freshness under travel and partition need a concrete design and test.

## Delivery and local authority

A new typed, versioned, bounded peer stream carries one challenge and owner-action exchange
on an already authenticated Supgang QUIC session. Admission, frame size, queue length,
per-peer concurrency, timeouts, retries, and cancellation are explicit limits. No general RPC,
peer-selected local port, arbitrary forwarding, public listener, hosted service, or vendor
relay is introduced. Transport authenticates the sending **device** and supplies a route;
it does not authorize the action. The signed assertion can name a different enrolled signer
only if the grant allows it.

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
applies the consumer's own policy. It refuses any missing or stale proof even if Supgang
delivered the bytes successfully.

The substitutable scope is an Agenxy-owned operation behind this independently verifying
boundary: for example Remap DNS activation, K7 owner actions, or defined Supgang setup
operations such as firewall rules and Supgang certificate trust decisions. A possible `sudo`
PAM integration is a separate later decision, not part of version 1. This protocol cannot
satisfy macOS-reserved approvals such as TCC privacy grants, System Settings authorization,
system or kernel extension approval, or FileVault pre-boot unlock. Those remain physical or
require a distinct supported operating-system workflow. No product may present an unverified
bypass as remote acceptance.

Local enabling of Supgang mode and trust-anchor changes remain owner-approved through the
consumer's existing native boundary. A missing Supgang installation does not break a tool's
native mode. Native modes use each consumer's own keys, schema, and domain separators; K7 may
use its own `k7/owner-action/v1` and `k7/action-request/v1` domains. Supgang mode has no hidden
fallback to an unauthenticated path.

Supgang itself may consume owner-action assertions for ordinary remote administration while
healthy, but it cannot be its own only recovery path. Every consumer, including Supgang, needs
a pre-provisioned, independently authenticated native recovery path that remains usable when
the target's Supgang service or route is broken. A tunnel carried by that same Supgang service
does not meet this requirement. Before relying on remote administration during travel, the
owner must have an off-network test showing the independent path can repair a stopped or
wedged Supgang on the target without a target-local presence prompt. If the operating system
still requires such a prompt for a particular repair, that repair remains an explicit physical
recovery limit rather than an accepted remote action.

## Open details before implementation

1. How will enrollment verify the carried Secure Enclave key's per-signature presence policy,
   and how will each consumer validate the root-certified enrollment and exact-action proof?
   The root's local enrollment inspection is an explicit trust assumption, not attestation.
2. What is the maximum status-lease lifetime, and which remote root, threshold, or delegated
   status signers can issue a fresh lease while the owner is away? Define authenticated
   current-head evidence, availability after expiry, and the bound on revoked authority.
3. Define the canonical target challenge, authentication, disclosure scope, nonce storage,
   prompt rendering, time, and replay rules for the chosen challenge flow.
4. What are the exact per-grant lifetime, operation-count, request-size, concurrency, and
   clock-skew ceilings? Consumers may narrow them but cannot widen them.
5. Which macOS and Linux IPC mechanisms give each consumer verifier a verifiable caller
   without granting ordinary same-UID processes administrative authority?
6. What independently authenticated native recovery path works for each consumer when
   Supgang is absent or broken, especially to repair Supgang itself on an unattended target?
   Which repairs still require physical intervention because of operating-system policy?

The owner chose the two presence modes and target-issued challenge direction; the Supgang
lead and owner must settle these remaining details before this ADR changes from Proposed.
Remap ADR-0022 and K7's Supgang authorization mode remain proposed consumers; neither should
ship against this draft's bytes or presume the missing grant, lease, or delivery APIs exist.

## Acceptance evidence required

- Canonical cross-tool fixtures and negative tests for every field, algorithm, scope,
  downgrade, equivocation, replay, clock error, revocation, stale lease, presence requirement,
  challenge digest, per-operation policy mode, and local policy.
- Physical carried-device tests proving one fresh OS-enforced presence check per `required`
  action, cancellation before signing, no reusable authentication context, prompt text derived
  only from validated structured fields, and no target-local touch. `policy` actions must be
  proved limited to the exact root-granted operation set.
- Durable crash/restart tests proving nonce consumption precedes side effects and rollback
  cannot silently restore spent authority.
- Consumer-verifier tests on macOS and Linux showing that a same-UID untrusted process and
  an ordinary hive member cannot request a privileged operation. K7 must prove an
  owner-approved carried-device presence policy for Supgang mode without silently weakening
  its native owner-touch gate or requiring a touch on the target.
- An off-network fault test with target Supgang stopped or wedged, proving a separate native
  recovery path can restore it without that Supgang instance or a target-local presence prompt.
- The complete Supgang quality gate, then identical installed artifacts on each configured
  physical peer and a cross-host action through Remap and K7 with their native policies intact.

Until this evidence exists, Supgang's current member authentication and service tunnel must
not be described as an owner-action authorization provider.
