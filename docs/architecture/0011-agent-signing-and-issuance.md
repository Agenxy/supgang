# ADR 0011: Member-authorized signing and issuance

Status: Accepted, partly implemented. Local agent-purpose key policy, vault
format v4, bounded append-only audit with a durable head, durable nonce
reservation, hourly purpose and denial caps, and the member-only remote signing
stream are implemented in source on the root-authority computer. The remote CLI
requires an explicit public-key fingerprint pin and verifies the returned
signature. Other members require a bounded-fresh root status path before
local agent signing is enabled. Remote key creation, certificate issuance,
the consumer pin installer, audit checkpoint rotation, phone approval, and
physical fleet acceptance remain open.

Date: 2026-11-19

## Decision and order

Authorized hive computers may request signing and issuance without waiting for
the owner. Routine software signing is the main path. Each purpose has its own
key, fixed context policy, consumer pin, audit trail and revocation boundary.
Creating a new agent-purpose key is unattended and audited, but does not enroll
that key at a consumer. The first implementation milestone is the **agent** tier.

Public releases, chip and boot roots, and trust-anchor changes retain an
owner-word boundary. A later **release** tier adds a separate owner-action proof
from the owner's phone, verified by the consumer alongside the artifact
signature. It does not hold up ordinary agent signing. ADR 0005 remains the
shared owner-action design; its carried-key implementation and physical gates
are open. This ADR does not make that authority available.

ADR 0008's guest is a different principal. A guest is never a member and can
never use the member signing or issuing service, even through a sponsored
tunnel. Guest credentials may be issued only by ADR 0008's separately scoped
guest-issuer role and sponsor policy. This ADR does not implement that role.

## Threat model and trust boundary

Assume an agent process on one member is compromised, and assume a member's
device key may be copied where its platform stores the key in a file. A live
authenticated member can request signatures for every purpose whose policy
admits it until that member is revoked at the signer. Neither a signature nor
membership says which process on that computer requested it or that the owner
approved it. Consumers must treat an agent-tier signature as evidence that a
permitted member process had access, not as owner intent.

The existing vault's Ed25519 seed is encrypted under an agreement key held by
the local key provider. A process with the owner's user privileges may be able
to invoke that provider or an older binary. A check made only inside `supgang
sign` is therefore not a hard boundary against that process. Sealed policy
prevents accidental or unauthorized document edits within the supported vault
path; it does not make a same-user host a trusted execution environment.

An append-only, hash-chained, synced file detects interrupted writes and
cooperating-writer tampering. A same-user attacker who can restore the vault,
audit and count ledger together can roll them all back. Local rate and count
caps are operational limits, not a security claim against that attacker.
Where a hard cap or durable non-equivocation is required, the signer must
obtain an independent monotonic witness before releasing a signature, or refuse
while that witness is unavailable. The agent tier may operate without that
witness only for purposes whose consumers accept this residual risk.

Current root-certified transport authenticates a computer, not its local
process. Linux members with file-held device keys have a weaker custody claim
than members with hardware-held keys. Use hardware-backed device keys where
the platform supports them, and expose custody as verified local evidence,
never as a peer's self-claim. The member identity and its issuance authority
must remain independent of the selected QUIC implementation.

## Purpose key and consumer policy

Each agent signing key has one canonical purpose identifier, a closed list of
1 to 16 exact contexts, and a bounded member allowlist. The default allowlist
is all current, unrevoked members. A narrower list names exact certified
device identities, not computer names, tags or addresses. Policy is fixed at
key creation and authenticated with the entry as vault associated data. An
entry with no policy is not eligible for the new agent service. Unknown policy
versions, duplicate or unsorted members or contexts, oversized fields and
unsupported key kinds fail closed. A changed policy requires a fresh key and
consumer pin update; it cannot be edited in place.

Consumers pin the purpose, key fingerprint and exact context together. They
refuse a signature under another key or context even if both are valid in the
same hive. A newly created key is not trusted merely because it is listed in
the vault, signed by a member, or advertised by Supgang. An agent-tier
consumer may install or rotate an agent-purpose pin on an authenticated member
request or under its own agent policy, with a durable audit record. This is
not a release trust-anchor change and does not wait for the owner. Public
release, chip and boot roots, the launcher anchor, and the phone approval key
remain owner-word changes. Suspected compromise rotates only the affected
purpose key and its pins. Old fingerprints are explicitly revoked, and any
planned old/new overlap is bounded to at most 24 hours. Consumers fail closed
on ambiguous or expired overlap and preserve their own rollback protection.
Rotation and revocation must not invalidate unrelated purpose keys.

The existing `solis.placement.stage` key is a candidate for one agent-purpose
policy. It needs an exact fingerprint and public-key check against the current
vault before migration. The existing launcher key remains single-proof for now.
Moving it to a release-tier two-proof format is a later rotation with Agenxy
Labs and its consumers. A software update must never silently promote a legacy
unscoped key into either policy. Existing unscoped keys remain readable for
inventory, but new-policy signing refuses them until an explicit migration or
rotation with a reviewed consumer pin plan. Existing key bytes are never
exported as part of migration.

## Authenticated remote request

The service accepts only a new, typed stream on an existing authenticated
hive member channel. It opens no new public listener and performs no new
public connection in strict mode. It refuses guests, unauthenticated streams,
and local control-socket callers that try to self-claim a remote member.

For **every** sign or issue request, the signer takes the peer's live
root-certified transport identity from the authenticated session. It checks
the current authority manifest, certificate scope and expiry, membership and
revocation before policy lookup and again immediately before the effect. It
does not turn a successful handshake into a cached grant. A stale manifest,
unreliable clock, unknown revocation state, session replacement or revoked
member refuses the request. Revocation on the signer's current authoritative
state stops new requests and cancels queued and in-flight work. Across a
partition, the signer cannot know a remote revocation instantaneously; it
must require bounded-fresh root status or fail closed after its freshness
window. Receipt of a record over a live session does not renew that window.

Each bounded request carries a unique nonce, exact purpose, context, digest or
canonical issuer input, an expiry no more than five minutes ahead, and a
request authentication tag derived from the
authenticated session's exporter. The tag binds protocol version, hive,
certified requester identity, signer identity, session, stream and exact
request bytes. Replays, cross-session copies and malformed canonical encodings
fail before any durable effect. This reuses the existing transport certificate
authority and channel exporter; it creates no second membership scheme.
Responses bind the request nonce and identity, so a peer cannot substitute a
different result. The signer durably spends each nonce before the effect in a
bounded replay set. Version 1 admits at most 4,096 live nonces globally and
256 per member; entries remain through request expiry plus a two-minute clock
skew bound. A full, unreadable, rolled-back or equivocal set refuses new
requests rather than evicting unexpired entries. Request bytes and tags stay
on the encrypted stream, never in argv, URLs or ordinary logs.

Per-member and global request rates, queues, in-flight work, payload sizes,
response sizes, retries and wall-clock timeouts have explicit ceilings. A
per-member queue cannot consume the member-control or revocation lanes.
Cancellation and session loss release capacity. A queued request is
re-authorized when selected; no queued work survives a revocation or stale
authority view. An expired or ambiguous request returns no signature.

## Agent signing and audit

The signer checks the sealed policy and member allowlist, reserves a bounded
per-purpose count under the vault lock, and writes one canonical audit record
before returning a signature. The record binds a sequence, previous-record
hash, requesting certified device identity, purpose, context, message digest,
key fingerprint, decision, and time. The digest is public request metadata,
but is emitted only to the owner-only audit file, never ordinary logs. No
secret, peer address, request body or raw bearer credential is recorded.
The writer appends and fsyncs the file and its durable head before releasing
the signature. A failed append, sync, head check or bounded rotation refuses
release. A crash after reservation may consume a count without returning a
signature. A crash after signing but before the response may yield a retry;
the same nonce never signs twice, and callers must compare the signed result
against their own release ledger.

The log is bounded through linked segments with a durable predecessor hash
and a retained owner-review checkpoint; truncation is reported, not hidden by
the current vault log's keep-newest-half behavior. The owner can review
purpose, requester, context and digest after the fact. This is an audit trail,
not proof that a same-user attacker could not delete every local copy. Rate
and count caps throttle normal automation and accidental loops. Consumers do
not infer owner approval from those caps or the audit record.
Version 1 permits at most 64 reservations per member and purpose per rolling
hour and 256 per purpose across the hive per rolling hour. A crash after
reservation consumes the count. Agent-policy local signing reserves a fresh
nonce under the same cap.

Authenticated policy refusals are recorded with a `denied` decision before
returning the refusal. An unknown purpose is marked with an `unknown` key
fingerprint, never a claimed key identity. Denials do not reserve the request
nonce. At most 64 denials per member and 256 per hive are recorded per rolling
hour; further requests still refuse, including when the denial audit is full.
Malformed or unauthenticated traffic does not write this durable audit.

The local `supgang sign` path uses the signer's own current certified device
identity as requester. It follows the same sealed purpose/context policy,
nonce ledger, caps and audit path as a remote member. An unscoped legacy key
cannot be reached through a second, less restricted local signing route after
its explicit migration. A non-authority computer receives a specific refusal
directing it to request signing from the root-authority computer. Local callers
do not gain an all-purpose exception.

## Issuance and provision

The same authenticated member request boundary applies to issuance. A purpose
policy names which member identities may request each issuer key and the
closed certificate profile, subject form, validity ceiling and count ceiling.
New subjects prove possession of their own private key. The issuer signs
only a canonical, bounded request under its profile; it does not accept
arbitrary certificate fields from a peer. Short-lived certificates are the
default. The signed certificate, public key and chain may be returned to a
member after the same audit and revocation checks.

Supgang may issue its own service or SSH certificates only where consumers
explicitly trust that issuer and enforce its scope. Supgang cannot mint an
[Apple Developer ID certificate][apple-id].
Apple issues that certificate; Supgang may
use a separately provisioned Developer ID signing identity on macOS to sign
a fixed artifact purpose. The adapter must pin the identity, accepted artifact
type, signing flags and verification policy, stage an exact immutable input,
audit requester and artifact digest, invoke the platform code-signing facility,
then verify the result before release. It returns public certificate material
and the signed artifact, never the private key. No Apple account credential or
private key crosses the hive. The existing `make install` signing option is
local installation machinery, not remote code-signing authorization.

Bearer secrets require a separate named grant for the exact member, purpose,
secret and expiry. The server encrypts the result to a device encryption key
certified and possession-proven under that exact member identity, on top of
the authenticated transport, and never returns it to an
all-member default. A guest never receives it through this service. Grant
issuance, revocation, replay protection, recipient binding and secure local
delivery must be implemented and tested before this route is enabled.
Non-exportable signing keys are never provided as bytes; a permitted member
receives only a signature or public material.

## Later release tier and phone bootstrap

For the few owner-word actions, the consumer requires both the purpose key's
artifact signature and an independent owner-action assertion over the exact
artifact or operation digest, purpose, key fingerprint, context, target,
single-use nonce and short expiry. Supgang checks it before signing, but the
consumer must verify both proofs. An old binary or same-user process must not
be able to turn a single vault signature into a release acceptance.

The phone generates and retains its owner-action private key. Enrolling its
public key is the one irreducible trust bootstrap: the owner compares the
phone's fingerprint directly with each consumer's displayed candidate pin
and locally confirms the pin through that consumer's protected setup path.
Neither an agent, a hive message nor a vault signature may install the phone
pin. A lost phone is revoked or replaced through the independently held
recovery key and the consumer's local recovery procedure, never through the
vault. ADR 0005's grant, fresh status, device enrollment, durable nonce and
physical presence gates still apply. Notification or Dibs delivery may carry
an approval request but is never authority. Clock doubt or replay refuses.

## Remote key creation and migration

Agent-purpose key creation is governed by a separate hive-level creation
policy, because the proposed key does not yet have a per-key allowlist. The
default admits any current, unrevoked member. A configured list may narrow
the creators. Its operational ceilings are eight new agent keys per member
and 32 across the hive in any rolling 24 hours, plus the vault's existing
128-entry bound. A purpose uses the existing vault name grammar:
`[a-z0-9][a-z0-9._-]{0,63}`. An exact active purpose collision refuses;
rotation is the only exception and may hold at most one old and one new
fingerprint for the bounded overlap. Version 1 requires the creating member
to appear in the new key's allowlist; it cannot create a key that excludes
itself. The count ledger has the same same-user rollback limitation as signing
caps, so consumers must rely on explicit pins rather than those counts for
authorization.

A permitted member may request creation without a target TTY. It generates a
fresh key in the target vault,
seals the exact immutable policy, audits the requesting certified identity,
and reports the public key and fingerprint. Creation does not update any
consumer pin or grant more authority than existing member policy. Exact name
collisions, excess keys, partial writes and audit failures refuse or leave a
non-signing pending entry for explicit recovery. No private key leaves.

Release-purpose key creation is later: create a bounded pending candidate and
show its public fingerprint and fixed policy on the phone. The phone approves
the candidate fingerprint, policy digest, request nonce and expiry. The target
checks the assertion and consumes it durably before making the key usable.
The consumer still requires two proofs. Migration of old keys cannot create
this assurance; rotate to a new key and update pins through the protected
trust-anchor procedure instead.

## Delivery and acceptance gates

1. Ship agent-purpose policy and fail-closed legacy handling with canonical
   codec, AAD, adversarial tests and installed artifact checks.
2. Ship durable per-purpose audit and operational caps. Prove write, sync,
   crash, truncation, replay and rollback behavior; label the same-user limit.
3. Ship the member-only remote stream with exact certified identity, exporter
   binding, per-request authority checks, bounded resource use and real
   cross-host revocation tests. Refuse stale manifest and partitioned status.
4. Ship only the issuer profiles actually implemented. Verify certificate
   possession, scope, lifetime and recipient binding; test Apple code signing
   with a provisioned test identity separately from certificate issuance.
5. Install the same artifact on the owner's laptop and Solis, the configured
   physical acceptance peers, for the new runtime path. Demonstrate remote
   signing, denial after revocation and audit evidence across both hosts.
   Source tests, simulation and a local listener are not that proof.
6. Later, after ADR 0005's phone enrollment and recovery gates, ship the
   consumer-verified two-proof release format and rotate the launcher key with
   Agenxy Labs. Public release still needs the owner's direct word.

[apple-id]: https://developer.apple.com/help/account/certificates/create-developer-id-certificates
