# ADR 0004: The threshold root protocol

Status: proposed (fifth draft; after astra's seventh review of the prototype and package 5's corrections)

Date: 2026-09-20

## Decision

The hive root of ADR 0003 ("Root authority: no single point of failure") is a
FROST signing group (RFC 9591, the Ed25519 suite, `frost-ed25519` 3.0.0 pinned
with `frost-core`), and this ADR is its protocol: how shares come to exist
without a dealer, how a root operation is agreed before it is signed, how a
signing session runs, how devices join and leave the group, what each custody
mode of a share actually protects, how recovery outranks a compromised root,
and the vectors the implementation must refuse. Nothing here changes what a
verifier sees: every root signature is an ordinary Ed25519 signature under
the root public key.

## Founding: shares without a dealer

`supgang root found --devices <n> --threshold <k>` runs a distributed key
generation (FROST's DKG as specified in the `frost-core` `keys::dkg` module:
each participant contributes a random polynomial, commitments are exchanged
in round 1, shares in round 2, and each participant verifies every share it
receives against the commitments) among the founding devices over the
**founding channel**: the devices in one place, paired pairwise by the same
owner-held-medium ceremony Compass uses for a browser (a QR code or a USB
key carrying the peer's device public key and a 256-bit capability; the
owner compares six words on both screens). No device ever holds the whole
root secret, not at founding, not after. The result on each device is one
share, the group public key (the root), and every participant's verifying
share. The **founding digest**, the chain's first predecessor, is SHA-256 over
the complete group descriptor (hive label, every participant's device key,
(k, n), every verifying share, the root public key) *and* the recovery
group's descriptor (below), which is fixed at founding too; every founder
confirms the same digest on screen before the first step, so the chain is
bound to one agreed transcript, not to a library call. The founding devices
are the first members, and the first root operation issues their memberships.
Founding refuses `n < k + 1` unless `--accept-single-loss-failure` is given,
and `doctor` says so thereafter. Supported parameters: `2 <= k <= n <= 16`.
The pinned FROST 3.0.0 implementation does not support `k = 1`: it refuses
`min_signers < 2`. This is an implementation limit, not a claim that threshold
one is mathematically impossible. A hive with one device is administered by
the file-held root of today, which is not this protocol, and `doctor` says so.
Three devices (2-of-3) is the minimum meeting single-loss tolerance; 2-of-2
is supported only as an explicitly accepted failure of that tolerance.

## Root state: agreement before signature

A FROST signature proves that a quorum signed a message; it does not decide
which of two messages was the one. So every root operation is a step in a
**root-state chain**, and a signing session signs a step, never a bare
message:

```
RootStep/v1 (canonical CBOR, domain supgang/root-step/v1\0):
  hive            HiveId
  predecessor     32 bytes: SHA-256 of the previous RootStep, or the founding digest
  sequence        u64, predecessor.sequence + 1
  epoch           u64, the root epoch this step is under
  recovery_gen    u64, the recovery generation in force
  operation       one of: issue-membership, revoke, trust-anchor, allocate-name,
                  issue-leaf, succession, admit-roster, set-ca-holders
                  (no reshare: group changes are DKG plus succession; no
                  standalone set-recovery-group: the recovery descriptor
                  changes only inside a recovery succession; an unknown
                  tag fails to decode)
  payload         the operation's canonical bytes
  proposed_at     seconds
  proposer        NodeId
```

The root signature covers the domain and the whole canonical step; what a
signer commits to is the step's content digest, and the signing package it
later receives must carry a message byte-equal to the step it committed to
(the package's own digest binds the session id and the commitment set, and
is a separate check). A member holds the digest of the
last step it accepted and accepts a step only if its `predecessor` is that
digest and its `sequence` is next; a step whose predecessor it has not seen
is held until the chain arrives, as revocation snapshots are today.

**The property, stated exactly.** This chain gives *fork detection and a
halt*, not fork prevention, and the ADR's first draft claimed more. Two
valid steps with the same predecessor and different content are a **fork**.
Whether a fork requires a faulty signer depends on the quorums: with k of n
signing and 2k > n, any two signing quorums share a member, so a fork means
some member released signature shares on two steps with one predecessor,
which the permanent-lock rule below makes a faulty act; with 2k <= n (a
permitted 2-of-4, say) two honest, disjoint quorums can each sign a
different step in good faith, and a fork is not evidence of fault at all.
Supgang states which regime a group is in (`doctor`: "quorums intersect" or
"quorums may be disjoint") and does not pretend the second is the first. In
either regime the behaviour on a fork is the same: the member records both
branches, stops accepting root steps, and reports. There is no `resolve` or
`abort` step under the ordinary root: a quorum that could sign one could be
the faulty quorum, and honest signers locked on different proposals could
never assemble it (the first draft's circularity). The way out of a fork is
a **recovery succession** (below): the recovery group, pinned at founding and
independent of the chain, names the branch that stands, or none, and every
member follows it because its authority does not derive from the forked
chain. A fork is therefore an owner-in-person event by design. On a detected fork a
member also stops honouring, for admissions, enrolments and writes, any
certificate or allocation issued by either branch after the fork point;
reads continue; recovery restores authority prospectively and undoes nothing
done before the fork was discovered.

## A signing session

A session signs one step. Any shareholder may coordinate; the coordinator is
a role, not an authority.

1. **Propose.** The coordinator builds the step, records it durably as
   `proposed`, and sends it whole to every shareholder over the control
   channel (below).
2. **Review and commit (round 1).** Each participating shareholder shows the
   step to the owner (operation, payload in words, predecessor sequence),
   requires presence to proceed (Touch ID, PIN, touch; on a file-held share,
   the owner-only control channel), records `committed(step digest,
   session id)` durably, then generates its FROST nonces for *this session
   id*, records `nonces_issued(session id, commitment)` durably, and sends
   its commitment. **The lock on a predecessor is permanent once a signature
   share has left this device.** A shareholder that has committed to a step
   with predecessor P refuses to commit to any other step with predecessor P
   until: the first step is published (then P is no longer the tip); or, if
   it never released a signature share for it, its 10-minute deadline passes
   (the commitment alone proves nothing and the nonces are recorded
   `discarded`); or a recovery succession moves the chain past P. Once it
   *has* released a share, only the same step or a recovery can move it: a
   delayed publication can then never meet a second signature from the same
   signer, so with intersecting quorums (2k > n) a fork does imply a signer
   that broke this rule. The cost is stated: a step whose session died after
   shares were released leaves its signers locked on P until that step is
   published or a recovery runs; the CLI shows the lock and the step, and the
   session can be resumed (below) to finish it.
3. **Sign (round 2).** With k commitments, the coordinator sends the signing
   package (the domain plus the whole canonical step as the signed message,
   and the exact set of commitments). Each participant checks that the message
   is byte-equal to the domain plus the step it committed to and that its own
   commitment is among those listed. The package digest separately binds the
   session and commitments. The participant records
   `nonces_consumed(session id, package digest)` durably **before** computing
   its signature share, then returns the share. A participant asked to sign a
   package for a session whose nonces are `consumed` returns the cached share
   only if the package digest is byte-identical, and refuses otherwise; it
   never recomputes with used nonces. A resumed session (another coordinator)
   is a **new session id**: commitments and nonces are regenerated; the step
   and its lock are the same.
4. **Aggregate and publish.** The coordinator aggregates, verifies under the
   root public key, appends the step to the chain, and publishes it as
   revocation snapshots are published. Every participant verifies the
   published step against its own `committed` record.

Nonce secrets are never in a backup (they live in a separate file the backup
excludes, or in the sealed store), and a restored signer reconciles its
`committed`/`consumed` records with the chain before it may sign again.

## The control channel

Sessions, group changes and recoveries run over a channel whose
authentication is the shareholders' **device keys and share generation**, not
membership, so expired membership cannot make repair impossible. The proof is
a typed authority operation of the device key (added to ADR 0003's signing
inventory as `supgang/control-auth/v1`, so the helper can produce it): a
signature over {hive, group descriptor digest, share generation, this
device's node id, the peer's node id, the peer's fresh 32-byte challenge, the
TLS channel binding (exporter)}. It is replayable nowhere: another session
has another challenge, another generation another digest, another peer
another id. A shareholder admits a peer if the signature verifies under a
device key in the current group's verifying-share set. The channel carries
only session, group-change and recovery messages; admission to it confers no
application membership, and a device outside the group is refused whatever
it presents.

## Custody of a share, honestly

| Mode | What holds the share | What signing exposes | What presence enforces |
| --- | --- | --- | --- |
| `native` | hardware that runs the FROST arithmetic | nothing leaves the hardware | the hardware's own policy |
| `sealed` | the share encrypted to a hardware key (Secure Enclave, TPM) | the share is in process memory for the session, zeroised after | unsealing requires presence |
| `file` | an owner-only file | the share is in memory while the service runs | the owner-only control channel |

No `native` provider is assumed to exist; a provider capability matrix
(platform, API, whether it can run FROST rounds, whether it can enforce
presence) is a deliverable before any platform is described as `native`, and
the P-256 device provider of ADR 0003 signs ordinary keys and implements none
of this. `sealed` is what Apple platforms and TPMs get first. A share's
custody is recorded in the group descriptor and shown by `doctor`.

## Changing the group: a new root, bound by succession

The first version has no same-key reshare. Adding or removing a device, or
changing k, is: run a fresh DKG among the new group (as at founding, over the
control channel, with a new founding digest), then a `planned` succession
step of the *old* root naming the new root public key, the new group
descriptor digest (its every public output: roster, verifying shares, root
public key; the founding digest is over these public outputs, not the
private DKG transcript), and the retained set (ADR 0003), signed by a quorum
of the old group; members move to the new root exactly as for any planned
succession. The successor's first step names the succession step's digest as
predecessor, continues the sequence, and carries the new epoch; the `HiveId`
never changes. The DKG among the new group runs over the control channel
under a **pending roster**: an `admit-roster` step of the old root names the
candidate devices for exactly this DKG, and the control channel admits a
candidate to that ceremony alone until the succession lands. What the
transition gives, stated relative to a verifier: one that has accepted the
succession cannot be moved by the old root's shares (the key changed); one
that has not can still be shown old-root branches by retired shares, which
is the stale-peer window every succession has and reconciliation closes; the
cost is that everything issued by the old root is either retained by digest
in the succession or reissued, which ADR 0003 already requires. Same-key refresh (FROST's
`keys::refresh`, whose construction for a *different* participant set and
threshold is a protocol in its own right, not a library call) is deferred to
a later ADR with its own review; until then `doctor` has no "reshare" and the
CLI verb is `supgang root regroup`. A device restored from a backup carries a
share of a retired root and no nonce state: it is refused from sessions and
re-enrols.

## The recovery group

A second FROST group, `(k_r, n_r)` over the shareholders plus offline shares
(a security key kept in a drawer, a file on media kept apart), whose
operations are a `recovery` succession and changes to *itself*. Its
descriptor is part of the founding digest: **pinned at founding, and never
changed by the ordinary root.** Changing the recovery group (its roster,
threshold or key) happens only inside a recovery succession, authorized by
the *existing* recovery group with the successor group's possession, never
by a root quorum and never as a standalone step; so a compromised root cannot
install a recovery group of its own.
Precedence is by the **recovery generation**, ordered before the root epoch:
a member orders state by `(recovery_gen, epoch, sequence)`, only a recovery
succession advances `recovery_gen`, and a step with a greater `recovery_gen`
supersedes any chain of planned steps whatever their epochs. A recovery
succession names as predecessor the last step the recovery group *saw*,
which need not be the tip of a compromised chain; members accept it
regardless of tip, since its authority is the recovery group's, and discard
every step after that predecessor; it resets authority as ADR 0003 requires
(every device re-enrols, every anchor and name is withdrawn). The recovery
descriptor has its own monotonic sequence and predecessor-descriptor digest,
independent of the ordinary chain, and changes to it happen *only inside a
recovery succession* (which carries the new descriptor and advances the
generation), so it is never a step that must follow a possibly forked tip; a
planned succession carries the recovery descriptor forward unchanged, by
digest, and one that does not is refused. Stale peers learn the current
descriptor from the latest recovery succession they hold, ordered by
generation. Two recovery successions at one generation with different
content are a fork of the recovery group itself: members halt and the owner
re-founds in person. The
owner chooses `(k_r, n_r)` so that no set of devices small enough to be
stolen together meets `k_r`, and no set small enough to be lost together
prevents it; the CLI asks which devices share a bag or a house, and states
whether the recovery quorums intersect.

## The CA: replicated, sealed, and a one-holder threshold

Trust-anchor and leaf issuance are steps (`trust-anchor`, `issue-leaf`), so a
quorum authorizes them. The CA *key* cannot be a FROST group: FROST produces
Schnorr signatures, and X.509 verifiers over P-256 accept only ECDSA. (ADR
0003's mention of a P-256 FROST CA is withdrawn; this section is the one
design.) So the CA key is a P-256 key held **sealed** by every shareholder of
the root group (the same bytes, encrypted to each device's hardware key, or
in an owner-only file where a device has none; the holder set is exactly the
root group's roster and is recorded in the trust-anchor manifest). A leaf is
issued by any one holder, after a quorum has signed the `issue-leaf` step
that names the exact certificate body (serial, subject, SANs, SPKI,
validity) and the CA identity; the holder signs only that body. Stated
prominently: **browser trust in this hive has a one-holder compromise
threshold, not the root's k-holder threshold.** A stolen shareholder device
whose sealed key is unsealed can issue a leaf for any name under the anchor's
constraint without any step, and browsers do not consult the ledger. That is
the honest trade for X.509 compatibility until a reviewed threshold-ECDSA
scheme is worth its complexity. Two compromises are distinguished: a *leaf*
key's, bounded by the leaf's 90 days; and the *CA* key's, which short leaves
do not bound at all (a thief issues leaves with any validity) and which ends
only when every relying party has stopped trusting the anchor, which is what
`trust-anchor` withdrawal and `compass trust compromised` are for. The name
constraint bounds what either can be used for. Consequences are
specified: distribution of the sealed key to a new holder is a
`set-ca-holders` step plus an encrypted transfer over the control channel;
removing a holder (a lost device) rotates the CA (`trust-anchor` with a new
key), and until every browser has the new anchor the old one is still
trusted by them, so the withdrawal manifest is published at once and old
leaves are not renewed; the CA key is in each holder's backup only as the
sealed blob, never in the clear.

## Two trades, decided

- **A retired root can halt its successor.** A verifier that accepted a
  planned succession keeps the old context so that it can still detect a fork
  of the old root retrospectively; the price is that a later thief of the
  retired quorum can sign a competing child of the old predecessor and halt
  the successor chain (it gains no authority under the new key; it costs the
  owner a recovery). Decided: keep retrospective detection. A halt is loud and
  the owner's to end; a silently accepted old-root fork would not be. The
  fixture that delivers an old-root branch to a receiver that has already
  accepted the succession asserts the halt.
- **A signing engine is not an authorization engine.** The session signs what
  the policy validator (package 5) admits: predecessor at the tip, operation
  known, succession payloads complete, root and recovery keys distinct after
  every succession. What the validator does not yet judge, and a service
  must before any real authority: membership issuance policy, name
  ownership, CA issuance policy, the retained set's validity, recovery-role
  restrictions. Those are the operations' application rules, and each is a
  test in the package that wires the operation.

## What the prototype covers, and does not

Founding, sessions, forks, regroup by DKG plus succession, the recovery group
and its generation lock, control-auth, and the policy validator, all with
file-custody test keys and no network: covered, 47 tests. `admit-roster` and
`set-ca-holders` are decoded and refused as unimplemented; the pending-roster
admission ceremony, encrypted CA-key transfer, sealed custody, any provider,
and every network path are not implemented, and nothing here claims they
are.

## Vectors the implementation refuses (tests, one each)

A lying shareholder (a bad round-2 share at founding; a bad signature share);
a replayed session (old commitments presented again); a substituted payload
(the signing package's message differs from the committed digest); a restored
share (retired generation, or reused nonce state) presented to a session; two
conflicting steps with one predecessor (a fork halts, in both quorum regimes,
with the 2-of-4 honest-disjoint and 2-of-3 one-faulty cases as fixtures); a
root quorum attempting `set-recovery-group` (refused); a planned succession
chain racing a recovery (the recovery wins by generation); a signing package
re-sent with a different commitment set (refused; the cached share returned
only for the byte-identical package); a control-channel proof replayed with
another challenge or generation (refused); the all-honest delayed-publication
case (A and B sign X on P, B is later asked to sign Y on P: refused by the
permanent lock; the fixture shows no fork results); a stale recovery
descriptor replayed (refused by its sequence); a candidate device on the
control channel outside a pending roster (refused); a step whose predecessor is unknown (held, not
rejected, then accepted when the chain arrives); founding with `n < k + 1`
refused without the flag; a session past 10 minutes abandoned with nonces
gone; a peer outside the group on the control channel refused whatever it
presents; a coordinator that vanishes mid-session (resumed elsewhere).

## Consequences

Until this ADR's tests pass, a hive is administered by the file-held root as
today, and `doctor` names it a single point of failure. The provider
capability matrix (platform, API, whether FROST rounds can run inside,
presence behaviour, memory lifetime, export and backup behaviour, failure
handling) is a deliverable before any platform is described as `sealed`, and
a test-key prototype of founding, one session and one regroup precedes any
real authority. ADR 0003's root
operations (membership, revocation, trust anchors, names, successions) are
steps of this chain from the first implementation, so that moving a hive
from a file-held root to a threshold root is a `planned` succession and
nothing downstream changes shape.

## Review

To be put to astra (security lens) on the same thread as ADR 0003, with the
provider capability matrix as a stated missing deliverable.
