# ADR 0004: The threshold root protocol

Status: proposed (first draft, after astra's fourth review of ADR 0003)

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
share; the founding devices are the first members, and the first root
operation issues their memberships. Founding refuses `n < k + 1` unless
`--accept-single-loss-failure` is given, and `doctor` says so thereafter.

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
                  issue-leaf, reshare, succession, set-recovery-group
  payload         the operation's canonical bytes
  proposed_at     seconds
  proposer        NodeId
```

The root signature covers the whole step. A member holds the digest of the
last step it accepted and accepts a step only if its `predecessor` is that
digest and its `sequence` is next; a step whose predecessor it has not seen
is held until the chain arrives, as revocation snapshots are today. Two
valid steps with the same predecessor and different content are **root
equivocation**: the member records both, stops accepting root operations,
and reports; the owner resolves it in person by a quorum signing a step whose
payload names which branch stands (`operation: resolve`, added to the set
above), and a member accepts the resolution only from a quorum that includes
at least one signer of each branch, so a lone faulty subset cannot resolve
its own equivocation. Administration halting on conflict is the chosen
behaviour: a hive is one owner's devices, and a halt that the owner ends by
hand is safer than an agreement protocol that decides for them.

## A signing session

A session signs one step. Any shareholder may coordinate; the coordinator is
a role, not an authority.

1. **Propose.** The coordinator builds the step, records it durably as
   `proposed`, and sends it whole to every shareholder over the control
   channel (below).
2. **Review and commit (round 1).** Each participating shareholder shows the
   step to the owner (operation, payload in words, predecessor sequence),
   requires presence to proceed (Touch ID, PIN, touch; on a file-held share,
   the owner-only control channel), records the step's digest durably as
   `committed`, then generates its FROST nonces and sends its commitment.
   A shareholder that has committed to a step with this predecessor refuses
   to commit to another with the same predecessor until the first is signed
   or abandoned by a quorum-signed `abort` (an `operation` too): this is what
   makes equivocation need a faulty signer, never an honest one who was
   shown two proposals.
3. **Sign (round 2).** With k commitments, the coordinator sends the signing
   package; each participant checks that the message is byte-equal to the
   digest it committed to (a coordinator cannot substitute the payload) and
   returns its signature share.
4. **Aggregate and publish.** The coordinator aggregates, verifies under the
   root public key, appends the step to the chain, and publishes it as
   revocation snapshots are published. Every participant verifies the
   published step against its own `committed` record.

Nonces are generated fresh per session from the OS CSPRNG and used once; a
participant that is asked to sign twice with the same commitment refuses; a
session that does not complete within 10 minutes is abandoned and its nonces
discarded. A session is resumable from another coordinator: the step is the
same, the commitments are re-collected.

## The control channel

Sessions, reshares and recoveries run over a channel whose authentication is
the shareholders' **device keys and share generation**, not membership: a
device presents its `transport-client` certificate or, when its membership
has expired or its authority is stale, its bare device key with a proof of
possession and its share generation id; a shareholder accepts a peer into a
session if that peer's device key is in the current group's verifying-share
set. So expired membership cannot make repair impossible, and a device that
is not in the group cannot take part whatever it presents.

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

## Reshare: adding and removing devices

`supgang root reshare --devices <n'> --threshold <k'>` is a root operation
(a step) whose payload is the new group descriptor, signed by a quorum of the
*current* group; the protocol is FROST's refresh (`keys::refresh`) run among
the new members, producing shares of the **same** root public key with a new
**share generation** id. What that gives and does not give, stated: a
retired share cannot join a session of the new generation (sessions check the
generation), but k retired shares that survive together can still produce a
valid signature under the unchanged public key, and a verifier cannot tell.
So a reshare assumes that fewer than k retired shares are ever exposed
together. After any period at 1-of-1, or on any suspicion that a quorum of
old shares exists, the owner rotates the root public key by a `planned`
succession (ADR 0003), which the CLI proposes whenever the group leaves
1-of-1. A device restored from a backup carries a share of a retired
generation and nonce state: it is refused from sessions and re-enrols.

## The recovery group

A second FROST group, `(k_r, n_r)` over the shareholders plus offline shares
(a security key kept in a drawer, a file on media kept apart), whose only
operation is a `recovery` succession. Its descriptor is set by a root step
(`set-recovery-group`) and is part of what a member pins. Precedence is by
the **recovery generation**: only a recovery succession advances it, a
planned succession never does, a member holds `(epoch, recovery_gen)` and a
step with a greater `recovery_gen` supersedes any chain of planned steps
whatever their epochs. A recovery succession's step names as predecessor the
last step the recovery group *saw*, which need not be the tip of a
compromised chain; members accept it regardless of tip, since its authority
is the recovery group's, not the chain's, and then discard every planned
step after that predecessor. The owner chooses `(k_r, n_r)` so that no set of
devices small enough to be stolen together meets `k_r`, and no set small
enough to be lost together prevents it; the CLI asks which devices share a
bag or a house.

## The CA is the root's

Trust-anchor and leaf issuance are steps (`trust-anchor`, `issue-leaf`), so a
quorum signs them and the CA's authority is the root's. The CA *key* cannot
be a FROST group: FROST produces Schnorr signatures, and X.509 verifiers over
P-256 accept only ECDSA. So the CA key is a P-256 key held **sealed** by
every shareholder (encrypted to each device's hardware key, the same bytes),
released for a leaf issuance only after a quorum has signed the `issue-leaf`
step, and re-generated by a quorum (`trust-anchor` with a new key) if any
holder is lost. Availability: issuance needs one shareholder with the sealed
key and a quorum-signed step; loss of any device does not lose the key.
Exposure: a compromised shareholder device exposes the CA key, which is why
the anchor is name-constrained and why `compass trust compromised` exists;
this is the honest trade until an X.509-compatible threshold ECDSA is worth
its complexity, and the ADR says so rather than hiding it.

## Vectors the implementation refuses (tests, one each)

A lying shareholder (a bad round-2 share at founding; a bad signature share);
a replayed session (old commitments presented again); a substituted payload
(the signing package's message differs from the committed digest); a restored
share (retired generation, or reused nonce state) presented to a session; two
conflicting steps with one predecessor (equivocation halts; a lone subset's
`resolve` refused); a planned succession chain racing a recovery (the
recovery wins by generation); a step whose predecessor is unknown (held, not
rejected, then accepted when the chain arrives); founding with `n < k + 1`
refused without the flag; a session past 10 minutes abandoned with nonces
gone; a peer outside the group on the control channel refused whatever it
presents; a coordinator that vanishes mid-session (resumed elsewhere).

## Consequences

Until this ADR's tests pass, a hive is administered by the file-held root as
today, and `doctor` names it a single point of failure. ADR 0003's root
operations (membership, revocation, trust anchors, names, successions) are
steps of this chain from the first implementation, so that moving a hive
from a file-held root to a threshold root is a `planned` succession and
nothing downstream changes shape.

## Review

To be put to astra (security lens) on the same thread as ADR 0003, with the
provider capability matrix as a stated missing deliverable.
