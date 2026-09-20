# ADR 0003: Hardware-held device keys and device-certified subordinate keys

Status: proposed (seventh draft, after astra's six security reviews)

Date: 2026-09-19

## Decision

Three additions to the identity model, each coherent with the key types Supgang
already keeps apart (root, device, transport; docs/security/threat-model.md,
"Assets and boundaries"):

1. **A device holds two keys, and may hold them in hardware the owner controls.**
   The *device key* (ECDSA P-256) is the device's identity: it is what the root
   certifies membership of, it derives `NodeId`, and it signs only *authority*:
   certificates for subordinate keys, revocations of them, and the publication
   key below. It lives in the Secure Enclave on Apple platforms or a TPM 2.0
   elsewhere, or a security key, generated inside and never leaving; the
   owner-only file provider remains the fallback with its `doctor` warning.
   Signing with the device key requires the owner's presence where the
   hardware can ask (Touch ID, PIN, touch). The *publication key* (P-256, may
   be file-held) signs endpoint records: addresses, candidates, capabilities,
   advertisements. It is a subordinate the device key certified under purpose
   `publish`, so a laptop that changes networks re-signs its record unattended,
   and nothing an unattended process can sign changes what the device is
   authorised to do. What a record claims about authority (services, keys) is
   bound to a device-signed *authority manifest* (below); publication cannot
   alter it.

2. **A device certifies subordinate keys by a canonical, versioned certificate.**
   `CertifiedKey/v1`, CBOR, canonical encoding, signature domain
   `supgang/certified-key/v1\0`, fields in this order and all present:
   - `hive`: the `HiveId`, so a certificate from one hive verifies in no other.
   - `issuer`: the device's `NodeId` and its *authority epoch* (a monotonic
     counter the device advances whenever it re-founds its authority: a new
     device key, or a wholesale revocation).
   - `id`: 16 random bytes, the certificate's identity; never reused.
   - `subject`: the key: algorithm (`p256` | `ed25519`), public key bytes,
     and `custody`: `hardware` | `file` | `synced`, self-reported and labelled
     so (a device cannot prove where another key lives; the label says what
     the owner enrolled it as, and `doctor` says the same).
   - `purpose`: exactly one of `publish`, `service`, `transport-client`,
     `transport-server`, `attest`. A purpose a verifier does not implement
     is refused, never accepted as harmless. The sovereign-trust roadmap
     (docs/architecture/roadmap-sovereign-trust.md) names further *roles*
     (code signing, releases, SSH); each is an authorization of its own, by
     the root, naming who may sign what, and not a purpose a device may
     certify for itself. Not `sync`: custody is an attribute above, not a
     purpose.
   - `audience`: what the key may speak for, a schema per purpose, and an
     unknown or incompatible combination is rejected: for `service`, the
     service name and the consumer's *instance id* (a 16-byte id the
     consumer, Compass for one, generates once and states, so
     `service:compass` on this device is this Compass and not another); for
     `transport-server`, the service name, the instance id and the exact
     hostname it may serve, so a leaf is issued only to a key certified for
     that name; for `transport-client`, the peer hive (always this one) and
     optionally one `NodeId`; for `attest`, the consumer's instance id; for
     `publish`, nothing.
   - `operations`: a bounded set of strings the consumer defines and the
     owner sees at certification (`sign-enrollment`, `serve-tls`, `dial`).
   - `not_before`, `not_after`: seconds; validity at most 366 days.
   - `policy`: the version of the signer policy (below) in force.
   - `possession`: the subject key's signature, in its own algorithm, over
     domain `supgang/certified-key-possession/v1\0` and the canonical bytes
     of the fields above this one (`hive` through `policy`): the key proved
     it was there at certification, bound to exactly this certificate. A
     certificate authenticates a key only together with a fresh proof of
     possession in the protocol that uses it (the TLS handshake for
     `transport-*`, the DPoP proof, the transcript signature for `attest`):
     the certificate says the device vouched for the key; the protocol says
     the key is present now. Both are mandatory.
   A certificate carries no signature of its own: it is an authenticated
   statement *inside* the device-signed authority manifest (below), and a
   proof that presents a certificate presents the manifest, or its digest
   with the manifest fetched from the record. One construction, one
   signature, one typed operation that produces it. Depth is one: a
   certified key certifies nothing. At most 16 live certificates per device;
   consumers reject a manifest carrying more.

3. **Revocation of certified keys is a complete set inside the manifest,** as
   the root's revocation of devices is: `CertifiedKeyRevocations/v1`, the
   sorted set of revoked certificate ids, monotonic across manifest revisions
   (a newer manifest may not remove an id; a revoked id is never certified
   again).
   The set rides in the endpoint record's authority manifest and is reconciled
   as records are; a consumer keeps the greatest sequence seen. Omission from a
   record is *not* revocation: a certificate is live until its `not_after`, or
   its id is in the set, or its issuer's epoch has advanced past the
   certificate's (a re-founded device revokes everything it had certified).
   A consumer states a **maximum status age**: how old the newest authority
   manifest it has seen may be before it stops honouring that device's
   certificates for actions that matter (Compass: 24 hours for `attest`, 7
   days for `transport-*`; reads may continue, writes and enrollment stop).
   Clocks: a certificate is checked against the consumer's clock; a consumer
   whose clock moves backwards past the newest manifest it has seen refuses
   until it moves forward again.

The **authority manifest** is a device-signed section of the endpoint record:
`{epoch, revision, issued_at, next_update, certificates: [CertifiedKey],
revocations: CertifiedKeyRevocations, services: [ServiceAdvert]}`, signed by
the device key over its own domain (`supgang/authority/v1\0`) and carried
opaque inside the record the publication key signs. `revision` is monotonic
within an epoch; `issued_at` and `next_update` are the device's statement of
when it signed and by when it will sign again (at most 7 days later). A
consumer persists, per device, the greatest `(epoch, revision)` seen, rejects
a manifest that is older, and treats two manifests with equal `(epoch,
revision)` and different content as equivocation: it keeps neither for
authority and says so. **Freshness is computed from `issued_at`, never from
when a record arrived**: a manifest past its `next_update` is stale, and
stale means the consumer's maximum status age counts from `issued_at`. So a
replayed or unattended republished record cannot make old authority look
new. Renewing freshness is signing a new manifest, and that needs the device
key: the owner's presence on a hardware-held key. That is a deliberate cost:
a touch a week on any device, since every device publishes through a
certified publication key and so carries a manifest. Renewal requirements by
purpose and by operation, not by key: a device whose manifest is stale may
still have its *addresses* used as a bounded hint to reach it (the
publication certificate checked against the manifest that certified it, until
its own `not_after`), never overriding a known revocation, a newer authority
epoch or a root denial, and never authenticating a network session: session
authentication requires a publication certificate whose manifest is within
the consumer's maximum status age; `attest` (24 hours, so a device that
endorses enrolments renews daily, not weekly), `service` and `transport-*`
keys are not honoured for new admissions, enrolments or writes once the age
has passed. Epoch watermarks persist after old revocation sets are discarded. The revocation set is
bounded: at most 64 ids and 4 KiB encoded; when either would be exceeded the
device advances its authority epoch (an owner-approved operation that
revokes everything certified before it) and starts an empty set, and
consumers retain the last set of the previous epoch for one further maximum
status age. A separate status issuer is *not* part of
this ADR: re-signing changes device-signed content, and a lease that could
extend freshness would need its own delegation, ceiling and sequence; if it
is ever wanted it is a later ADR, and until then a device that cannot renew
is stale, which is the truthful state. **Acceptance of a certificate** is the
intersection of: the manifest not past `next_update`; `issued_at` plus the
consumer's maximum status age for the purpose not passed; the certificate's
own `not_before`/`not_after`; the issuer's membership valid and not revoked
under the newest root set the consumer holds, itself within its maximum age;
and the certificate id absent from the revocation set. A manifest whose
`issued_at` is in the consumer's future by more than 5 minutes is refused.
ADR 0002 advertisements move into the
manifest: a service pin is authority, not an address. A record whose
manifest signature fails is rejected whole. A consumer that once saw a
certificate for a service never falls back to a bare pin for it. The same
freshness rule applies upward: a consumer applies its maximum status age to
the newest root revocation set it has seen, by that set's issuance time.

## Why

The owner stated the invariant on 2026-09-19: no Agenxy tool takes a critical
dependency on public or commercial infrastructure or an external actor.
Hardware the owner holds is theirs and belongs in the core; platform
conveniences such as synced credentials are supported for polish, on top of a
path that works without them. The owner also said: when a sibling tool has a
gap in its own domain, extend the sibling if coherent. The threat model already
names the gap: "the owner-only file provider is weaker than Keychain, Secret
Service, or hardware keys."

Compass is the consumer that forced the question (Compass,
docs/design/authentication.md). Its browsers on other devices need a secure
context whose trust root is the gang's; its passkey enrollment wants
provenance from a device the gang already knows; its hop between machines
wants a purpose-bound key certified by the device rather than the device key
in a certificate. Facts about a device's keys are Supgang's to state, signed.

Astra's review of the first draft (2026-09-19) set the shape of this one: a
purpose label is not an authorization policy (hence hive, issuer epoch, id,
audience, operations, possession); omission is not revocation (hence the
signed set, epochs and a maximum status age); presence-to-certify holds only
if publication cannot change authority (hence two keys and the manifest); a
provider label is self-reported (hence `custody` labelled as such); a browser
CA is a separate authorization act (below); root recovery cannot stay later
(below).

## The browser trust anchor

A browser-trusted root is authority over names, wider than any one service,
and no device key confers it. It is issued by the hive root, once per hive:

- **CA material** is generated separately (P-256; held as ADR 0004 states,
  sealed by every shareholder), never derived from any hive identifier or
  device key.
- **A trust-anchor manifest**, root-signed (`supgang/trust-anchor/v1\0`):
  the CA's SPKI, its X.509 certificate, an epoch, and validity. The
  certificate: `basicConstraints` critical `CA:TRUE, pathLen:0`; `keyUsage`
  critical `keyCertSign` only; `nameConstraints` critical with
  `permittedSubtrees`: `dNSName` `<hive-label>.gang` (the RFC 5280 subtree:
  the label itself and every name under it; the leading-dot form is not
  used, and the apex is permitted deliberately so `<hive>.gang` may carry a
  member directory); `excludedSubtrees`: `iPAddress` `0.0.0.0/0` and `::/0`
  (every IPv4 and IPv6 address, excluded outright; a "permitted subtree that
  matches nothing" is not a thing, and 0.0.0.0/32 would permit 0.0.0.0),
  `rfc822Name` and `uniformResourceIdentifier` are not constrained by this
  profile because leaves never carry them and RFC 5280 gives no interoperable
  way to exclude a whole name form; the harness below checks that a leaf
  carrying one is refused by each platform, and a platform that accepts it is
  recorded as not confining that form. Leaves carry `dNSName` SANs only, and
  the standalone instance anchor (Compass) uses the same profile with a
  single hostname permitted, which as a DNS subtree also permits names under
  it; exact-host confinement is a claim only where the harness shows the
  platform refuses a child name, and otherwise the anchor is described as
  confined to the subtree. Whether a
  platform *enforces* name constraints on a user-installed anchor is not
  assumed: `supgang trust verify` builds a throwaway anchor of this exact
  profile in an isolated store (a temporary keychain on macOS, a temporary
  NSS database on Linux, a disposable profile in a browser) and checks, with
  a positive control, that a leaf for an allowed name is accepted and that
  leaves for a forbidden DNS name, an IPv4 SAN, an IPv6 SAN, a mixed SAN set
  (allowed name plus forbidden) and a subordinate CA are each refused for the
  trust purpose actually in use (server authentication, the purpose the
  anchor is installed for; other purposes are not claimed and not inferred),
  and that a leaf carrying an allowed DNS name plus an unused email SAN is
  accepted (an irrelevant SAN is not the property). The harness is
  parameterised by the claimed profile: for the hive **subtree** profile a
  child of the permitted name must be *accepted* (children are the service
  names the hive exists to name) and a name outside the subtree refused; for
  Compass's **exact-host** profile a child must be refused, and since X.509
  DNS constraints are subtrees, exact-host is claimed only where the harness
  shows the platform enforces it by some construction the ADR of that
  profile states; otherwise Compass describes its anchor as a subtree of its
  hostname. The result is recorded per platform and
  browser, and an anchor is installed in the real store only where every
  refusal held. Members install the anchor
  into platform trust only when the manifest verifies under the root they
  already trust, and remove it when a newer manifest supersedes or a
  root-signed withdrawal arrives, completing removal before the new one is
  trusted; `supgang trust install|remove|status|verify` are the verbs, owner
  presence required for install.
- **Leaves** are issued by an `issue-leaf` root step (ADR 0004; a quorum
  authorizes the exact certificate body, a CA holder signs it) for a name
  under the suffix to a device-certified `transport-server` key: the leaf's
  SPKI is the certified key, validity at most 90 days, `serverAuth` only. A
  consumer serving TLS (Compass's `compassd`) presents that leaf; Remap's
  gateway may keep pinning as today, browsers verify the chain.
- Names are allocated by the root (`supgang trust name <label> --device
  <node> --instance <id>`, a root operation), one per service instance,
  recorded root-signed as `{hostname, instance id, device NodeId, epoch}` so
  two instances never collide and a leaf for the name is issued only to a
  `transport-server` key that device certified for that instance and
  hostname; moving the name to another device is a new allocation that
  supersedes the old;
  each instance's exact hostname (`compass.<hive>.gang`, or
  `compass-2.<hive>.gang`) is Remap's to resolve, and the RP ID for WebAuthn
  is that exact hostname. A consumer that had a standalone hostname before
  the hive keeps it: the root may allocate that exact name under the gang
  suffix only if it already ends in the suffix, and otherwise the consumer's
  name stays what it was and the hive issues a leaf for it through a second,
  instance-specific anchor rather than renaming; renaming is a destructive
  migration the owner runs on purpose.

## Root authority: no single point of failure

The owner's requirement (2026-09-19): a gang adds and drops computers; some
will have no hardware key store; losing a laptop must not lose the ability to
administer the gang from another; there is no central point of failure; and
the result is provably secure. A founder-held root with a founder-held
recovery key fails that requirement. So the root is not a key held anywhere;
it is a **threshold** the owner's devices hold shares of. What a threshold
gives, stated exactly, because the first draft of this section claimed more:

- **Two bounds, not one.** A k-of-n group is *safe* while fewer than k shares
  are compromised, and *available* while at least k shares can take part.
  It therefore tolerates at most n − k unavailable devices: 2-of-2 fails on
  one lost laptop and does not meet the requirement; 2-of-3 is the least
  configuration that does. Supgang refuses to found or reshare a root with
  n < k + 1 unless the owner passes `--accept-single-loss-failure`, and
  `doctor` names such a hive as failing the requirement. A device that
  withholds participation counts against availability like a lost one. The
  root group and the recovery group each state their own (k, n), and the
  devices likely to be lost together (one bag, one house) or stolen together
  are the owner's to spread the shares across; the CLI asks.
- **Where a share lives, honestly.** FROST needs arithmetic on the share and
  on fresh nonces at signing time; a Secure Enclave, TPM or security key that
  signs with an ordinary key does not do that arithmetic. Three custody modes
  are distinguished and labelled: *native* (hardware that can run the
  threshold operation itself; none is assumed to exist until a provider
  proves it), *sealed* (the share is encrypted to a hardware key and released
  into process memory only for a signing session, with the owner's presence to
  unseal; the share is in RAM while signing), and *file* (owner-only file, in
  memory when the service runs). `custody` on a share says which. A provider
  capability matrix and a working prototype with test keys precede any claim
  that a platform offers `sealed`; nothing here says the P-256 device provider
  (which signs ordinary keys) implements FROST.
- **Ciphersuite.** FROST (RFC 9591) is specified for Ed25519, ristretto255,
  Ed448, P-256 and secp256k1. The root uses the Ed25519 suite so that verifiers
  see an ordinary Ed25519 signature and records do not change shape; the
  choice is a suite, not a limitation of FROST.
- **Reshare does not kill an old quorum.** A reshare produces new shares over
  the *same* public key; a retired share cannot join a current session, but k
  retired shares that survive together can still sign, and a verifier cannot
  tell. So reshare is for adding and removing devices under the assumption
  that fewer than k retired shares are ever exposed together; after a period
  as 1-of-1 (one device held the whole secret), or on any suspicion that a
  quorum of old shares exists, the root *public key* rotates by a `planned`
  succession. Every share carries a generation id; sessions refuse shares of
  another generation; a restored backup that resurrects a retired share, or
  a nonce state, is refused and the device re-enrols.
- **A signature is not agreement.** FROST produces a signature; it does not
  decide which of two conflicting root operations happened. Two 2-of-3
  subsets sharing one member can each sign incompatible states. ADR 0004
  therefore defines a *root-state protocol* apart from signing: every root
  operation names the predecessor root-state digest and a sequence, carries
  the exact payload digest, and is durably recorded by each participant
  before it signs; a member accepts a root operation only if its predecessor
  is the member's current state; two operations with the same predecessor
  and different content are root equivocation, on which administration halts
  until the owner resolves it in person with a quorum. Any eligible
  shareholder may coordinate a session; the coordinator can neither
  substitute the payload (each signer signs the digest it was shown and
  recorded) nor become a dependency (a session is abortable and resumable
  from another coordinator).
- **Bootstrap and recovery cannot depend on what they repair.** Founding runs
  over an owner-authenticated channel (the devices in one room, pairing by
  the same owner-held-medium ceremony Compass uses) before any membership
  exists; the first root operation issues the founding memberships to the
  shareholders themselves. Gathering a quorum to renew stale root status, or
  to recover, uses a bounded *control channel* whose authentication is the
  shareholders' own device keys and share generation, not their membership
  validity, so expired membership cannot make repair impossible.
- **The CA is the root's, not the founder's.** Trust-anchor issuance and
  leaf issuance are root operations like any other (a quorum signs). The CA
  key itself is held sealed by every shareholder and has a one-holder
  compromise threshold; ADR 0004 states that trade and its consequences, and
  supersedes any earlier mention of a threshold CA here.
- **Succession** (`RootSuccession/v1`) is for a root that is compromised or
  must rotate: the stable `HiveId` (the hash of the founding root public key,
  never changing), the predecessor root public key and epoch, the successor
  root public key, the next epoch, `kind` `planned` | `recovery`, an issuance
  time, the digest of the retained set (below), the recovery-group descriptor
  in force after the transition (its public key and (k, n)), the successor's
  possession signature over the rest, and the authorizing signature. A
  `planned` succession is signed by the predecessor root quorum; a `recovery`
  succession by the recovery group, a separate threshold over the
  shareholders plus offline shares the owner keeps apart. Precedence is by a
  **recovery generation** that only recovery successions advance: a member
  holds (root epoch, recovery generation), a recovery succession with a
  greater recovery generation supersedes any chain of planned successions
  whatever their epochs, and a planned succession never advances the
  recovery generation, so a compromised root cannot pre-empt recovery and a
  recovery is never mistaken for equivocation. Identical successions
  delivered twice are one.
- **What a succession keeps.** `planned`: the retained set of memberships and
  revocations, by identifier and digest, is frozen *inside* the succession
  (its digest is a field the successor's possession and the authorizing
  signature cover), and members accept under the retired root only what it
  names; a later holder of the retired root can add nothing. `recovery`:
  nothing is kept; every device re-enrols, every trust anchor and name the
  predecessor issued is withdrawn, the shareholders reshare for the new root.
- **Epochs and rollback.** Members persist the greatest (root epoch, recovery
  generation) seen and refuse anything older. The durable head witness
  detects a rolled-back state file, not a whole-machine restore; that
  boundary stays as the threat model states it, and a restored member is
  stale under the freshness rule until it reconciles.

ADR 0004 specifies the protocol: dealerless share generation, the two-round
signing session over the control channel with presence at each participant,
the root-state protocol, reshare with generations, the custody modes and the
provider capability matrix, the recovery group, and the adversarial vectors
(a lying shareholder, a replayed session, a substituted payload, a restored
share, two conflicting operations, a recovery racing a planned chain).
Threshold enrolment, reshare and succession are not implemented until ADR
0004's tests pass; until then a hive is administered by the file-held root as
today, labelled by `doctor` as a single point of failure.

## Signer policy

Which signatures need the owner's presence, and what a hostile same-user
process can still do, stated once and versioned (`policy: 1`):

- Presence required: certifying a key, revoking one, advancing the authority
  epoch, installing a trust anchor, enrolling the recovery authority. On a
  file-held device key, "presence" is the owner-only local control channel as
  today; `doctor` says the difference.
- Unattended: publishing an endpoint record (the publication key), membership
  renewal proof, reconciliation.
- The hardware helper (Swift, macOS/iOS) exposes one authority operation:
  `update-authority(manifest without signature)`, which validates every
  certificate, revocation and advertisement in it against the policy, shows
  the owner what changes (added, revoked, renewed) in one prompt, and signs
  the whole manifest atomically; and `advance-epoch`, and `renew-publication`
  (certify a new `publish` key before the old one's `not_after`, both live
  for one overlap). Never `sign(bytes)`. So a same-user process cannot make
  it sign an endpoint record with the device key, and a certificate cannot
  exist outside a signed manifest.
- Every signing domain, assigned. Root (threshold, as ADR 0004 steps):
  `supgang/root-step/v1`, whose payloads carry membership, revocation,
  trust-anchor, name, succession and roster operations. Device key:
  `supgang/authority/v1`, and `supgang/control-auth/v1` (ADR 0004's typed
  control-channel proof; the helper exposes it as `control-auth(challenge,
  peer, descriptor digest)` and nothing more general). Publication key: `supgang/endpoint-record/v4`,
  `supgang/session/v2`, `supgang/checkpoint/v2`, `supgang/renewal/v1`.
  Subject keys: `supgang/certified-key-possession/v1` and their own
  protocols. Nothing else signs. Stated consequence: a publication-key
  compromise lets the attacker publish addresses and speak in the network
  protocol as the device until the device revokes that key (an authority
  update, presence); it cannot change what the device is authorised to do.
- The helper reserves the next revision durably, signs, and publishes the
  new manifest to local state atomically before it returns anything usable;
  a crash between leaves a reserved, unused revision, never two manifests at
  one revision.
- What same-user malware can still do, stated: publish addresses of its
  choosing (as today), ask for a certification and hope the owner approves
  the prompt (the prompt shows purpose, audience and operations), read the
  file-held publication key. It cannot mint authority without the owner's
  touch, and it cannot extract a hardware-held key.

## What changes

- P-256 device keys outright; Ed25519 root and recovery authority. Existing
  records, node ids and memberships are not migrated; the hive is founded
  again (owner, 2026-09-19: legacy does not hold the design back).
- Encoding, stated: P-256 public keys as 33-byte compressed SEC1, validated on
  the curve at decode; ECDSA over SHA-256 of the domain-separated message;
  signatures as fixed 64-byte `r || s` with low-`s` enforced, so a given
  signature has one encoding. That is normalisation, not uniqueness: two valid
  ECDSA signatures over the same content differ, so record identity is by
  canonical content and `(epoch, revision)` or `(generation, sequence)`, and
  two records equal in those and in content are one record whatever their
  signature bytes; equivocation is different content, never different
  signatures. Every signed protocol that
  carries a device signature is versioned (endpoint record v4, membership v2,
  the new certificate, revocation set, manifest and trust-anchor types).
  `NodeId` is the hash of `p256 || compressed key`.
- `DeviceIdentity` becomes a trait: `public_key`, `custody`, and the typed
  authority operations; the file provider implements it; secret export and
  copy interfaces (`secret_bytes`, `duplicate_for_network_actor`) go, the
  network actor holds an opaque signing handle to the publication key.
- `supgang keys list|certify|revoke`, `supgang trust install|remove|status|
  issue`, `supgang recovery enrol`; `peers`, `resolve` and MCP `resolve`
  return the authority manifest.

## Invariants and threats

- Depth one; the device is the only issuer; a device's revocation by the root,
  or its epoch advancing, ends everything under it.
- A synced key's compromise is bounded by purpose, audience, operations,
  validity and the consumer's maximum status age; revoking it is an authority
  update, so it takes the owner's presence on the device key, and nothing
  less.
- Publication cannot change authority: the manifest is device-signed, the
  record publication-signed, and a manifest with an older epoch is rejected.
- No algorithm downgrade: device signatures are P-256, root and recovery
  signatures Ed25519, each in its own domain.
- Adversarial vectors to ship with the code: cross-hive certificate,
  cross-instance audience, wrong purpose for the operation, replayed
  possession, expired, revoked then re-presented, id reused, manifest with
  older epoch, record with a bare pin after certification was seen, clock
  rollback, succession by the old root alone.

## Consequences

Compass: passkey enrollment optionally endorsed by an `attest` certificate
over a server-issued transcript (its design says what the transcript binds);
`compassd` serves a leaf on a `transport-server` key; Remap's gateway dials
with a `transport-client` key when mutual admission is wanted. Dibs's hub key
becomes a `service` certificate. None keeps a key hierarchy of its own, and
each states its maximum status age.

Not decided here: the Secure Enclave helper's exact Swift surface and the
iOS member (its own ADR, after a real-device test of user-installed roots
for WebAuthn); TPM; whether a hive may require hardware custody of its
members.

## Review

First draft reviewed by astra (security lens) 2026-09-19 with Compass's
authentication design as one system; this draft answers the findings and
goes back before implementation.
