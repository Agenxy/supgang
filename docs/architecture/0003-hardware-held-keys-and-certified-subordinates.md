# ADR 0003: Hardware-held device keys and device-certified subordinate keys

Status: proposed (third draft, after astra's two security reviews)

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
     `transport-server`, `attest`, `code-sign`, `release`, `time`,
     `ssh-host`, `ssh-user` (the last five from the sovereign-trust roadmap,
     docs/architecture/roadmap-sovereign-trust.md; each with its audience
     schema stated when it is built). Not `sync`: custody is an attribute
     above, not a purpose; a synced key still has one narrow operational
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
     of the fields above this one (`hive` through `policy`; neither
     `possession` nor `signature` is part of them): the key proved it was
     there at certification, bound to exactly this certificate. A consumer
     re-verifies possession whenever the key is used in a protocol that lets
     it (a TLS handshake, a DPoP proof, a transcript signature).
   - `signature`: the device key's, over the canonical bytes of every field
     above, `possession` included.
   Depth is one: a certified key certifies nothing. At most 16 live
   certificates per device; consumers reject a record carrying more.

3. **Revocation of certified keys is a device-signed complete set,** as the
   root's revocation of devices is: `CertifiedKeyRevocations/v1`, the device's
   `NodeId`, authority epoch, a monotonic `sequence`, the sorted set of revoked
   certificate ids, signed by the device key. A newer set may not remove an id.
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
key: the owner's presence on a hardware-held key. That is a deliberate cost
(a touch a week on a laptop that publishes authority; none on one that
publishes only addresses, since a manifest with no certificates and no
services need not be renewed); a *status issuer*, a `publish`-like purpose
whose only power is to re-sign the same manifest with a new `issued_at`, is
the relief valve and is stated here as allowed, with the consequence that a
same-user process holding that key can keep stale authority looking fresh
for as long as the manifest's own `not_after` bounds allow. The owner chooses
per device; `doctor` says which. ADR 0002 advertisements move into the
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

- **CA material** is generated separately (P-256, held by the founder as the
  root is, hardware where available), never derived from any hive identifier
  or device key.
- **A trust-anchor manifest**, root-signed (`supgang/trust-anchor/v1\0`):
  the CA's SPKI, its X.509 certificate, an epoch, and validity. The
  certificate: `basicConstraints` critical `CA:TRUE, pathLen:0`; `keyUsage`
  critical `keyCertSign` only; `nameConstraints` critical, `permittedSubtrees`
  one `dNSName` `.<hive-label>.gang` (an X.509 subtree: the suffix and every
  name under it; there is no wildcard matching) and `iPAddress` none,
  `excludedSubtrees` the rest by omission; the label chosen at founding and
  stable. Whether a platform *enforces* name constraints on a user-installed
  anchor is not assumed: before an anchor is installed on a platform, that
  platform is tested with a leaf for a forbidden name and must refuse it
  (`supgang trust verify` runs that test against a throwaway pair and records
  the result per platform), and an anchor is not installed under a
  confinement claim the platform does not honour. Members install the anchor
  into platform trust only when the manifest verifies under the root they
  already trust, and remove it when a newer manifest supersedes or a
  root-signed withdrawal arrives, completing removal before the new one is
  trusted; `supgang trust install|remove|status|verify` are the verbs, owner
  presence required for install.
- **Leaves** are issued by the founder's `supgang trust issue` for a name
  under the suffix to a device-certified `transport-server` key: the leaf's
  SPKI is the certified key, validity at most 90 days, `serverAuth` only. A
  consumer serving TLS (Compass's `compassd`) presents that leaf; Remap's
  gateway may keep pinning as today, browsers verify the chain.
- Names are allocated by the founder (`supgang trust name <label>`), one per
  service instance, recorded root-signed so two instances never collide;
  each instance's exact hostname (`compass.<hive>.gang`, or
  `compass-2.<hive>.gang`) is Remap's to resolve, and the RP ID for WebAuthn
  is that exact hostname. A consumer that had a standalone hostname before
  the hive keeps it: the founder may allocate that exact name under the gang
  suffix only if it already ends in the suffix, and otherwise the consumer's
  name stays what it was and the hive issues a leaf for it through a second,
  instance-specific anchor rather than renaming; renaming is a destructive
  migration the owner runs on purpose.

## Root lifecycle

The root stays Ed25519, file-held by the founder, and gains what a root over
hardware-held devices must have before this ships:

- **Recovery authority.** At founding, or at the migration to this ADR, the
  founder enrols a second key, held apart (a security key, or a file on media
  the owner keeps offline), whose only power is to sign a *root succession*.
  `RootSuccession/v1`: the stable `HiveId`, the predecessor root's public key
  and epoch, the successor root's public key, the next epoch (exactly
  predecessor + 1), the recovery authority's identity, `kind`: `planned` or
  `recovery`, an issuance time, the successor's possession signature over the
  rest, and the recovery authority's signature over everything. Only the
  recovery authority advances the root epoch; an active root cannot sign a
  succession and so cannot pre-empt recovery with a larger epoch. Members
  accept a succession whose predecessor is their current root and whose
  signer is the recovery authority they were founded with; two successions
  from the same predecessor are equivocation, and the member stops until the
  owner resolves it in person. A `planned` succession keeps every membership
  the predecessor issued until its own expiry; a `recovery` succession keeps
  none: every device re-enrols, every trust anchor the predecessor issued is
  withdrawn, and the founder re-issues what is still wanted. Re-enrolment is
  the honest answer to a compromised root; a "surviving snapshot" would be
  the attacker's to choose. The recovery authority itself is rotated by a
  `planned` succession signed by the old recovery authority naming a new one.
- **Epochs and rollback.** Root revocation sets and successions carry the
  root epoch; a member persists the greatest epoch seen and refuses anything
  older. The durable head witness detects a rolled-back state file, not a
  whole-machine restore that rolls the witness back with it; that boundary is
  stated in the threat model already and stays. What limits it is
  reconciliation: a restored member learns the greater epoch from the first
  peer it meets, and until it does it is treated by peers as stale under the
  freshness rule above.
- **Stable hive identity.** `HiveId` becomes the hash of the *founding* root
  key and never changes; a succession chains from it. Certificates and
  manifests name the `HiveId`, so a root rotation does not invalidate them;
  a succession that *revokes* the old root does.
- **Offline members** catch up by the same reconciliation, processing
  successions before anything else, as revocations are today.

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
- Every signing domain, assigned: root: membership, revocation sets, trust
  anchors, successions (with the recovery authority). Device key: authority
  manifests only. Publication key: endpoint records, session authentication
  in the network protocol, checkpoints of local state, membership renewal
  proof. Recovery authority: successions only. Nothing else signs.
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
