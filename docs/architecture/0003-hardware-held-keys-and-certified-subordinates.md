# ADR 0003: Hardware-held device keys and device-certified subordinate keys

Status: proposed (second draft, after astra's security review of the first)

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
     `transport-server`, `attest`. Not `sync`: custody is an attribute above,
     not a purpose; a synced key still has one narrow operational purpose.
   - `audience`: what the key may speak for: for `service`, the service name
     and the consumer's *instance id* (a 16-byte id the consumer, Compass for
     one, generates once and states, so `service:compass` on this device is
     this Compass and not another); for `transport-*`, the peer hive (always
     this one) and optionally one `NodeId`; for `attest`, the consumer's
     instance id; for `publish`, nothing.
   - `operations`: a bounded set of strings the consumer defines and the
     owner sees at certification (`sign-enrollment`, `serve-tls`, `dial`).
   - `not_before`, `not_after`: seconds; validity at most 366 days.
   - `policy`: the version of the signer policy (below) in force.
   - `possession`: the subject key's signature, in its own algorithm, over
     domain `supgang/certified-key-possession/v1\0` and the certificate's
     canonical bytes with this field empty: the key proved it was there at
     certification, bound to exactly this certificate.
   - `signature`: the device key's, over everything above.
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
`{epoch, certificates: [CertifiedKey], revocations: CertifiedKeyRevocations,
services: [ServiceAdvert]}`, signed by the device key over its own domain
(`supgang/authority/v1\0`) and carried opaque inside the record the
publication key signs. ADR 0002 advertisements move into it: a service pin is
authority, not an address. A record whose manifest signature fails, or whose
manifest epoch is older than one already seen for that device, is rejected
whole. A consumer that once saw a certificate for a service never falls back
to a bare pin for it.

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
  the CA's SPKI, its X.509 certificate with a name constraint permitting
  exactly the hive's private suffix (`*.<hive-label>.gang`, the label chosen
  at founding and stable), `pathLen` 0, key usage `keyCertSign` only, an
  epoch, and validity. A member installs the anchor into its platform trust
  only when the manifest verifies under the root it already trusts, and
  removes it when a newer manifest supersedes or a root-signed withdrawal
  arrives; `supgang trust install|remove|status` are the verbs, owner
  presence required for install.
- **Leaves** are issued by the founder's `supgang trust issue` for a name
  under the suffix to a device-certified `transport-server` key: the leaf's
  SPKI is the certified key, validity at most 90 days, `serverAuth` only. A
  consumer serving TLS (Compass's `compassd`) presents that leaf; Remap's
  gateway may keep pinning as today, browsers verify the chain.
- The suffix and each instance's exact hostname (`compass.<hive>.gang`) are
  Remap's to resolve; the RP ID for WebAuthn is that exact hostname.

## Root lifecycle

The root stays Ed25519, file-held by the founder, and gains what a root over
hardware-held devices must have before this ships:

- **Recovery authority.** At founding, or at the migration to this ADR, the
  founder enrols a second key, held apart (a security key, or a file on media
  the owner keeps offline), whose only power is to sign a *root succession*:
  a statement naming a new root key, an epoch, and the old root's `HiveId`.
  Members accept a succession signed by the recovery authority they were
  founded with, whether or not the old root signs it; an old-root signature
  alone, after compromise, is worthless, which is the point.
- **Epochs and rollback.** Root revocation sets and successions carry a root
  epoch; a member persists the greatest epoch seen and refuses anything older,
  including a restored backup of itself (the durable head witness the state
  already keeps).
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
- The hardware helper (Swift, macOS/iOS) exposes typed operations only:
  `certify(CertifiedKey without signature)`, `revoke(set)`, `advance-epoch`,
  never `sign(bytes)`. It validates the operation against the policy before
  asking the hardware, so a same-user process cannot make it sign an endpoint
  record with the device key.
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
  signatures as fixed 64-byte `r || s` with low-`s` enforced, so a signature
  has one form and record equality is by content; every signed protocol that
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
  validity and the consumer's maximum status age; the device revokes it
  without the hardware key being touched.
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
