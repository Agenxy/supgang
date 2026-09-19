# ADR 0003: Hardware-held device keys and device-certified subordinate keys

Status: proposed

Date: 2026-09-19

## Decision

Two additions to the identity model, each coherent with the key types Supgang
already keeps apart (root, device, transport; docs/security/threat-model.md,
"Assets and boundaries"):

1. **A device key may be held by hardware the owner controls.** The Secure
   Enclave on Apple platforms, a TPM 2.0 on Linux and Windows, or a security
   key. The private key is generated inside the hardware and never leaves it;
   signing is an operation the hardware performs, and may require the owner's
   presence (Touch ID, a PIN, a touch). The owner-only file provider remains
   the fallback and keeps its `doctor` warning; a hardware-held key is what
   removes the warning. A device says which provider holds its key in its
   signed record, so peers can tell.

2. **A device may certify subordinate keys.** A *certified key* is a new
   device-signed record: a public key, its algorithm, a purpose, an issuance
   and an expiry, and the device's signature over the whole under a signing
   domain of its own. Purposes are a closed set that grows by ADR:
   `sync` (a convenience key the platform may carry across the owner's
   devices, iCloud Keychain for one), `service:<name>` (the key a local
   service presents, today advertised as a bare pin under ADR 0002),
   `transport` (a purpose-bound key for a hop between machines, certified
   rather than the device key itself exposed to TLS), `attestation` (a
   key another program's credential is bound to, a passkey's enrollment for
   one). Certified keys are published in the endpoint record beside
   addresses and advertisements, reconciled and returned as those are, and
   revoked by a later record that omits them or names them revoked.

A consumer that meets a certified key has the assurance Supgang gives about
the device: the hive root authorised this device, and this device, from its
hardware where it is so held, certified this key for this purpose. Where the
key lives, on disk, in a platform keychain, synced across devices, is not what
its authority rests on.

## Why

The owner stated the invariant on 2026-09-19: no Agenxy tool takes a critical
dependency on public or commercial infrastructure or an external actor.
Hardware the owner holds is theirs and belongs in the core; platform
conveniences such as synced credentials are supported for polish, on top of a
path that works without them. The threat model already names the gap: "the
owner-only file provider is weaker than Keychain, Secret Service, or hardware
keys."

Compass is the consumer that forced the question. Its authentication design
(Compass, docs/design/authentication.md) needs, for the owner's browsers on
other devices, a secure context whose trust root is the gang's; for passkeys,
an enrollment bound to a device the gang already knows, with a synced passkey
shown for what it is; for the hop between machines, a purpose-bound key
certified by the device rather than the device key itself in a certificate.
Each of those is a fact about a device's keys, and facts about a device's
keys are Supgang's to state, signed. The alternative, Compass keeping its own
key hierarchy, is what the tools decided against on 2026-09-13, and the rule
the owner set on 2026-09-19 is the general form: a gap in a sibling's domain
is fixed in the sibling, if coherent.

Synced keys are the case the owner named directly: a key the platform carries
across devices is a convenience, and it keeps an unbroken chain of trust when
the hardware-held device key signs it. That is exactly a certified key of
purpose `sync`.

## What changes

- **Algorithm.** The Secure Enclave and TPMs sign with ECDSA P-256, not
  Ed25519. Supgang moves to P-256 for device keys outright: one algorithm,
  the one the owner's hardware speaks, rather than two carried side by side
  with the agility risk that brings. Existing records, node ids and
  memberships are not migrated; the hive is founded again on hardware-held
  keys. The owner decided this on 2026-09-19: at this stage legacy is not to
  hold the design back, and everything is recoverable. The root key stays
  Ed25519 for now (the founder's, offline-capable, not hardware-held until
  root rotation is designed); a later ADR may move it too.
- **Providers.** `DeviceIdentity` becomes a provider behind a trait: sign a
  domain-separated message, give the public key, say what holds the key. The
  file provider is the existing code. The Secure Enclave provider is a
  Swift helper (Supgang's macOS/iOS pieces are Swift already where the
  platform demands it) reached over the same local control channel, doing
  nothing but sign on request with the owner present as the key's policy
  says. The TPM provider is a later ADR when a Linux or Windows member
  exists.
- **Certified keys.** A new record section, bounded (at most 16), each entry
  bounded, purposes a closed enum, expiry required and at most a year, the
  signature domain `supgang.certified-key/v1`. `supgang keys` lists, certifies
  (`supgang keys certify --purpose sync --public-key …`) and revokes. The MCP
  `resolve` tool returns them beside advertisements.
- **ADR 0002 advertisements** are unchanged; a service may additionally
  certify its key, at which point the pin and the certification say the same
  thing two ways, and a consumer may prefer the certification.

## Invariants and threats

- A certified key never certifies another; depth is one. The device is the
  only issuer, so revoking a device (root revocation) revokes everything
  under it at once.
- A synced key's compromise is bounded by its purpose and expiry, and the
  device can revoke it without the hardware key being touched. A hardware
  key's compromise is a device compromise, as today.
- Signing with the hardware key may require the owner's presence; the service
  therefore never signs on a network peer's demand alone. Endpoint records
  are re-signed when they change, and change is owner-driven or
  address-driven; a presence policy that is too strict makes a moving laptop
  fall silent, so the default policy is "presence to certify, not to publish",
  and the ADR for the Secure Enclave provider states the exact policy.
- There is no algorithm choice to downgrade: device keys are P-256, root
  keys Ed25519, each in its own domain, and a signature of the wrong kind
  for its domain fails verification.

## Consequences

Compass's leg 2 (passkeys) binds enrollment to an `attestation` key of the
device; leg 4 (machines) presents a `transport` key; a synced passkey is
recorded as `sync`. Remap's gateway can present a certified `transport` key
to Compass instead of nothing. Dibs's hub key becomes a `service:dibs`
certification when it wants one. None of them keeps a key hierarchy of its
own.

Not decided here: the Secure Enclave provider's presence policy and Swift
surface (its own ADR); TPM; root rotation and a hardware-held root; device
key rotation (a `successor` purpose is the obvious shape when it is needed);
whether a hive may require hardware-held keys of its members.

## Review

To be put to astra (security lens) together with Compass's authentication
design, as one system, before implementation.
