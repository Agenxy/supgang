# ADR 0007: Release and code-signing roles

Status: Proposed for owner and consumer review; no protocol or API in this ADR is implemented.

Date: 2026-10-27

## Direction and boundary

The owner, 27 Oct 2026, relayed verbatim by Remap's lead, while the Remap 0.2.0 release waited
on Touch ID at a Mac he was away from:

> we should be using supgang to provide auth/certs so this can happen without me at the
> computer, it's a severe roadblock for agenxy development if I need to be there to physically
> approve these common processes

The sovereign-trust roadmap names two roles for this, code signing and release authority, each
"own ADR". This is that ADR. It removes three presence steps that Remap measures today:

| Step | Frequency | Removed by |
| --- | --- | --- |
| Release key's Touch ID at the signing Mac (Remap ADR-0029) | every signature | the release role, with presence moved to a carried device |
| Installer-certificate trust and local codesign identity trust | once per Mac | the code-signing role: targets accept a signature and never mint one |
| `sudo` for install and DNS activation | every operation | not this ADR: ADR 0005 owner-action grants |

What this ADR does not change:

- Enrolment stays in person, by the owner's 15 Oct rule (agenxy-installation.md). That includes
  pinning a hive in a consumer and turning a role on.
- Update authority stays separate from hive authority (secure-updates.md). The root grants a
  role to a separate key. The root never signs artifacts, and no role key is derived from or
  reused as a root, device, transport, publication or TUF key.
- Supgang's own updates keep TUF, with its thresholds, expiry, rollback and mix-and-match rules.
  A release-role signature replaces none of them. The code-signing role only supplies the
  platform identity that secure-updates.md "macOS signing" leaves to a per-Mac trusted
  certificate.
- Supgang is an optional provider (owner, 14 Oct). A consumer's own release key and signing
  path remain its default. Accepting a role is an opt-in per consumer, and disabling it needs no
  ceremony.

## The two roles

Both are typed root operations (`supgang/root-step/v1` payloads). They follow the same
predecessor, sequence, fork and durable-write rules as membership and ADR 0005's grants. Each
has a matching monotonic revocation operation. A device authority manifest cannot issue either
one. A role is not an ADR 0003 purpose: no device may certify a key for it.

Fields common to both, in canonical order:

| Field | Meaning |
| --- | --- |
| `hive_id`, `role_id` | Exact hive and a random, never-reused 16-byte role identity. |
| `kind` | `release` or `code-signing`; a verifier refuses a kind it does not implement. |
| `consumer_id` | Exact product, such as `org.agenxy.remap`; no wildcard. |
| `signers` | 1 to 3 role keys (P-256 or Ed25519), each with algorithm, public key, enrolled custody label and a possession proof over the role fields above `signers`. |
| `threshold` | k of `signers`; for `release`, also the stated presence mode below. |
| `not_before`, `not_after` | At most 366 days. |
| `issuer_head` | Root-chain predecessor and sequence. |

Extra fields per kind:

- `release`: `package_format`, such as `remap-package-v1`; `channels`, a sorted set of 1 to 4
  short names; `min_version`, the floor below which nothing is accepted; and `presence`, one of
  `carried-device` or `unattended`.
- `code-signing`: `identifiers`, a sorted set of 1 to 8 exact code-signing identifiers
  (`org.agenxy.remap.daemon`; no prefix or wildcard), and `certificate`, the DER of the role's
  self-issued code-signing certificate (below), whose key must be one of `signers`.

Revoking a role's signer device, or revoking the role, ends it at once. Rotating a role key is a
new grant followed by revocation of the old one. That makes rotation an owner action at root
authority, never something a role key can do for itself.

## Release role

A release is a **release statement**. It is canonical CBOR, signed under domain
`supgang/release/v1` by `threshold` of the role's signers:

- `role_id`, `consumer_id`, `package_format`, `channel`;
- `version`, at least `min_version` and strictly greater than every version the consumer has
  accepted on that channel. The consumer keeps that per-channel high-water mark as durable state
  that only root can write.
- `artifacts`: 1 to 16 entries, each with target OS and architecture, byte length and SHA-256.
  The consumer's `package_format` defines what one artifact is. For `remap-package-v1`, it is
  the canonical release manifest, one per architecture, because that manifest already binds
  every payload file's path, kind, hash, size and mode. All of a release's artifacts appear in
  one statement, so artifacts from two different releases cannot be mixed.
- `source_commit` and the provenance digest the consumer defines;
- `issued_at` and `expires_at`, at most 30 days apart. A consumer refuses an expired statement
  for a new install or update, so a frozen mirror shows up as a failure instead of being
  accepted.
- for `presence: carried-device`, an ADR 0005 owner-action assertion. The assertion names
  consumer `org.agenxy.supgang`, operation `release.sign`, and the statement's digest without
  this field. It is signed by an owner-held key on a device the owner carries, under that
  device's own presence prompt.

**Presence modes.** `carried-device` is the default. It moves the Touch ID from the signing Mac
to the phone or laptop with the owner. The owner still approves each release, but from
anywhere, and nobody needs to be at the signing machine. `unattended` lets a hardware-held role
key sign with no prompt, so CI-style releases need no person at all. The owner chooses it per
role at grant time, and it is refused unless all of the following hold:

- every signer has custody `hardware`;
- the role's `channels` exclude any channel the consumer installs by default;
- `not_after` is at most 90 days after `not_before`;
- the role is bounded to `consumer_id`.

The consequences are stated rather than hidden. A compromised unattended role key can publish
releases to that consumer's opted-in Macs, on those channels, until the role expires or is
revoked. A compromised carried-device role key cannot publish without the owner approving each
release.

**Consumer verification (Remap's `remap-package-v1`).** The consumer accepts a package if
either of these holds:

1. its pinned native key (Remap's Enclave key) signed it, the default and unchanged; or
2. the owner opted this Mac into the hive's release role, and every check below passes.

The role path is accepted beside the native key and never instead of it. A role-path failure
never masks or replaces a native success, and turning the role path off removes only that path.

The opt-in is the consumer's own state, which only root can write, written only by the
in-person enrolment. It holds:

- the pinned hive fingerprint;
- the role id;
- the accepted channels;
- the maximum status age.

The opt-in is never read from the package or its staging area. The consumer implements the
role checks in its own verifier, with no Supgang code, against the frozen wire specification
and test vectors listed under acceptance. A consumer that runs as root at install time cannot
depend on a sibling program. The checks:

- the role grant is root-signed on the pinned hive;
- a root-signed status shows the role and its signer devices unrevoked. The status must be no
  older than the consumer's stated maximum age, at most 7 days.
- the statement and its assertion verify;
- version, channel and expiry rules hold;
- the artifact bytes match.

The consumer obtains the grant and status bundle from Supgang when it is present. It can also
take the bundle as a file shipped beside the package, because the root signatures make the
transport irrelevant. A missing, stale or ambiguous bundle fails the role path and leaves the
native path. Nothing ever falls back to accepting.

ADR 0005 already records the gap this depends on: the root-signed revocation snapshot has no
expiry. This ADR needs it closed, and status freshness is the same work for both ADRs.

## Code-signing role

**The measurement this rests on** (agenxy-installation.md, 24 Sep): a binary signed on one Mac
with a certificate that a second Mac has never held passes `codesign --verify --strict` on the
second Mac, satisfies its designated requirement, and runs. Only *minting* a signature needs a
trusted identity. So targets that receive pre-signed binaries need no trust setting, no
installer certificate, and no local signing identity.

**The certificate.** It is self-issued by the role key, with:

- key usage `digitalSignature`;
- extended key usage `codeSigning` only;
- subject common name `<consumer_id> code signing <role_id prefix>`;
- validity no longer than the grant.

It does not chain to the ADR 0003 browser trust anchor. That anchor is name-constrained for
TLS, and giving it a code-signing purpose would widen what a TLS key compromise can do. The
certificate's authority comes from the root grant that pins it, not from any chain.

**Designated requirement.** Every signed binary carries:

```text
identifier "<identifier>" and certificate root = H"<SHA-1 of the role certificate>"
```

The requirement stays the same across releases for as long as the role certificate does. That
is the property a stable TCC, firewall and keychain identity needs, and that ad hoc signatures
lack. Rotating the role changes it. The last release under the old role therefore ships a
statement that names the successor certificate. The consumer's updater then accepts the
designated-requirement change exactly once, and expects macOS to re-ask any TCC permissions.

**Signing without a trusted identity.** The signing host cannot use `codesign` either, unless
the identity is trusted there: macOS 27 refuses an untrusted identity, as measured. The decided
signer is in-process Mach-O signing through a keychain-independent signer, the `apple-codesign`
crate. It is pinned and reviewed under the usual dependency rules, and it calls the custody
provider's signing operation for the CMS signature. The private key never leaves the provider
and the keychain is never asked. Until that signer is accepted, one stated fallback is allowed:
trusting the role certificate once, in person, on the single release host, and on no target.

**Installation.** What the role requires is Mach-O that arrives already signed, together with a
detached release statement. Removing the installer-certificate trust step also means not
shipping an installer package signed with an installer certificate. Each consumer decides its
own distribution format; Remap's lead has scoped that as a Remap ADR. The same in-process
signer, used with a consumer's own native key, removes the local codesign trust step from the
native path too. A root-owned helper installs the files from root-owned staging after verifying
them. Running that helper still needs `sudo` until ADR 0005 replaces it with an owner-action
assertion.

## Custody and sequencing

Both roles rest on the root and on the role keys staying where the owner put them.

- Package 8 (portable custody, the macOS Secure Enclave provider) must hold every
  `unattended` signer and the carried-device assertion key. A `file` custody label is refused
  for both.
- `carried-device` signers may be file-held only while the hive's live identity is itself
  file-held. In that case `doctor` and the grant prompt say so.
- Root grants are signed by the hive root. Until ADR 0004's threshold root is operational, that
  root is a single file-held key. Each role grant then carries that limitation in its prompt,
  and consumers keep the role path off by default.

Order of work:

1. close ADR 0005's status-freshness gap;
2. the shared grant encoding with ADR 0005;
3. the release role with `carried-device`;
4. the code-signing role and in-process signer;
5. `unattended`, last, only on hardware custody.

## Acceptance before anything is advertised

Each gate below is proven on two physical Macs before any `doctor`, `--help` or MCP output
offers the role:

- a release signed through a carried-device approval, made with nobody at the signing Mac,
  installs on a second Mac;
- the same release refuses each of the following: expired, version rollback, wrong channel,
  revoked role, revoked signer device, stale status, mixed artifacts, wrong consumer;
- a launchd daemon signed by the role loads on a Mac that has never held the role certificate.
  This is unproven today (agenxy-installation.md).
- a TCC prompt names the product, and a granted permission survives a role-signed update;
- the application firewall keeps its decision across a role-signed update;
- disabling the role path on a consumer leaves its native path working, with no ceremony;
- a frozen wire specification of the grant, status, release statement and ADR 0005 assertion,
  published with test vectors. Each of the four comes in a valid form and in tampered forms that
  cover every refusal below. An independent consumer verifier, such as Remap's CryptoKit
  implementation, passes all of them.

Adversarial vectors to ship as tests, one each:

- a cross-hive grant;
- a release role used as code-signing and the reverse;
- an identifier not in the grant;
- a prefix identifier;
- an unattended role with a file signer;
- an unattended role on a default channel;
- a statement signed by fewer than `threshold` keys;
- an assertion bound to another digest;
- a reused `role_id`;
- a grant with a stale `issuer_head`;
- a status older than its maximum age.

## Consequences

- Remap releases and installs proceed with the owner away. The owner approves releases on a
  carried device, or approves nothing at all for an unattended role they chose to grant.
- Target Macs lose the per-Mac trust steps entirely; macOS is never asked to trust anything.
- The hive root becomes the authority for which keys may publish an Agenxy product, which makes
  ADR 0004's threshold root and package 8 more urgent, not optional.
- Secure-updates.md's per-Mac trusted signing identity for Supgang is superseded by the
  code-signing role once its acceptance gates pass. TUF remains Supgang's release authority.

## Review

Open for the owner:

- whether `unattended` is wanted at all in the first release;
- the default maximum status age (7 days proposed);
- which channels Remap installs by default.

Remap's lead confirmed (27 Oct) that `remap-package-v1` can take a second authority behind an
opt-in. The single authority check, `PortableReleaseVerifier.verifySignature`, authenticates
the canonical release manifest, and everything after it is keyed to those bytes. The five
conditions that came with the confirmation are folded in above:

- the consumer defines what an artifact is;
- the opt-in is state that only root can write, set at enrolment;
- the consumer has its own verifier, with frozen vectors;
- a per-channel high-water mark;
- the distribution format is the consumer's decision.

Remap's consumer ADR decides two things of its own:

- where the bundle sits in its staging area;
- whether its native path gains the same rollback high-water mark.

Before relying on it, Remap measures whether a launchd daemon loads, and a TCC prompt names the
product, under a certificate the target Mac does not hold.
