# Roadmap: sovereign trust services

Agenxy's tenet (owner, 2026-09-19): rich, featureful computing and networking
never depends on commercial or otherwise external entities. Every service
below is one that third parties provide today because "an authority everyone
trusts" is needed; the hive root already is that authority for the owner's
devices. Each is an *authorization role* the root grants by name (who may
sign what, for which targets, under what threshold), never a purpose a device
may certify for itself: ADR 0003's certified keys authenticate keys; these
roles authorize them. Each gets an ADR stating its issuance authority, its
bounds and what consumers must pin. Corrections from astra's review
(2026-09-19) are folded in below.

| Service | Replaces | Shape in Supgang | Status |
| --- | --- | --- | --- |
| TLS certificate authority | public CAs, ACME | root-issued name-constrained trust anchor, leaves on `transport-server` keys (ADR 0003) | ADR 0003 draft |
| Names under a gang suffix | registrars, public DNS | `<name>.<hive>.gang`, root-signed records, Remap resolves | ADR 0003 draft, Remap |
| Code signing | Apple Developer ID, notarization, repo signing keys | a root-granted role: this key may sign these bundle ids or package names; members pin the role, never a bare member chain | own ADR |
| Software update trust | Sparkle, stores, mirrors | a root-granted release role per product and channel, keeping docs/security/secure-updates.md's rollback, expiry and release-authority rules; a generic signature replaces none of them | own ADR |
| Time | NTP pools, vendor time | an optional service: authenticated challenge-response with delay and uncertainty bounds, source selection, collusion and offline bootstrap stated; it does not close ADR 0003's freshness, which rests on signed issuance times and a bounded local clock | own ADR, later |
| SSH certificate authority | known_hosts sprawl, cloud SSH CAs | a root-granted role naming which hosts and which principals a key may certify | own ADR |
| Identity provider | Okta, Google, Apple ID as IdP | the hive as an *optional* OIDC issuer keyed to device and passkey, for consumers that want it; Compass remains its own authorization server and its grants are never sourced from the hive | own ADR |
| Passkey and secret sync | iCloud Keychain, password managers as dependencies | an end-to-end encrypted sync fabric with separately generated, purpose-bound key-agreement keys (never the signing keys), membership changes, rekeying and what revocation cannot erase stated; synced passkeys as an exportable credential-provider path, never an export of a hardware-bound one | own ADR |
| Backup recovery | vendor accounts for restore | recovery recipients with their own encryption keys; threshold escrow across members, designed apart from root succession | own ADR (Compass backups want this) |
| Mail and messaging keys | public keyservers, WKD | member certificates for S/MIME or OpenPGP, a device-keyed directory | later |
| Overlay network | Tailscale-style coordination servers | WireGuard keys certified by the device, peer config from records (ADR 0001 is most of it) | later |
| Owner-verified hardware custody | vendor attestation services | portable `CustodyProvider` and versioned `SealedKey`; macOS CryptoKit sealed-blob helper; owner-enrolled label, never attestation | Package 8 primitive; Linux TPM 2.0 and security keys `NotBuilt`; live identity remains file-held; typed authority integration pending (ADR 0003, tenth draft) |
| Firmware and boot trust | vendor Secure Boot roots | stays partly external; said so | out of scope |

Order: the ADR 0003 primitive and ADR 0004 (threshold root) first; then the
code-signing and release roles (Remap and Supgang already need them); then
SSH; then the identity provider, sync, recovery and time ADRs, none of which
the first tracks wait for.
