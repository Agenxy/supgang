# Roadmap: sovereign trust services

Agenxy's tenet (owner, 2026-09-19): rich, featureful computing and networking
never depends on commercial or otherwise external entities. Every service
below is one that third parties provide today because "an authority everyone
trusts" is needed; the hive root already is that authority for the owner's
devices. Each becomes a certified-key purpose under ADR 0003 plus a small
issuing protocol, or an ADR of its own where the protocol is larger.

| Service | Replaces | Shape in Supgang | Status |
| --- | --- | --- | --- |
| TLS certificate authority | public CAs, ACME | root-issued name-constrained trust anchor, leaves on `transport-server` keys (ADR 0003) | ADR 0003 draft |
| Names under a gang suffix | registrars, public DNS | `<name>.<hive>.gang`, root-signed records, Remap resolves | ADR 0003 draft, Remap |
| Code signing | Apple Developer ID, notarization, repo signing keys | purpose `code-sign`; a gang code-signing identity trusted on members; hardware-backed | purpose to add |
| Software update trust | Sparkle, stores, mirrors | purpose `release`; signed release manifests with rollback protection, published in the gang (generalises docs/security/secure-updates.md) | purpose to add |
| Time | NTP pools, vendor time | purpose `time`; signed timestamps from members, roughtime-style, so validity, freshness and rollback checks are sovereign | purpose to add; answers ADR 0003 freshness |
| SSH certificate authority | known_hosts sprawl, cloud SSH CAs | purposes `ssh-host`, `ssh-user`; certificates for every member | purpose to add |
| Identity provider | Okta, Google, Apple ID as IdP | the hive as OIDC issuer keyed to device and passkey; consumers (Compass, Dibs) use it instead of each being an authorization server | own ADR |
| Passkey and secret sync | iCloud Keychain, password managers as dependencies | the hive as an end-to-end encrypted sync fabric for `synced` custody, encrypted to device keys; vendors' sync remains a convenience | own ADR |
| Backup recovery | vendor accounts for restore | recovery recipients as certified keys; threshold escrow across members | own ADR (Compass backups want this) |
| Mail and messaging keys | public keyservers, WKD | member certificates for S/MIME or OpenPGP, a device-keyed directory | later |
| Overlay network | Tailscale-style coordination servers | WireGuard keys certified by the device, peer config from records (ADR 0001 is most of it) | later |
| Owner-verified hardware custody | vendor attestation services | `custody: hardware`, verified once by the owner in person, labelled owner-verified never attested | ADR 0003 |
| Firmware and boot trust | vendor Secure Boot roots | stays partly external; said so | out of scope |

Order: the ADR 0003 primitive first; then `time` (freshness is a blocker in
review), `code-sign` and `release` (Remap and Supgang already need them),
`ssh-*` (cheap); then the identity provider, sync and recovery ADRs.
