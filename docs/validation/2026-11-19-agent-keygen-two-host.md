# Agent-purpose remote key creation: two-host acceptance

Date: 2026-11-19 local / 2026-11-20 UTC. Scope: private agent-purpose key
creation and signing on the configured laptop and Solis acceptance peers.
This is installed, physical-path evidence for `0.2.0-alpha.20`, not a public
release or release-tier owner approval.

## Source and artifact custody

- PR #40 was squash-merged to `main` at `b3d019e0ed4acdc644f071cbb9334955a57a8fb0`.
  Its reviewed head `61a4da9293971e1fa70b5749d290e2cbfe6fb4b0` has the same source tree.
- The complete local quality gate passed: 21 cache misses, 0 skips, 557 core
  tests passed, 4 explicitly ignored; package verification passed. The eight
  hosted macOS, Linux, RustSec, and dependency checks all passed.
- `make install` from the merged `main` commit made one signed binary with
  SHA-256 `059229510a6c2e00e3d80dcd882abdbbb60c0b6d8e305e1c5e8e52533483fad8`
  and one signed Secure Enclave helper with SHA-256
  `06e179c3621e8fd10f5a2d67f5a6c580857e0151c31168f3061152b3d37dd213`.
  Outside the checkout, the installed command path, both hashes, `--help`,
  and JSON `doctor` were checked. Both signatures passed strict verification.
- Those exact bytes were installed on both physical peers. The helper was
  owner-only. Both `service refresh` operations committed probation; running
  version was alpha.20, no activation was pending, and the live service process
  on each host hashed to the binary above. Neither active slot had an adjacent
  helper. Solis reconnected after each refresh and remained connected at the
  final check.

## Member request and negative cases

The current certified Solis member requested purpose
`sg-remote-keygen-20261119` with only context
`acceptance.remote-keygen` on the laptop. The returned Ed25519 public key and
SHA-256 fingerprint matched the laptop vault's public-key result. Solis then
requested a signature with that exact purpose, context and fingerprint pin.
An independent Python `cryptography` Ed25519 verifier accepted the signature
over `supgang-sign/v1\0`, the context, a zero separator, and the fixed public
test digest `0x11` repeated 32 times.

The target refused a wrong-context signature and refused creation under the
same purpose name. The laptop audit recorded the certified Solis requester in
contiguous, hash-linked records: sequence 22 `create-reserved`, 23
`create-activated`, 24 `nonce-reserved`, 25 `sign`, and 26 `denied`. The test key
was then removed on the laptop: sequence 27 is `revoke-reserved`, and a later
remote signing attempt was refused with sequence 28 `denied`. The test key is
no longer present.

A previously root-revoked disposable member on Solis was briefly started with
its preserved, owner-only state. It had zero active peers; its remote creation
request was refused because it could not connect. The laptop had no vault key
or audit entry for that requested purpose. The disposable process was stopped.
This proves admission refusal for a revoked member across the two hosts; it
does not claim an in-flight keygen cancellation after a new revocation.

## Remaining boundaries

This exercise does not provision an owner-action key on a phone, authorize a
release-purpose key, install a consumer pin, issue a service certificate,
rotate audit checkpoints, migrate the existing placement or launcher keys,
or establish public-release acceptance. Those remain separate work and gates
in ADR 0011 and ADR 0005.
