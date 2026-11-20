# Legacy agent-policy migration: installed refusal gate

Date: 2026-11-20 UTC. Scope: the `0.2.0-alpha.21` migration command on the
configured laptop and Solis acceptance peers. This records installed command
and refusal evidence. The live placement key was **not migrated**.

## Source and hosted checks

- PR #42 was squash-merged to `main` at
  `b54a4d574b78c01aad3383001a5fc282903491d4` from reviewed head
  `5c94a67225aa7004372f7f5d51573f42b0613e30`.
- The complete local quality gate passed 21/21 stages with zero skips:
  562 core tests passed, four declared ignores, and package verification
  passed. The migration tests covered wrong public pin, immutable policy,
  public-key preservation, self-exclusion refusal, and recovery after either
  side of the vault-save boundary.
- All hosted macOS, Ubuntu, RustSec and dependency checks ultimately passed.
  The first Ubuntu run failed the existing 10-second departed-path retirement
  assertion in the simulated hotspot scenario. A second Ubuntu run on the same
  head and the failed job's rerun passed without a code change. The intermittent
  failure remains open as [issue #22](https://github.com/Agenxy/supgang/issues/22);
  these later passes do not establish its root cause.

## Signed artifact and two-host install

- `make install` from the merged `main` commit produced a signed `supgang`
  binary with SHA-256
  `93c6a99c758e07931471b94ce5a77a6c28d3d08dc53e8611a661622f39f36fb9`
  and a signed Secure Enclave helper with SHA-256
  `e3305796cc039d3ec31f75985419d82dd46d187553b2e4a39a17d73a8d1f5330`.
  Both signatures passed strict verification.
- Outside the checkout, the installed command path, exact hashes, `--help`,
  `vault migrate-agent-policy --help`, and JSON `doctor` were checked. Doctor
  parsed as alpha.21 in strict mode on both hosts. It reported the existing
  unconfirmed public-reachability and file-held Ed25519 provider warnings;
  neither was treated as a passed reachability or hardware-custody claim.
- Alpha.20 backups were verified before replacing either host's binaries.
  Both physical peers received the exact signed alpha.21 bytes with owner-only
  helper permissions. Both service refreshes committed after reconnection.
  Service status on each host reported alpha.21 running, and each active
  process image hashed to the binary above.

## Live-vault refusal and migration hold

On the laptop, the installed alpha.21 command attempted migration of
`solis-placement-stage` to exact context `solis.placement.stage` with an
intentionally wrong public fingerprint. It refused with exit 3 and a public
fingerprint-mismatch error. Hashes of the vault, agent-audit head, and audit
segment were unchanged. This checks the no-effect wrong-pin path against the
live vault; it is not a successful migration test.

The current vault's public fingerprint for that key is
`568046ddaf2c7fd910ef82424646ab01e71f27ed946696957a2bbc819658e1f0`.
The actual verifier, its reviewed pin and exact context remain **UNKNOWN**.
Agenxy Labs reported that NC0 flows do not verify this signature and found no
consumer in its source tree. The Solis broker owner and Supgang lead were asked
to identify the consumer. The correct-pin migration remains held until that
review establishes consumer acceptance. The launcher key and release-tier
owner-action path are outside this acceptance.
