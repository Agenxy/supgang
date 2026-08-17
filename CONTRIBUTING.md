# Contributing to Supgang

Supgang accepts security-sensitive network and filesystem input. A change is complete only when its
failure behavior, resource bounds, documentation, and tests are complete too.

## Before changing code

Read `AGENTS.md`, the architecture decision, and the repository-backed threat model. For protocol,
identity, state, transport, local-control, or release changes, state which invariant and threat are
affected before implementation.

Do not add telemetry, an account, a hosted dependency, a vendor relay, a public bootstrap default,
a remote kill switch, or a proprietary component. A user-owned optional component must remain
replaceable and disabled unless deliberately configured.

## Engineering rules

- Use the pinned Rust toolchain and exact direct dependency versions.
- Keep warnings as errors. Do not suppress a finding without a narrow written security rationale.
- Keep portable Supgang source free of `unsafe` Rust and shell-owned application logic.
- Bound every frame, collection, allocation derived from input, queue, stream, connection set, and
  retry.
- Persist authoritative state before publishing it.
- Reject non-canonical or trailing input and preserve deterministic merge behavior.
- Do not print secrets or peer addresses in ordinary logs, errors, tests, or issue reports.
- Add a regression test for every fixed defect.
- Update the threat model and architecture record when the trust boundary changes.

## Local verification

Run focused tests while iterating, then the complete gate:

```text
cargo test --locked --package supgang TEST_NAME
make check
cargo build --locked --workspace --release
target/release/supgang --version
```

Protocol or service changes also need a real multi-process test. Exercise startup order, connection,
state-owner CLI access, interruption, restart, and the relevant failure path. Report the exact
platform and any target not tested.

## Dependency changes

Prefer no new dependency. When one is necessary:

1. Verify the current stable version from its primary source.
2. Pin it exactly and disable unused default features.
3. Inspect normal, build, development, macOS, and Linux graphs.
4. Run RustSec and licence checks with no ignored result:

   ```text
   cargo install --locked --version 0.22.2 cargo-audit
   cargo install --locked --version 0.20.2 cargo-deny
   cargo audit --deny warnings
   cargo deny check advisories licenses sources
   ```

5. Document any duplicate package identity in `docs/security/dependency-exceptions.md`.
6. Explain why the capability cannot be implemented safely with the existing graph.

## Security reports

Follow `SECURITY.md`. Do not place real keys, bundles, addresses, or another person's data in a
public issue or test fixture.
