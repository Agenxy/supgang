# Supgang Release Runbook

This runbook documents the exact steps to rehearse and publish a public Supgang release.
Do not execute the publish or public release steps without the owner's explicit approval.

Per `AGENTS.md`, every release is rehearsed first on the exact packaged bytes and published
from the exact same commit on `main`, because Cargo records the source commit inside each
packaged `.crate` archive (`.cargo_vcs_info.json`).

## Current release blockers

Before starting a release rehearsal, verify that every blocker below is closed on `main`:

1. **Toolchain drift**: keep `rust-toolchain.toml`, `Cargo.toml`, `README.md`, and all
   `.github/workflows/*.yml` action and `uv` pins current so `supgang-quality -- drift`
   passes (`chore/toolchain-1.100`).
2. **Issue #27 (packaged all-target dependencies)**: Cargo does not carry `[patch.crates-io]`
   into published crates. Vendored `netwatch` (0.20.2 without unused Windows `chrono` and
   with `wmi` `default-features = false`) and `portmapper` (0.20.2 pointing at
   `supgang-netwatch`) must be published as Supgang-owned crates (`supgang-netwatch`,
   `supgang-portmapper`), `[patch.crates-io]` and `third_party/netlink-packet-core` removed,
   and the multi-target packaged dependency graph rehearsal gate wired into `publish.yml`
   (`fix/release-packaged-deps-27`).
3. **Issue #29 (package verification isolation)**: `supgang-quality` package verification
   must run in a per-run isolated target directory and `CARGO_HOME` so two revisions sharing
   a prerelease version can never compile against a stale temporary-registry extraction
   (`fix/package-verify-isolation-29`).
4. **crates.io Trusted Publishing for brand-new crates**: as of `0.1.0`, only `supgang` and
   `supgang-core` exist on crates.io. `supgang-acl`, `supgang-netwatch`, and
   `supgang-portmapper` do not exist yet (HTTP 404). Before `.github/workflows/publish.yml`
   can publish them via OIDC (`rust-lang/crates-io-auth-action`), the owner must register or
   configure Trusted Publishing on crates.io for `supgang-netwatch`, `supgang-portmapper`,
   and `supgang-acl` (binding repository `Agenxy/supgang`, workflow `publish.yml`,
   environment `release`), and confirm the same binding on `supgang-core` and `supgang`.
5. **Physical cross-host acceptance**: per `AGENTS.md`, install the exact rehearsed release
   artifact on every configured physical acceptance peer and repeat the applicable
   cross-host checks (`command -v supgang`, SHA-256 hash match, `supgang --help`,
   `supgang --json doctor`, peer connectivity and service checks).

### Out of scope for this release (explicitly still gated)

Publishing to crates.io, GitHub Releases, and Homebrew does **not** activate Supgang's
production TUF auto-update root or ADR 0007 release/code-signing roles:

- Production TUF auto-update remains blocked on the witnessed 2-of-3 root and targets key
  ceremony, reproducible production binaries, and full platform acceptance described in
  `docs/security/secure-updates.md`.
- ADR 0007 release and code-signing roles remain off until status freshness, shared grant
  encoding, frozen vectors, and two-Mac acceptance pass
  (`docs/architecture/0007-release-and-code-signing-roles.md`).
- Release notes must state this boundary clearly so users do not mistake a crates.io or
  GitHub release for an enabled production TUF trust root.

## Step 1: Choose and bump the version

`0.2.0-alpha.21` has been reused across multiple development builds, which makes installed
binaries ambiguous by version string alone and triggered same-version packaging collisions
(Issue #29). Never reuse a version string once a rehearsal candidate is cut.

### Proposed next version

Choose one of two options with the owner before preparing the version-bump PR:

- **`0.2.0` (recommended if clearing Issue #6 now)**: crates.io displays the latest
  non-prerelease version on the default crate page. Currently `crates.io/crates/supgang`
  renders `0.1.0`, which still carries the retired `"Sovereign ..."` summary and
  `"sovereign"` keyword from before PR #5 (Issue #6). Publishing a non-prerelease `0.2.0`
  replaces `0.1.0` as the landing page and closes Issue #6.
- **`0.2.0-alpha.22` (or `0.2.0-rc.1`)**: keeps the release explicitly marked as a
  pre-release while Linux physical acceptance and production TUF root remain open, but
  leaves `0.1.0` (and Issue #6's outdated summary) as the default page on crates.io.

### Exact files to update in the version-bump PR

Update every pinned workspace version reference together on a dedicated branch from `main`
(replace `<NEW_VERSION>` with the chosen version, e.g. `0.2.0` or `0.2.0-alpha.22`):

1. `Cargo.toml`:
   - `[workspace.package].version = "<NEW_VERSION>"`
   - `[workspace.dependencies].supgang-acl = { path = "crates/supgang-acl", version = "=<NEW_VERSION>" }`
   - Verify `homepage = "https://agenxy.org/projects/supgang"` and
     `repository = "https://github.com/Agenxy/supgang"` (consistent `Agenxy` org casing,
     Issue #6).
2. `crates/supgang-cli/Cargo.toml`:
   - `supgang-core = { path = "../supgang", version = "=<NEW_VERSION>" }`
3. `crates/supgang-quality/src/main.rs`:
   - Update the `inspect_package_identity` assertion matching
     `supgang-core = { path = "../supgang", version = "=<NEW_VERSION>" }`.
4. `crates/supgang/assets/mcp-sdk-client.ndjson`:
   - Update `"version":"<NEW_VERSION>"` on lines 2 and 7 of the MCP client transcript fixture.
5. `Cargo.lock`:
   - Refresh workspace package versions (`cargo check --workspace` or
     `cargo update --workspace`).
6. `CHANGELOG.md`:
   - Move the `Unreleased` entries under a dated `## <NEW_VERSION> - YYYY-MM-DD` heading and
     open a fresh `## Unreleased` section.

Run the complete local gate with caching disabled and merge the version-bump PR to `main`
before starting the rehearsal:

```text
SUPGANG_QUALITY_CACHE=off cargo run --locked --package supgang-quality -- all
GH_TOKEN=$(gh auth token) cargo run --locked --package supgang-quality -- drift
```

Record the merged `main` commit SHA (`RELEASE_COMMIT`). Every rehearsal artifact and the
final publish must come from this exact commit.

## Step 2: Rehearsal channel and verification

Rehearsal builds, verifies, and serves the exact bytes that will be published, without
touching crates.io, public GitHub releases, or `Agenxy/homebrew-tap`.

### What the rehearsal channel serves

Stage a rehearsal directory (for example a local/internal rehearsal mirror or a workflow
artifact directory keyed by `RELEASE_COMMIT`) containing:

1. **Exact packaged crate archives** (`.crate` files produced by `cargo package --locked`):
   - `supgang-netwatch-<VER>.crate`
   - `supgang-portmapper-<VER>.crate`
   - `supgang-acl-<NEW_VERSION>.crate`
   - `supgang-core-<NEW_VERSION>.crate`
   - `supgang-<NEW_VERSION>.crate`
2. **Release binaries and checksums** built from `RELEASE_COMMIT`:
   - macOS `aarch64-apple-darwin` (and `x86_64-apple-darwin` if targeting Intel Macs):
     `supgang` and optional `supgang-secure-enclave` (built with
     `uv run --offline --script platforms/macos/build.py --beside <bin>`)
   - Linux `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`: `supgang`
   - `SHA256SUMS.txt` covering every `.crate` archive and binary tarball
3. **Audit and gate logs** from `RELEASE_COMMIT`:
   - `SUPGANG_QUALITY_CACHE=off cargo run --locked --package supgang-quality -- all`
   - Multi-target packaged dependency graph rehearsal gate (`cargo run --locked --package supgang-quality -- packaged-deps`, Issue #27) confirming that
     unpacking the exact `.crate` archives with no `[patch.crates-io]` resolves cleanly for
     all 6 targets (`aarch64-apple-darwin`, `x86_64-apple-darwin`,
     `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`,
     `riscv64gc-unknown-linux-gnu`, `x86_64-pc-windows-msvc`) with zero `chrono`, zero
     `paste`, zero `netlink-packet-core <0.9`, and zero duplicate `netwatch`.
   - `cargo audit --deny warnings --ignore RUSTSEC-2023-0089`
   - `cargo deny check licenses sources`

### Local and physical peer acceptance on the rehearsed build

1. Install from `RELEASE_COMMIT` with `make install` (passing `MACOS_CODESIGN_IDENTITY` on
   macOS when signing with the owner certificate).
2. From outside the repository directory, verify:
   - `command -v supgang` resolves to the installed path (`$HOME/.local/bin/supgang`)
   - `shasum -a 256 "$(command -v supgang)"` matches the rehearsed binary hash
   - `supgang --version` prints `supgang <NEW_VERSION>`
   - `supgang --help` and `supgang --json doctor` pass cleanly
3. Install the same rehearsed artifact on every configured physical acceptance peer and
   repeat the cross-host connectivity and service checks.

Stop here and request the owner's direct approval before moving from rehearsal to public
release.

## Step 3: Publish crates to crates.io

Only after the owner gives explicit approval for `RELEASE_COMMIT`:

1. Confirm `main` HEAD is still `RELEASE_COMMIT` (or dispatch on the exact tag/ref pointing
   at `RELEASE_COMMIT`).
2. Dispatch `.github/workflows/publish.yml` via GitHub Actions (`workflow_dispatch`) and
   approve the `release` environment gate when prompted.
3. The workflow executes in strict dependency order using short-lived OIDC tokens from
   `rust-lang/crates-io-auth-action`:
   1. `validate`: runs `supgang-quality -- all` (`SUPGANG_QUALITY_CACHE=off`), the Issue #27
      packaged dependency graph gate, `cargo audit`, and `cargo deny check licenses sources`.
   2. `publish-netwatch`: `cargo publish --locked --package supgang-netwatch` (skip if that
      exact vendored version is already published on crates.io).
   3. `publish-portmapper`: `cargo publish --locked --package supgang-portmapper` (needs
      `publish-netwatch`; skip if already published).
   4. `publish-acl`: `cargo publish --locked --package supgang-acl` (needs `validate`).
   5. `publish-core`: `cargo publish --locked --package supgang-core` (needs `publish-acl`
      and `publish-portmapper`).
   6. `publish-cli`: `cargo publish --locked --package supgang` (needs `publish-core`).
4. Verify each published crate page on crates.io:
   - Confirm `cargo install --locked supgang --version <NEW_VERSION>` resolves cleanly in a
     clean temporary `CARGO_HOME` and `--root`.
   - Confirm Issue #6: when `<NEW_VERSION>` is non-prerelease (such as `0.2.0`), verify
     `https://crates.io/crates/supgang` shows the updated description and keywords with no
     `"sovereign"` text.

## Step 4: Publish the GitHub release with binaries and SHA-256 checksums

1. Create and push the annotated git tag on the exact rehearsed commit:

   ```text
   git tag -a "v<NEW_VERSION>" "<RELEASE_COMMIT>" -m "Supgang <NEW_VERSION>"
   git push origin "v<NEW_VERSION>"
   ```

2. Build release archives from the exact tagged commit `v<NEW_VERSION>`:
   - **macOS (`aarch64-apple-darwin`, and `x86_64-apple-darwin` if built)**:
     - Build `supgang` with `cargo build --locked --release --package supgang`.
     - Note signing honestly in the release body: ad hoc Mach-O signatures provide no stable
       cross-version identity; owner-certificate signatures require per-Mac trust; Developer
       ID notarization requires Apple Developer Program membership
       (`docs/security/secure-updates.md`).
     - If bundling `supgang-secure-enclave`, build it via
       `uv run --offline --script platforms/macos/build.py --beside <bin>` and include it
       beside `supgang` in the macOS archive.
   - **Linux (`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`)**:
     - Feasible directly on GitHub Actions `ubuntu-24.04` (x86_64) and `ubuntu-24.04-arm`
       (aarch64) runners with `cargo build --locked --release --package supgang`.
     - `riscv64gc-unknown-linux-gnu` can be added once a hosted or lab RISC-V builder and
       physical acceptance gate are in place.
3. Package each target as `supgang-<NEW_VERSION>-<TARGET>.tar.gz` containing `supgang`
   (and `supgang-secure-enclave` on macOS when bundled), `LICENSE`, and `README.md`.
4. Generate `SHA256SUMS.txt` over every uploaded archive (`shasum -a 256 *.tar.gz`).
5. Create the GitHub release for `v<NEW_VERSION>` on `Agenxy/supgang` (marking
   `--prerelease` if `<NEW_VERSION>` is a prerelease, or as latest release if `0.2.0`),
   attaching all `.tar.gz` archives and `SHA256SUMS.txt`, and recording:
   - exact `RELEASE_COMMIT` SHA;
   - published crate names and versions;
   - changelog highlights;
   - current security and platform support boundary (including that production TUF root and
     ADR 0007 roles are not yet active).

## Step 5: Update the Homebrew tap (`Agenxy/homebrew-tap`)

After tag `v<NEW_VERSION>` is published on GitHub:

1. Fetch the exact GitHub source tarball and compute its SHA-256:

   ```text
   curl --fail --location --silent \
     "https://github.com/Agenxy/supgang/archive/refs/tags/v<NEW_VERSION>.tar.gz" \
     | shasum -a 256
   ```

2. In a branch of `Agenxy/homebrew-tap`, update `Formula/supgang.rb`:
   - Set `url` to `https://github.com/Agenxy/supgang/archive/refs/tags/v<NEW_VERSION>.tar.gz`.
   - Set `sha256` to the computed hash.
   - Keep `homepage "https://github.com/Agenxy/supgang"` (consistent `Agenxy` casing).
   - Keep `depends_on "rust" => :build` and
     `system "cargo", "install", *std_cargo_args(path: "crates/supgang-cli")`.
   - Note: `Formula/supgang.rb` currently builds only the Rust CLI and does not build the
     macOS Swift helper (`platforms/macos/build.py`). Users needing `supgang vault` on macOS
     use `make install` unless the formula is extended in a separate reviewed change.
   - Note: `homebrew-tap#4` already updated the formula test block to assert
     `supgang #{version}`, `Usage: supgang`, and the `doctor` subcommand rather than prose.
3. Verify locally on macOS:

   ```text
   brew install --build-from-source Agenxy/tap/supgang
   brew test Agenxy/tap/supgang
   brew audit --strict Agenxy/tap/supgang
   ```

4. Open and merge the PR on `Agenxy/homebrew-tap`.

## What requires the owner's direct word

No agent may perform or bypass these owner-only decisions:

1. **Version choice (`0.2.0` vs `0.2.0-alpha.22`)**: specifically whether to promote to
   non-prerelease `0.2.0` (which clears Issue #6 on crates.io's landing page) or stay on a
   prerelease.
2. **crates.io Trusted Publishing / initial crate registration**: enabling OIDC Trusted
   Publishing on crates.io for new crates (`supgang-netwatch`, `supgang-portmapper`,
   `supgang-acl`) and approving the GitHub `release` environment deployment.
3. **Rehearsal-to-public go-ahead**: explicit written approval to publish `RELEASE_COMMIT`
   to crates.io, push tag `v<NEW_VERSION>`, publish the GitHub release, and update
   `Agenxy/homebrew-tap`.
4. **Any licence change**: none is part of this release (`Apache-2.0` is preserved for
   Supgang; vendored crates keep their upstream `MIT OR Apache-2.0` licences and notices).
5. **Future production signing ceremonies (separate from this release)**: witnessed 2-of-3
   TUF root/targets key ceremony (`docs/security/secure-updates.md`) and ADR 0007 release
   and code-signing role grants (`docs/architecture/0007-release-and-code-signing-roles.md`).
