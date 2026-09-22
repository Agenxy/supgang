# Package 8: portable hardware custody

Baseline: clean `feat/mcp-server` at `0fa19f7`. Work is left uncommitted for
review. This package implements the custody primitive and reports capability
limits; it does not claim completed live hardware enrollment.

The decision follows the repository's linked
[values](https://github.com/Agenxy/.github/blob/main/VALUES.md) and
[engineering standards](https://github.com/Agenxy/.github/blob/main/ENGINEERING.md),
with the owner's explicit safe-Rust/out-of-process exception for custody.
Remap's `platforms/macos/Package.swift`, native `Sources` layout and
`tools/remap_macos_install.py` SwiftPM build/product lookup were read first.
No crate, lockfile or dependency version was added or changed by package 8.

## Result

`CustodyProvider` creates or restores an opaque `DeviceSigner`. Every platform
reports the fixed matrix: Secure Enclave, TPM 2.0, security key, file.
Unavailability is typed. Hardware requests cannot become file requests.
File custody refuses enforced presence. `SealedKey` stores a bounded,
versioned canonical CBOR record as 0600 beside the identity and rejects
cross-provider loads. The signer has an optional restore-record method,
with a default refusal so existing implementers keep compiling.

The macOS provider invokes the named sibling Swift helper through bounded
nonblocking pipes, with one in-flight operation, no queue, a deadline and
child cleanup. Blobs and digests never enter argv. Rust normalizes low-s and
verifies helper signatures. The helper uses CryptoKit sealed blobs, with no
keychain item, restricted entitlement, provisioning profile or developer
account. The API reports owner-enrolled hardware custody, never attestation.

Linux TPM 2.0 is declared as `NotBuilt`; its module documents the crate,
native stack, device access, wrapped-child record and PIN/presence work.
Security keys are also `NotBuilt`. Doctor keeps `supgang.doctor/v1`, adds
the typed `custody` object, and keeps warning that the actual live identity
is file-held. A separate P-256 record does not relabel that Ed25519 identity.

## Every package file

All paths are repository-relative. Other working-tree edits are listed
separately below.

| File | Change |
| --- | --- |
| `crates/supgang/src/device_key.rs` | Moved to `device_key/mod.rs`; existing public paths remain valid. |
| `crates/supgang/src/device_key/mod.rs` | Modules, typed provider refusal, default restore-record method, file record export; random-scalar generation bounded to 32 draws. |
| `crates/supgang/src/device_key/custody.rs` | Generic provider trait, presence policy, kind, availability, typed reasons and complete capability matrix. |
| `crates/supgang/src/device_key/file.rs` | Explicit file provider with presence refusal and kind checks. |
| `crates/supgang/src/device_key/sealed.rs` | Canonical CBOR, version/kind/size validation, redacted Debug, zeroization and owner-only persistence. |
| `crates/supgang/src/device_key/signature.rs` | Portable raw/DER conversion and low-s normalization. |
| `crates/supgang/src/device_key/secure_enclave.rs` | macOS provider, opaque signer and ignored real-helper tests. |
| `crates/supgang/src/device_key/helper.rs` | Named sibling lookup, strict versioned framing, bounded pipes, concurrency refusal and timeout cleanup. |
| `crates/supgang/src/device_key/helper/tests.rs` | Protocol/refusal tests and real process time/output bounds. |
| `crates/supgang/src/device_key/tpm2.rs` | Declared Linux provider with `NotBuilt` and implementation requirements. |
| `crates/supgang/src/device_key/custody_tests.rs` | Portable capability, storage, signature and generic proof tests. |
| `crates/supgang/src/authority.rs` | `CertifiedKey::prove_p256` accepts unsized trait objects. The request called this `Possession::prove_p256`; the actual baseline API is on `CertifiedKey`. |
| `crates/supgang/src/threshold/control_auth.rs` | `Proof::sign` accepts unsized trait objects. |
| `crates/supgang/src/cli.rs` | Actual live custody, additive JSON field and human section. |
| `crates/supgang/src/cli/doctor.rs` | Matrix rendering, typed JSON and unreadable-identity test. |
| `crates/supgang/src/cli/tests.rs` | Existing init/doctor flow additionally checks file custody and four capability rows. |
| `platforms/macos/Package.swift` | Optional named SwiftPM executable, Swift 6 mode, compiler warnings as errors. |
| `platforms/macos/Sources/SupgangSecureEnclave/main.swift` | CryptoKit operations, strict hex protocol, fresh presence contexts, safe numeric refusals. |
| `platforms/macos/build.py` | Explicit uv/PEP 723 build and sibling placement; no Cargo-to-Swift build hook. |
| `platforms/macos/test_protocol.py` | Hardware-free tests of the actual compiled helper's framing and argv refusal. |
| `platforms/macos/README.md` | Build, install, wire contract, tests and policy/distribution limits. |
| `docs/architecture/0003-hardware-held-keys-and-certified-subordinates.md` | Tenth draft, measured keychain rejection, generic boundary, CryptoKit decision and remaining policy work. |
| `docs/architecture/roadmap-sovereign-trust.md` | Hardware-custody row states implemented primitive and unimplemented providers/integration. |
| `docs/architecture/macos-coupling-package-8.md` | Every baseline macOS predicate plus coupling outside cfgs, classified a/b/c. |
| `docs/validation/2026-09-21-package-8-custody.md` | This report. |

## Every added test

| Test | Evidence it is intended to establish |
| --- | --- |
| `capability_matrix_is_complete_ordered_and_honest_on_each_platform` | All four kinds once, fixed order, correct platform and not-built answers. |
| `sealed_records_round_trip_and_refuse_noncanonical_truncated_and_foreign_input` | Every kind round-trips; every truncated envelope, trailing bytes, nonminimal CBOR, unknown version/kind, empty/oversized record and wrong provider are refused; short file scalar and unsupported presence are refused. |
| `sealed_file_is_owner_only_nonreplacing_and_restores_the_same_signer` | 0600 persistence beside identity, no overwrite, restored public key equality, insecure mode refusal. |
| `provider_signatures_normalize_high_s_pad_short_integers_and_refuse_malformed_input` | Raw and DER low/high-s conversion, short-integer padding, invalid lengths/ranges/DER refused before DeviceSignature construction. |
| `generic_provider_proves_possession_and_threshold_control_on_every_platform` | Independent provider/signer test double through boxed trait objects, real certificate possession, 2-of-3 control proof, changed channel binding refused. No hardware or macOS dependency. |
| `protocol_refusals_remain_distinct_and_framing_is_strict` | No hardware, owner cancellation and numeric refusal stay distinct; wrong version, extra line, CRLF and missing LF fail. |
| `pipe_transport_bounds_time_and_output_and_detects_missing_helper` | Native tee/yes/sleep processes exercise round-trip, output bound, missing executable and timeout without shells or hardware. |
| `custody_json_is_additive_and_does_not_guess_at_an_unreadable_identity` | Typed file provider/four rows, null on unreadable identity, honest human rendering. |
| `real_helper_restores_and_signs` | Ignored by default; real enclave create, CBOR restore, sign, verify and truncated provider-blob refusal. Requires helper beside the test executable. |
| `real_helper_requires_presence` | Same integration with owner presence; ignored by default and requires the owner at the Mac. |
| `platforms/macos/test_protocol.py` | Actual product probe, 11 malformed requests and argv refusal, no keys created. |

The existing CLI init/doctor test was extended, not duplicated. The existing
six device-key tests remain in `mod.rs`.

## Validation

All Cargo operations used the existing locked dependencies with offline mode.
Toolchain: Rust/Cargo 1.97.1; installed Apple Swift 6.4 from Xcode 27 beta 5.
No toolchain was installed or upgraded. Results are evidence for this
restricted macOS execution environment, not a Linux or physical-fleet pass.

| Command or check | Result |
| --- | --- |
| `CARGO_NET_OFFLINE=true make check` | Failed, exit 2. Policy, formatting, workspace check and all-target/all-feature Clippy passed. Core tests: **339 passed, 22 failed, 2 ignored**. All 22 failures returned OS error 1, `Operation not permitted`, in existing socket/network tests. No custody test failed. Log: `target/package8-make-check.log`. |
| `target/debug/supgang-quality policy` | Passed, including the final documentation. `make check` invokes `supgang-quality all`; its final documentation/CLI acceptance phases were not reached after the test failure. |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed again after the final custody changes. Log: `target/package8-final-clippy.log`. |
| `cargo test --locked -p supgang-core device_key` | **13 passed, 2 ignored**, final run. Log: `target/package8-device-key-final.log`. |
| `cargo test --locked -p supgang-core custody` | **6 passed**, including doctor serialization and the generic proof. Log: `target/package8-custody-tests.log`. |
| Exact `cli::tests::json_lifecycle_has_stable_schemas_and_no_secret` test | Passed with the new custody assertions. Log: `target/package8-doctor-cli.log`. |
| `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked` | Passed separately. Log: `target/package8-doc.log`. |
| `cargo fmt --all -- --check`; `git diff --check` | Passed. |
| `uv run --offline --script platforms/macos/build.py --beside <test-executable>` | Swift release build passed with compiler warnings as errors. No entitlement or signing step was used by the build helper. |
| `uv run --offline --script platforms/macos/test_protocol.py --helper <helper>` | Passed: product probe, 11 malformed requests, argv refusal. No keys created. |
| Ignored `real_helper_restores_and_signs`, explicitly attempted | Failed its availability assertion. First attempt timed out on probe; a subsequent actual probe and test reported **Unavailable(NoHardware)**. No real create/restore/sign acceptance claim follows. |
| Ignored `real_helper_requires_presence` | Not run: the helper reports no enclave available to this environment. No owner prompt or cancellation test was claimed. |
| Linux `cargo check --locked -p supgang-core --all-targets --target aarch64-unknown-linux-gnu` | Could not finish. Homebrew Rust lacked the target stdlib; selecting the installed rustup 1.97.1 compiler reached `aws-lc-sys`, then failed because `aarch64-linux-gnu-gcc` is absent. No Linux execution or build pass. |
| Normal `make install` | Failed opening `~/.local/.crates.toml`: `Operation not permitted`. Log: `target/package8-install.log`. |
| `make install INSTALL_ROOT=/private/tmp/supgang-package8-install` | Passed, including a rebuild after final custody source edits. This is a staged install, not normal-path installation acceptance. Log: `target/package8-staged-install-final.log`. |

The full-gate failure families were local control (2), service-manager socket
handoff (1), rendezvous (1), live service/control/reconciliation (10), session
authentication (3), transport pinning (1), update-over-QUIC (1), and update
wire/admission (3). The retained log names every failed test and its actual
permission error. No test or gate was relaxed to hide these failures.

From `/private/tmp`, with only the staged install prepended to PATH,
`command -v supgang` resolved to
`/private/tmp/supgang-package8-install/bin/supgang`; `supgang --help` passed.
The installed binary and `target/release/supgang` both had SHA-256:

```text
812538db6eb35ea4a4f4221335e53474006ac7a9533ff948c11f66f20c9a75e3
```

An isolated temporary identity was initialized and removed for each smoke
check. `supgang --json doctor` and human doctor passed, reporting actual file
custody. Without a sibling helper the enclave row was `HelperMissing`; after
the build tool installed the sibling it was `NoHardware`, exactly matching
the actual helper's probe. TPM 2.0 was `WrongPlatform`, security key `NotBuilt`,
file `Ready`. Only custody diagnostics were displayed; generated identity
material and identifiers were not logged. No existing identity was migrated.

Initial iteration failures were corrected and rerun: a storage-test fixture
needed the required 0700 directory mode, and Clippy required test-module
placement, documentation formatting and constant-function cleanup. SwiftPM
initially tried unwritable user caches and a denied dSYM operation; the build
tool now uses workspace-local caches and a release build without debug
information. A deprecated native-build-engine experiment was discarded; the
final helper uses SwiftPM's default engine. None of these changes weakens
warnings or a security check.

Not run: successful real enclave signing, presence/cancellation against the
owner's hardware, Linux native tests, physical-peer installation or cross-host
acceptance, and a completed full quality gate. Normal-path installation also
remains blocked. The owner's earlier successful unsigned CryptoKit measurements
are recorded as supplied evidence in ADR 0003, not as results reproduced here.

## Audit and remaining ADR requirements

The complete [macOS coupling audit](../architecture/macos-coupling-package-8.md)
enumerates all 44 baseline macOS sites against 11 Linux sites and includes
fleet/setup coupling outside Rust predicates. No audit fix is folded into
this package.

ADR 0003 still requires typed authority operations that validate and display
the transaction, durable revision reservation, atomic manifest publication,
live P-256 enrollment and publication-key separation. The requested low-level
digest signer does not satisfy those requirements. Touch ID gates key use;
it does not demonstrate approval of a particular transaction. FROST share
sealing, TPM 2.0, security keys, iOS membership and whole-machine rollback
protection are not implemented. Service and update copies still distribute
one executable and need explicit optional-helper packaging before live use.

The workspace's pre-existing `supgang-acl` FFI exception remains. The new
custody code inherits `unsafe_code = "forbid"`, but the literal workspace-wide
no-FFI requirement cannot be claimed. Its resolution belongs to the separately
reviewed ACL boundary, not removal of existing ACL checks. No independent
reviewer verdict was obtained in this offline run.

Concurrent edits observed and preserved: `crates/supgang/src/mcp.rs`,
`platform_service/definition.rs`, `transport.rs`, `trust_profile.rs`,
`update/transaction.rs`, plus `crates/supgang-cli/build.rs`,
`crates/supgang-cli/macos/Info.plist.in` and
`crates/supgang-cli/tests/product_identity.rs`. Later concurrent additions
also changed `CHANGELOG.md`, `crates/supgang/src/cli_peer.rs`,
`crates/supgang/src/transport_storage.rs`, and added
`crates/supgang/src/transport_storage/migration.rs` and
`docs/product-identity.md`. They are not package 8 work;
workspace gate results include the shared working tree at invocation time.
