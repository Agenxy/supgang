# Dependency identity exceptions

Status: reviewed for 0.1.0 development

Supgang denies new duplicate package identities through its typed repository policy. Two temporary
exceptions are explicit because Rust's general `multiple_crate_versions` lint cannot distinguish
host-only build tooling from code linked into the released executable.

## `syn` 2 and 3

`curve25519-dalek-derive` currently uses `syn` 2. The current releases of Clap, Serde, and thiserror
use `syn` 3. Both versions execute only while compiling procedural macros. Neither is linked into
the Supgang executable or processes Supgang protocol input at runtime.

Removing Ed25519 Dalek to collapse this build-time duplicate would replace the selected,
well-reviewed signature implementation for a non-security reason. The exception must be removed
when the upstream derivation stack converges without changing cryptographic behavior.

## `getrandom` 0.2, 0.3, and 0.4

Supgang uses `getrandom` 0.4 directly for operating-system randomness. Proptest's test-only random
stack currently uses `getrandom` 0.3. Quinn's WebAssembly-only Ring path selects `getrandom` 0.2
when the dependency graph is inspected for every target. Neither older identity is linked into the
macOS or Linux release build and neither generates Supgang keys.

The `getrandom` lines also select `r-efi` 5 and 6 for the UEFI target. `r-efi` is not compiled
for either supported target. It disappears with the associated `getrandom` exception.

## `rand` and `rand_core` 0.9 and 0.10

Quinn uses the current `rand` and `rand_core` 0.10 line for QUIC connection identifiers and protocol
randomness. Proptest uses the preceding 0.9 line only in tests. A normal and build-only dependency
graph for the release binary contains one version of each package.

## `windows-sys` 0.52 and 0.61

The WebAssembly-only Ring path includes `windows-sys` 0.52 while current filesystem and asynchronous
I/O crates include 0.61 for Windows targets. Supgang currently supports macOS and Linux, so neither
package is linked into a supported release. This exception exists so the every-target lockfile audit
continues to expose unexpected target-specific dependencies.

## `untrusted` 0.7 and 0.9

Rustls WebPKI and Quinn's WebAssembly-only Ring path use `untrusted` 0.9. AWS-LC-RS retains an
optional Ring-compatibility feature referencing `untrusted` 0.7, so Cargo resolves it into the
lockfile even though Supgang does not enable that feature. The supported-target normal and
build-only graph contains only 0.9.

The policy gate rejects every duplicate package name other than these reviewed identities. Any change to this file
or the allowlist requires security review with a fresh dependency graph.
