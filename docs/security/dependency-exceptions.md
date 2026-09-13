# Dependency identity exceptions

Status: reviewed for 0.2.0-alpha.10 corrective development; live RustSec and cargo-deny gates passed
on 2026-08-27

Supgang denies new duplicate package identities through its typed repository policy. The reviewed
exceptions below are explicit because Rust's general `multiple_crate_versions` lint cannot
distinguish host-only build tooling and unsupported targets from code linked into the released
executable.

## Reviewed MCP implementation dependencies

The MCP server uses `rmcp` 3.1.3, the Apache-2.0 official Rust SDK from the Model Context Protocol
project, with default features disabled and only its `server` feature enabled. HTTP, OAuth, SSE,
client, child-process, and subprocess transport features are absent from the release graph. The
server supplies its own fixed-ceiling standard-I/O transport because the generic SDK reader does not
provide Supgang's required 16 KiB request allocation bound.

`schemars` 1.2.2 is an exact direct pin because Rust derive expansion requires the schema crate to
be directly addressable. It generates JSON Schema 2020-12 for typed results. Both additions use
permissive licences already accepted by `deny.toml`, introduce no new duplicate package identity,
and keep all protocol handling in the existing `supgang` process.

## Reviewed local-router mapping dependencies

`portmapper` 0.19.1 is pinned with default features disabled. Supgang enables only its PCP and
NAT-PMP clients to maintain one UDP lease and react to gateway changes. UPnP is disabled at the
adapter boundary because unauthenticated SSDP can provide an attacker-selected HTTP description
location. The runtime network boundary is therefore the current default gateway; there is no hosted
endpoint, account, telemetry export, or public address lookup. Returned addresses pass Supgang's
scope checks, signed mapping changes are rate-limited, and the result remains unverified until an
authenticated peer independently reports the public socket.

The dependency is isolated behind `router_mapping.rs`. Its unconditional dependency graph still
contains HTTP and XML handling for the disabled UPnP implementation, platform interface discovery,
and code for targets that are not linked into macOS or Linux releases. This dormant code remains a
supply-chain cost and is reviewed even though Supgang never enables its runtime path. Implementing
and maintaining PCP and NAT-PMP lease state inside Supgang would create a separate parsing burden.
Metrics features are disabled, and no tracing subscriber is installed by Supgang.

`spez` 0.1.2 uses the permissive BSD-2-Clause licence, which is allowed for the dependency graph.
The disabled transitive UPnP implementation in `igd-next` brings in exactly `attohttpc` 0.30.1 under
MPL-2.0. MPL-2.0 is allowed only for that exact crate through a cargo-deny package exception; it is
not accepted globally. Supgang does not modify `attohttpc`. A distributed binary must retain the
applicable MPL notice and make that covered source available. Removing the dormant UPnP graph is a
dependency-minimization target. The release lockfile software bill of materials and retained
third-party notices remain a release gate.

### RustSec RUSTSEC-2024-0436

Linux route monitoring brings in `netlink-packet-core` 0.8.2, which uses `paste` 1.0.15 to generate
packet parser names at compile time. RustSec classifies `paste` as unmaintained; the advisory does
not report a vulnerability or unsoundness. `paste` is not in the macOS target graph. The current
`netlink-packet-core` release carries the same explicit advisory exception and considers the stable
macro preferable to an unvetted replacement.

Supgang therefore passes exactly `RUSTSEC-2024-0436` to `cargo audit --ignore` while retaining
`--deny warnings`. Every other vulnerability, unsoundness, unmaintained dependency, or yanked crate
remains fatal. The version and checksum remain fixed by `Cargo.lock`. This exception must be removed
when `netlink-packet-core` replaces `paste`, and it must be reconsidered before any change to the
ignored crate, advisory, or Linux routing dependency path.

`jni-sys` 0.3 and 0.4 occur only under Android support in `netdev`; Android is not a Supgang target.
`thiserror` and `thiserror-impl` 1 remain under that Android JNI path while Supgang and its current
direct dependencies use version 2. Neither duplicate changes the macOS or Linux error boundary.
These exceptions must be removed when the upstream platform graph converges or the router-mapping
adapter changes.

## `syn` 2 and 3

`curve25519-dalek-derive` and `tracing-attributes` currently use `syn` 2. The current releases of
Clap, Serde, futures, schemars, thiserror, and Tokio macros use `syn` 3. Both versions execute only
while compiling procedural macros. Neither is linked into the Supgang executable or processes
Supgang protocol input at runtime.

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

## Windows target package identities

The WebAssembly-only Ring path includes `windows-sys` 0.52 while current filesystem and asynchronous
I/O crates include 0.61 for Windows targets. Router gateway discovery also retains the older
`windows-sys` 0.45 and `windows-targets` 0.42 families beside the current 0.53 line. This duplicates
the architecture packages for AArch64, i686, and x86-64 GNU, GNU LLVM, and MSVC targets. Supgang
currently supports macOS and Linux, so none of these packages is linked into a supported release.
These exceptions keep the every-target lockfile audit explicit and must be removed if Windows support
is added or the upstream graph converges.

## `untrusted` 0.7 and 0.9

Rustls WebPKI and Quinn's WebAssembly-only Ring path use `untrusted` 0.9. AWS-LC-RS retains an
optional Ring-compatibility feature referencing `untrusted` 0.7, so Cargo resolves it into the
lockfile even though Supgang does not enable that feature. The supported-target normal and
build-only graph contains only 0.9.

## `bitflags` 1 and 2

TUF verification uses `tough` 0.24.0 without its HTTP feature. Tough's timestamp implementation
uses `jiff` 0.2.35. Jiff declares an optional embedded-formatting feature through `defmt`, whose
lockfile-only dependency retains `bitflags` 1.3.2. Supgang does not enable that feature: neither
`defmt` nor `bitflags` 1 appears in the normal, build-only, or supported-target executable graph.
Filesystem, platform, and test dependencies use `bitflags` 2.13.1. This exception exists only
because the repository policy audits every identity recorded in `Cargo.lock`; it must be removed if
Jiff stops recording that optional edge or if `bitflags` 1 enters a supported release graph.

## Local macOS owner setup

The separately reviewed `tools/setup_macos.py` automation uses the macOS-owned isolated Python
interpreter for the explicitly approved administrator step. It invokes native `launchctl`,
`codesign`, `security`, and `socketfilterfw` only to register an ordinary-user boot service,
verify the exact installed signature, approve an explicitly identified public owner certificate
for code signing, and allow that runtime in the host firewall. Password entry belongs to `sudo`.
No network request, private-key export, privileged runtime broker, or router change occurs.
The network binary uses the already pinned `plist` 1.10.0 parser only on macOS to validate
bounded service definitions; Linux does not add this runtime dependency.

The policy gate rejects every duplicate package name other than these reviewed identities. Any change to this file
or the allowlist requires security review with a fresh dependency graph.
