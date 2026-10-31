# macOS coupling audit, package 8

Baseline: `0fa19f7`, branch `feat/mcp-server`, 2026-09-21. Line numbers in
the first table refer to that commit so concurrent edits cannot change what
was reviewed. `git grep 'target_os = "macos"' 0fa19f7 -- crates` finds 44
sites, including negative and mixed predicates; the corresponding Linux
query finds 11. A count of predicates alone is not a portability verdict.

Classification:

- **a**: the boundary is generic, but Linux lacks an implementation or parity
  at the named behavior.
- **b**: the interface or orchestration assumes macOS; name the generic
  boundary before adding another platform.
- **c**: a legitimate macOS implementation detail behind a portable boundary,
  or an explicitly macOS-specific operation or test. No Linux imitation is
  needed for that operation. The table names existing counterparts.

This is an audit, not a set of fixes. No listed baseline implementation is
changed by package 8.

## Every baseline predicate mentioning macOS

Paths below are relative to `crates/`. Multiple line numbers enumerate every
site in that row, including imports and tests, rather than sampling one.

| File and lines at baseline | Class | Finding and next action |
| --- | --- | --- |
| `supgang-acl/src/lib.rs:23` | c | Descriptor ACL implementation; the same `reject_non_owner_grants` and `clear_inherited_acl` boundary has a Linux xattr implementation at 125. |
| `supgang-acl/src/lib.rs:169` | a | Explicit compile refusal on all other platforms. Boundary is suitable, but a third platform needs its descriptor ACL implementation. Linux already exists. |
| `supgang-acl/src/lib.rs:174,183,220,230,240` | c | Imports, chmod helper, allow-ACL refusal and deny-only tests for macOS ACL semantics. Linux does not have those same deny-only semantics; Linux-specific ACL adversarial coverage is still worth adding. |
| `supgang-quality/src/main.rs:135` | c | Chooses safe temporary storage for the test gate: macOS per-user temp versus Linux owner cache. This accounts for the platforms' different temporary-directory ancestors. |
| `supgang/Cargo.toml:60` | c | Gates `plist` to its launchd consumers. No plist dependency is imposed on Linux. |
| `supgang/src/control.rs:483,498` | c | macOS/BSD `getpeereid` client and server credential checks. Linux has peer-credential implementations at 460 and 471 under the same control boundary. |
| `supgang/src/platform_service.rs:19,63` | a | System-boot module and approval-required error: the generic service operations exist, but owner-approved boot persistence is implemented only for macOS. Linux currently uses a per-user systemd unit, not equivalent privileged boot setup. |
| `supgang/src/platform_service.rs:90` | c | A diagnostic for a missing macOS GUI service domain. Linux has no Aqua domain to diagnose. |
| `supgang/src/platform_service.rs:110,129,337` | c | Dispatch for `perform`, `preflight_restart` and the macOS module. Linux implements the same operations in the module beginning at 340. This is the model for platform separation. |
| `supgang/src/platform_service.rs:148,155` | c | Owner-home lookup uses the account database on macOS and validated HOME elsewhere. No macOS type escapes this path-returning boundary; review environment/account parity separately. |
| `supgang/src/platform_service/definition.rs:20,50,172` | c | launchd XML renderer, escaping, and test. The same file has a systemd renderer and escaping tests, executable even on macOS. |
| `supgang/src/platform_service/executable.rs:42,44` | c | Native install directories selected behind `installed_path`: Application Support versus `.local/lib`. Copies and validation share one implementation. |
| `supgang/src/storage.rs:159,166` | c | Default state location: Application Support versus XDG state/home. Both return a path through the same function. |
| `supgang/src/storage/path_safety.rs:116` | a | Ancestor validation is generic, but the adversarial ACL ancestor test is macOS-only. Add real Linux ACL/xattr ancestor tests without changing storage's interface. |
| `supgang/src/update/executable.rs:3,11,18` | c | Process import, Mach-O magic and unsupported-platform refusal. Linux ELF validation exists at 16. Another OS needs its executable format; no Mach-O type is public. |
| `supgang/src/update/executable.rs:49,55,61,74` | b | Generic function names hide a macOS designated-requirement policy; non-macOS functions unconditionally succeed because there is no codesign. Define a platform code-identity capability/result and state Linux policy explicitly, retaining independent TUF authorization. Do not invent an Apple-signature equivalent for Linux. |
| `supgang/src/update/executable.rs:90,121,128` | c | Parsing designated requirements, stdout/stderr text and codesign tests are intrinsically macOS details. Keep them under the platform code-identity implementation when the preceding boundary is made explicit. |
| `supgang/src/update/lifecycle.rs:431,434,485,517` | c | Test imports and per-platform candidate fixtures: macOS signs Mach-O; Linux appends a marker to its fixture. Shared lifecycle acceptance is tested on both. |
| `supgang/src/update/tests.rs:12,57,89,686` | c | Codesign import, fixture-signing variants and selection of a runnable fixture. Linux uses the current test executable; no production API inherits these details. |

## Coupling outside those predicates

| Site | Class | Finding and next action |
| --- | --- | --- |
| `tools/setup_fleet.py:71-112` | b | A generically named fleet tool selects `setup_macos.py`, `/Users`, a macOS Python path, owner signing certificates, and Mac-specific diagnostics for both ends. Name a platform setup interface and select its implementation for each peer. Do not infer peer OS from this host. |
| `tools/setup_macos.py` and `tools/test_setup_macos.py` | c | Explicit macOS owner setup: LaunchDaemons, platform trust, local code identity and firewall. These files should remain macOS-specific under a generic fleet setup interface. Their capabilities need an explicit Linux answer there. |
| `crates/supgang/src/platform_service/system_boot.rs` | a | Generic lifecycle result, macOS-only boot implementation. Name boot-persistence availability separately from login service availability; Linux user units alone do not close this gap. |
| `crates/supgang/src/platform_service/macos.rs` | c | launchctl/Aqua/system domain implementation under the shared service API. |
| `tools/probe_gateway.py:22-34` | c | Generic selected-gateway result with macOS route and Linux iproute2 implementations. No missing Linux path. |
| `Makefile:13-28` | c | Optional owner-selected macOS codesign step. Cargo install also works on Linux. This existing signing option is not a custody prerequisite. |
| `.github/workflows/ci.yml`, `deny.toml` | c | macOS and Linux targets are both explicit. Swift helper building and hardware acceptance remain separate from this Rust matrix. |
| Service executable copies and update slots | a | Generic lifecycle currently copies one executable, with no optional-provider companion manifest. A sibling helper installed beside the foreground CLI does not automatically follow a service or update slot. This package reports missing helpers honestly; companion distribution needs a portable packaging boundary before live hardware integration. |

## Package 8 and concurrent additions

The new `device_key/mod.rs` gates the helper and Secure Enclave provider on
macOS and TPM provider on Linux. `custody.rs` selects provider availability;
the tests assert platform-specific rows. These are **c**: the generic
`CustodyProvider` and `SealedKey` exist first, and neither public consumer
requires a macOS type. `tpm2.rs` is **a**, explicitly `NotBuilt`. SwiftPM and
`platforms/macos/build.py` are **c**, named as macOS implementations, with
an explicit wrong-platform refusal and no Cargo build hook.

Concurrent work added `crates/supgang-cli/build.rs`,
`crates/supgang-cli/macos/Info.plist.in` and
`crates/supgang-cli/tests/product_identity.rs` during this audit. They embed
and check macOS product identity, **c**, outside this package. The build hook
does not build the custody helper. Concurrent transport, MCP, plist rendering,
trust-profile and transaction edits are not package 8 changes.

## Existing rule conflicts

`unsafe_code = "forbid"` is the workspace lint, and all new custody Rust
inherits it. The existing `supgang-acl` crate does **not** inherit workspace
lints; it uses FFI on macOS and Linux, and the quality tool explicitly
permits that one source file. Therefore the requested literal workspace-wide
no-FFI property is not true at baseline or after package 8. Removing that
exception needs a separate reviewed descriptor-security design; replacing
ACL checks with mode checks would weaken a security property and is not an
acceptable shortcut. This report does not claim that gate has been met.

Priority for the next package: explicit platform setup and boot capabilities,
fleet setup dispatch, platform code-identity policy, companion-artifact
lifecycle, Linux ACL adversarial coverage, and a resolution of the existing
ACL unsafe exception. Preserve `platform_service`'s shared operation model.
