# Supgang installation conformance

Repository-local assessment of [the Agenxy installation discipline](agenxy-installation.md).
The canonical specification is unchanged. This assessment covers the native service installer,
the administrator-owned macOS boot definition and its owner setup helper.

## Numbered rules

| Rule | Verdict | Code and evidence |
|---|---|---|
| 1. Guarded directories | Fixed | `executable::installed_path` validates the canonical manager destination using `guarded::validate`. On macOS this is `~/Library/Application Support/org.agenxy.supgang/bin/supgang`. `macos::install` also rejects guarded state and endpoint paths. The diagnostic names the guarded directory and the supported location. |
| 2. Fresh binary inode | Conforms | `executable::copy_atomic` uses `create_new`, mode 0700, bounded descriptor copying, file sync, rename and parent sync. It never overwrites the existing inode. The regression retains an open descriptor to the old binary and verifies both inodes and contents. Cleanup now also covers ACL and mode failures. |
| 3. Teardown race | Fixed | `macos::bootout` calls `wait_until_gone` on the exact launchd target before any bootstrap. The socket wait remains a separate check. Manager calls have bounded output and a five-second deadline; the removal poll has a five-second deadline, with at most one in-flight manager call beyond it. `setup_macos.bootout` likewise polls the exact target and fails after its bounded wait, including rollback paths. Systemd stop/restart operations remain synchronous; explicit stop paths also poll manager state. |
| 4. Atomic deterministic definitions | Fixed | `write_atomic` writes a mode-0600 exclusive temporary file in the destination directory, syncs, renames and syncs the parent. Cleanup now includes ACL failures. `setup_macos.write_definition` now stages in the destination directory, retaining mode 0644 for the root-owned definition. Both Rust renderers have literal byte fixtures and repeat-render equality tests. |
| 5. Crate-root assets | Conforms | Renderer fixtures live under `crates/supgang/src/platform_service/fixtures`; the MCP mark lives in `crates/supgang/assets`. `supgang-quality::acceptance::run` runs verified `cargo package` for all three publishable crates: `supgang-acl`, `supgang-core` and `supgang`. Packaging execution remains an acceptance requirement. |
| 6. Older running service | Fixed, with a limit | `control::request_observed` retains kernel socket-peer evidence. `observation::version_note`, `cli_background` and `cli_control::status` report client and running versions plus `supgang service refresh`. Missing legacy versions are explicitly unknown. `ControlError::InvalidResponse` names possible incompatibility and the diagnostic/remedy instead of exposing a JSON parse failure. There is no per-operation capability negotiation in the existing local protocol; an undecodable reply cannot establish the remote build's exact version. |

Contrary to the original audit assumption, `install_current` copies the running executable
to protected application storage. It does not install a definition pointing at `current_exe`.
A source checkout on Desktop therefore remains usable for installation: the manager program
is the protected copy. The refusal applies to paths the background process must use. Existing
owner-directory and symlink validation remains in force.

## Positive duties and remaining limits

| Duty | Verdict | Code and remaining work |
|---|---|---|
| Installed versus running identity | Cannot yet fully prove attribution | `Observation` reports the protected installed path, definition path, manager program when available, manager PID and kernel-observed socket PID separately. `classify` distinguishes an answering socket without an active manager. The OS parent PID distinguishes a supervisor child from an unrelated process even while the manager is active. If parent evidence is unavailable it reports `different-pids-ownership-unverified`. Comparing the actual loaded executable to installed bytes still needs OS executable evidence; equal version strings and paths cannot prove it. Status is a point-in-time observation, not an atomic process snapshot. |
| Persistent manager state | Fixed | `launchd_disabled` parses the exact owner's label in `print-disabled`, accepting both boolean and enabled/disabled spellings. `observe_systemd` reports `UnitFileState` and `loginctl show-user` lingering. Unavailable lingering is null, not false. Definition files alone are never treated as enablement evidence. |
| No incidental persistent manager changes | Fixed for ordinary service operations | `macos::bootstrap` no longer enables the job and refuses an owner-disabled label. Linux install starts the unit without enabling it or changing lingering; masked units are refused. To opt into Linux login startup, the owner runs `systemctl --user enable supgang.service`. Uninstall removes the unit's enablement as part of the explicitly requested removal. The separate privileged helper explicitly plans boot enablement or persistent disablement for owner approval. |
| Display identities | Conforms | `definition::render_launchd` fixes `org.agenxy.supgang`; `boot_definition` adds the owner UID. `render_systemd` sets the unit description and `SyslogIdentifier=supgang`. Both renderers explicitly discard stdout/stderr; status names that destination instead of implying an empty log file proves readiness. |
| Daemon configuration validation before install | Fixed for static configuration; cannot yet guarantee every startup condition | `validate_state` replays protected identity/journal, refuses local revocation, and validates settings and profile; `validated_endpoints` applies the daemon's `EndpointConfig::read`; `validate_policy` rejects fixed endpoints plus router mapping. Renderers reject relative/non-Unicode paths, control characters and invalid XML characters. Dynamic interface discovery, socket availability, journal/runtime races and transport-key availability still require actual startup and its bounded readiness check. A fully shared read-only daemon preflight is not yet implemented. |
| Minimal privilege and exact approval | Conforms within the existing boot setup boundary | `system_boot::perform` refuses install/stop/uninstall as `BootApprovalRequired`. Runtime work remains owner-only. `tools/setup_macos.py::main` presents the explicit action before elevation; `validate_installed` and `approve_runtime` verify the fixed owner artifact and signing identity. The privileged subprocess deliberately uses isolated system Python, rather than resolving an owner-writable interpreter as root. |

## Tests and static enforcement

Both renderers and all pure boot-definition, guarded-path, parser and status tests compile
under `cfg(test)` on macOS and Linux. The boot definition's pure validation moved to
`boot_definition.rs`; runtime behavior and the Action/Report dispatch remain in place.
The added dependency declarations use already locked, locally cached crates: `plist` for cross-platform boot-definition tests and `syn` 2.0.119 for syntax-aware gate inspection. Cargo.lock adds only the quality crate dependency edge.

`supgang-quality::installation` enforces the existing macOS/Linux CI matrix, keeps the
specification and this local record mandatory, and rejects OS-only guards hiding the pure
tests. It rejects common truncating filesystem calls in the Rust installer boundary and
write-enabled `OpenOptions` chains that lack `create_new`. This is conservative Rust syntax
inspection, not whole-program dataflow analysis. Test-only modules are excluded without
skipping later production code; a regression test enforces that distinction. Aliased APIs, wrappers outside that
boundary, external package-manager behavior, OS code-signature caches, actual manager
teardown and process ancestry require review or execution. They cannot be proved by this
static gate. Ordinary source scans also enforce the uv/PEP 723 helper format, prohibit
explicit bash executables and scan Python/workflow prose for forbidden punctuation.

The full gate still runs workspace tests and verified packaging. CI uses both macOS and
Linux, with `sh` as the command runner and uv for the Python regression entry point.
Configuration of CI is not evidence that a hosted run passed.

## Validation for this change

The following checks were run on macOS in the restricted workspace sandbox. No gate
was weakened, and blocked checks were not skipped to obtain a passing full gate.

| Command or check | Result |
|---|---|
| `CARGO_NET_OFFLINE=true make check` (runs `cargo run --locked --package supgang-quality -- all`) | Policy, formatting, workspace/all-targets check and warnings-fatal Clippy passed. Core tests: 359 passed, 22 failed with socket permission errors, 2 pre-existing ignored. CLI product-identity tests: 2 passed. ACL tests: 3 passed. The full gate exits nonzero. |
| Final `cargo clippy --offline --locked --workspace --all-targets --all-features -- -D warnings` | Passed after the final source changes. |
| Final `cargo test --offline --locked --package supgang-core platform_service --lib` | 23 passed, including all 14 added installer tests. The existing `stop_wait_retries_a_socket_closing_during_handoff` fails with `Operation not permitted` while binding its Unix socket. |
| `cargo test --offline --locked --package supgang-quality` | All 4 passed, including the 3 new enforcement regressions. |
| `UV_CACHE_DIR="$TMPDIR/supgang-uv-cache" uv run --offline --script tools/check.py` | 31 passed, 4 failed creating existing protected fixtures directly under the home directory. All 4 added setup tests also passed in an explicit focused run. Failed existing tests: `test_acl_writable_supervisor_or_parent_is_rejected_before_execution`, `test_bounded_reads_reject_symlinks_fifos_and_writable_files`, `test_fresh_artifact_acl_is_cleared_before_use`, `test_setup_lock_rejects_replaceable_parent_and_retains_exclusion`. |
| `RUSTDOCFLAGS='-D warnings' cargo doc --offline --locked --workspace --no-deps` | Passed. |
| `cargo package --offline --locked --allow-dirty --package supgang-acl --package supgang-core --package supgang` | All 3 archives created; ACL verified. Core verification stopped at Cargo's temporary-registry error: `no hash listed for supgang-acl v0.2.0-alpha.10`. No successful core/CLI package verification is claimed. |
| Same package command without `--offline` | Failed resolving `index.crates.io`; the sandbox has no usable registry network access. |
| `cargo check --offline --locked --package supgang-core --tests --target x86_64-unknown-linux-gnu` | Blocked: the Linux `core`/`std` target libraries are not installed. Linux execution and hosted CI remain unverified. |
| `make install` | Blocked opening `~/.local/.crates.toml` with `Operation not permitted`. The normal installed artifact was not replaced. |
| Existing installation, checked from `/private/tmp` | `command -v supgang` resolves `~/.local/bin/supgang`; SHA-256 is `c49b2020cc3e1e5c77acf5b447c75e89f62ebdaaeba42217c61eb575f7c154f8`. Help succeeds. `supgang --json doctor` exits 3 because its control socket is inaccessible. These are observations of the pre-existing artifact, not acceptance of this change. |
| `cargo build --offline --locked --package supgang`, then debug help/status outside the repository | Passed. Read-only service status successfully parsed the real launchd program, PID and enablement; the sandbox denied socket access, which is reported as unverified readiness/version rather than a version mismatch. No install, refresh, stop, start or restart of the live service was performed. |

The final debug binary's SHA-256 is
`baa4036fa897ea20c3da1d90c58462935b71f51da98c2048b2aa38c019981c69`.
It is a review artifact, not an installed release. Live lifecycle/teardown, privileged boot
setup, Linux manager behavior and physical fleet acceptance still require an environment
with the corresponding permissions. The CI matrix is configured, but no hosted run was
launched. The complete installation milestone is therefore not accepted yet.

## Changed files

The starting commit was `f93445d8b11a90dffdc64d00c9455579448a2d9c` on `feat/mcp-server`.
The supplied canonical specification was already untracked on arrival and was left byte-for-byte unchanged.
No commit, push, privilege change or live service mutation was performed.

- `.github/workflows/ci.yml`
- `.github/workflows/publish.yml`
- `Cargo.lock`
- `README.md`
- `crates/supgang-quality/Cargo.toml`
- `crates/supgang-quality/src/acceptance.rs`
- `crates/supgang-quality/src/installation.rs`
- `crates/supgang-quality/src/main.rs`
- `crates/supgang/Cargo.toml`
- `crates/supgang/src/cli_background.rs`
- `crates/supgang/src/cli_control/status.rs`
- `crates/supgang/src/control.rs`
- `crates/supgang/src/platform_service.rs`
- `crates/supgang/src/platform_service/boot_definition.rs`
- `crates/supgang/src/platform_service/definition.rs`
- `crates/supgang/src/platform_service/definition_tests.rs`
- `crates/supgang/src/platform_service/executable.rs`
- `crates/supgang/src/platform_service/fixtures/launchd.plist`
- `crates/supgang/src/platform_service/fixtures/systemd.service`
- `crates/supgang/src/platform_service/guarded.rs`
- `crates/supgang/src/platform_service/macos.rs`
- `crates/supgang/src/platform_service/observation.rs`
- `crates/supgang/src/platform_service/observation/tests.rs`
- `crates/supgang/src/platform_service/system_boot.rs`
- `crates/supgang/src/platform_service/tests.rs`
- `docs/architecture/supgang-installation-conformance.md`
- `tools/check.py`
- `tools/setup_macos.py`
- `tools/test_k7_netlab.py`
- `tools/test_setup_macos.py`

## Added regression tests

21 named tests were added. The original launchd renderer test and both original
boot-definition tests are now reachable on Linux as well as macOS.

- `gate_rejects_detectable_in_place_installer_writes` in `crates/supgang-quality/src/installation.rs`.
- `gate_accepts_fresh_file_and_rename_installation` in `crates/supgang-quality/src/installation.rs`.
- `gate_scans_production_after_test_modules_and_ignores_test_only_copies` in `crates/supgang-quality/src/installation.rs`.
- `each_renderer_is_byte_exact_and_deterministic` in `crates/supgang/src/platform_service/definition_tests.rs`.
- `every_renderer_refuses_controls_relative_paths_and_non_unicode_in_every_argument` in `crates/supgang/src/platform_service/definition_tests.rs`.
- `both_renderers_refuse_fixed_endpoints_with_router_mapping_before_installation` in `crates/supgang/src/platform_service/definition_tests.rs`.
- `replacing_an_installed_binary_uses_a_fresh_inode_and_keeps_the_old_open_file` in `crates/supgang/src/platform_service/executable.rs`.
- `a_program_in_a_directory_the_platform_guards_is_refused_by_name` in `crates/supgang/src/platform_service/guarded.rs`.
- `launchd_status_reads_only_its_own_fields_not_nested_pids_or_states` in `crates/supgang/src/platform_service/observation/tests.rs`.
- `launchd_disabled_parser_uses_the_exact_owner_label` in `crates/supgang/src/platform_service/observation/tests.rs`.
- `systemd_status_reads_exact_flat_properties_not_embedded_fields` in `crates/supgang/src/platform_service/observation/tests.rs`.
- `status_distinguishes_installed_stopped_foreign_running_and_owner_disabled` in `crates/supgang/src/platform_service/observation/tests.rs`.
- `supervisor_and_payload_pids_are_not_falsely_reported_as_the_same_process` in `crates/supgang/src/platform_service/observation/tests.rs`.
- `an_older_or_unversioned_service_names_the_mismatch_and_refresh_remedy` in `crates/supgang/src/platform_service/observation/tests.rs`.
- `definition_replacement_is_atomic_mode_0600_and_leaves_no_temporary_file` in `crates/supgang/src/platform_service/tests.rs`.
- `bootout_waits_for_manager_removal_even_after_the_socket_is_gone` in `crates/supgang/src/platform_service/tests.rs`.
- `bootout_that_never_disappears_fails_within_its_bound` in `crates/supgang/src/platform_service/tests.rs`.
- `test_bootout_waits_for_the_job_to_disappear_before_returning` in `tools/test_setup_macos.py`.
- `test_a_manager_query_failure_is_not_evidence_of_job_removal` in `tools/test_setup_macos.py`.
- `test_bootout_fails_when_launchd_never_releases_the_job` in `tools/test_setup_macos.py`.
- `test_definition_rename_uses_the_destination_directory_and_preserves_mode` in `tools/test_setup_macos.py`.
