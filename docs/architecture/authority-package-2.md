# Authority library package 2: encoding and test evidence

This implements ADR 0003's sixth-draft certified-key contract against test identities.
It adds `authority` and `trust_profile` as public library modules. Endpoint records,
network protocols, the CLI and the running service are unchanged. The existing exact
pins, rcgen 0.14.9 and rustls 0.23.45, supply certificate generation and WebPKI
verification; no dependency or lockfile changes are needed.

The complete byte contract is in the module documentation of
`crates/supgang/src/authority.rs`. No new authority is operational in the fleet.

## Canonical encodings

All CBOR arrays and strings have definite lengths; integers use minimal unsigned
encodings. Every field is present, including optional node id as either b32 or null.
Decoders bound counts before allocation, refuse trailing bytes and compare canonical
re-encoding to input. `bN` denotes a byte string of N bytes.

- Certified key: `[1, hive:b32, [issuer:b32, epoch], id:b16,
  [algorithm, public_key, custody], purpose, audience, [operations...],
  not_before, not_after, policy, possession:b64]`.
- Possession payload: the 11-element array containing all fields before possession,
  including schema version. Domain: `supgang/certified-key-possession/v1\0`.
  P-256 uses compressed SEC1 b33 and low-s r||s b64 over SHA-256(domain || payload).
  Ed25519 uses b32 keys, b64 signatures over domain || payload and strict verification.
- Algorithms are text `p256` or `ed25519`; custody is self-reported text `hardware`,
  `file` or `synced`. Unknown algorithms, custody, policy versions or purposes fail.
- Audiences: `["publish"]`; `["service", name, instance:b16]`;
  `["transport-server", name, instance:b16, hostname]`;
  `["transport-client", hive:b32, node:b32-or-null]`; `["attest", instance:b16]`.
  The audience tag must match purpose. A transport client without a node restriction
  may dial a concrete peer only in the same hive. Service names retain the existing
  16-byte portable schema. Server names are exact lowercase ASCII DNS names, at most
  253 bytes with nonempty labels of at most 63 bytes, without wildcards.
- Operations: up to 16 strictly sorted unique strings, each 1..=64 visible ASCII bytes.
  The consumer selects the operation and must call `authorize` with the actual audience.
- Revocation set: `[1, [id:b16...]]`, sorted unique, at most 64 and 4096 encoded bytes.
  The 64-id ceiling actually limits its encoding to 1092 bytes.
- Manifest content: `[1, epoch, revision, issued_at, next_update,
  [certificates...], revocations, [services...]]`. Certificates sort by unique id;
  at most 16. Services sort by unique name; at most four, with existing `ServiceAdvert`
  encoding `[name, port, key_pin:b32]` and nonzero port.
- Manifest envelope: `[1, content:bytes, device_signature:b64]`, at most 8192 bytes
  including envelope. Domain: `supgang/authority/v1\0`. Device signature bytes are
  excluded from record identity; content and `(epoch, revision)` identify the record.
- P-256 issuer id is SHA-256(`p256 || compressed public key`), local to this library;
  the legacy network identity derivation is unchanged.

## State and freshness

`AuthorityUpdate` validates the change, verifies possession, checks the predecessor,
reserves the next revision durably, signs, commits durably and then returns. An epoch
advance starts with no certificates or revocations, may enroll new-epoch certificates,
and rejects simultaneous revocations. Existing service advertisements can be retained
or replaced. A removed certificate is revoked; omission alone is not revocation.

The protected file store serializes writers with the existing `StateLock`. Its one
canonical CBOR state file holds hive/key binding, reserved `(epoch, revision)`, the
committed manifest, pending content digest and lifetime used-id set. Replacement uses
file fsync, rename, then directory fsync. Reopening burns an uncommitted reservation,
including when a signature survived the crash. Commit accepts the exact reservation
once. A failed write poisons the handle. Whole-directory backup restoration is not
covered by this store.

Lifetime id history is bounded to 4096 per device and never reset by an epoch advance;
exhaustion refuses issuance. Store bytes are bounded to 96 KiB. The verifier retains
at most 64 devices, 16 live certificates and 4096 historical ids per device, without
watermark eviction. It retains the previous epoch's bounded revocation set until the
next epoch transition; the epoch watermark still refuses all earlier epochs. Different
content at the same `(epoch, revision)` removes both authority records and quarantines
the epoch; recovery requires a higher epoch. Issuance-time watermarks and ids present
in either conflicting signed record survive quarantine. Exhausted tombstone capacity
refuses subsequent authority instead of dropping history.
The verifier is an in-memory library object; durable consumer-state integration is
outside this package and is required before service use.

Certificate lookup is precisely this inclusive intersection:

```text
issued_at <= now <= next_update
AND now - issued_at <= max_status_age
AND certificate.not_before <= now <= certificate.not_after
AND certificate.epoch == current_manifest.epoch
AND certificate.id is not revoked
AND certificate.purpose == requested_purpose
```

Ingest rejects `issued_at > now + 300 seconds`. Accepting a manifest within that skew
tolerance does not authorize a certificate before issuance. Receipt time is never used.
The certificate lifetime may not exceed 366 days; the manifest update interval may
not exceed seven days. An expired/stale manifest remains decodable and authenticatable.
Root membership, current root revocation freshness, and fresh protocol possession are
explicit caller obligations, not inferred from a successful library lookup.

## Test matrix

Names below are test functions in `authority/tests.rs` and `authority/adversarial_tests.rs`.
All identities and revision directories are temporary test fixtures.

| Test | What it proves |
| --- | --- |
| `canonical_certificates_round_trip_every_purpose_and_subject_algorithm` | All five audience schemas, optional client node and both key algorithms round-trip; signed manifests round-trip. |
| `cross_hive_certificate_is_refused` | A valid device signature cannot admit a certificate for a different hive. |
| `cross_instance_audience_is_refused` | An instance's attestation certificate does not authorize another instance. |
| `wrong_purpose_and_unlisted_operation_are_refused` | Purpose and operation are independently enforced; lookup also checks purpose. |
| `unknown_purpose_is_refused_at_decode` | An unimplemented wire purpose is a hard decode error. |
| `incompatible_audience_is_refused_at_decode` | A known but mismatched audience schema is refused before proof checking. |
| `replayed_possession_on_another_id_is_refused_for_both_algorithms` | A copied P-256 or Ed25519 proof fails after an id change. |
| `expired_certificate_is_decodable_but_not_usable` | Decoding and authentication do not grant use after certificate expiry. |
| `revoked_then_represented_certificate_is_refused` | An old manifest cannot resurrect a revoked id; a new revision cannot remove its revocation. |
| `revoked_id_cannot_be_recertified_by_an_update` | Typed issuance refuses a revoked id. |
| `id_reused_is_refused_even_for_an_identical_certificate` | Re-enrollment cannot reuse an already certified id, even unchanged. |
| `older_epoch_is_refused_and_advance_clears_prior_authority` | Epoch advance clears certificates/revocations, rejects older authority and preserves lifetime id non-reuse. |
| `same_revision_different_content_keeps_neither_and_replays_cannot_restore_it` | Equivocation removes both records and neither replay restores authority. |
| `clock_six_minutes_ahead_is_refused_without_poisoning_state` | Excessive future skew is refused without changing the watermark. |
| `freshness_is_an_intersection_and_decoding_does_not_renew_it` | Both deadlines independently constrain use, boundaries are inclusive, and replay does not refresh age. |
| `clock_rollback_past_latest_issuance_refuses_until_clock_recovers` | Clock rollback past issuance stops use. |
| `sixty_five_revocations_are_refused_before_reserving` | An oversized change consumes no revision. |
| `encoded_manifest_above_eight_kib_is_refused` | Oversized wire input and oversized otherwise-valid output both fail. |
| `reserve_without_commit_burns_revision_across_reopen` | Crash between reservation and commit makes the next update take revision 2 and recover only its committed result. |
| `different_valid_signature_bytes_are_one_content_record` | Two genuinely different low-s signatures, both verified, remain one content record. |
| `possession_mutations_and_noncanonical_bytes_are_rejected` | Trailing bytes, nonminimal integers, unknown policy and changed operations fail. |
| `certificate_lifetimes_operation_sets_and_key_encodings_are_bounded` | The 366-day boundary passes; overlong lifetimes/operations, duplicate operations, excessive operations and weak Ed25519 keys fail. |
| `transport_client_cannot_name_another_hive_and_server_hostname_is_exact` | Client hive binding and exact server hostname binding are enforced. |
| `omission_is_not_revocation_and_changed_content_cannot_reuse_an_id` | Omitted live certificates remain usable under current status; a changed statement cannot reuse their id. |
| `invalid_signature_does_not_create_equivocation_or_advance_watermark` | Unauthenticated conflicting content cannot poison valid authority. |
| `store_excludes_concurrent_writers_and_rejects_stale_predecessors` | Exclusive ownership, durable predecessor matching and one-shot commit are enforced. |
| `store_commits_only_exactly_reserved_content_and_is_bound_to_issuer` | A substituted body cannot commit; reopening under another hive or key fails. |
| `update_validates_services_and_manifest_deadlines_before_reserving` | Invalid service ports and update intervals consume no revision. |
| `revocation_decoder_refuses_65_unsorted_duplicate_and_indefinite_sets` | Revocation decoding checks count, ordering, duplicates, definite lengths and encoded size; monotonic extension is enforced. |
| `manifest_decoder_bounds_declared_counts_before_allocation` | An attacker-controlled huge array count fails before allocation. |
| `recovered_reservation_cannot_commit_even_with_a_surviving_signature` | A signed but uncommitted pre-crash manifest cannot be committed after recovery. |
| `wrong_device_and_subordinate_signatures_cannot_issue_authority` | A subordinate or other device cannot sign the issuer's manifest. |
| `transport_client_optional_node_means_this_hive_or_exactly_one_peer` | Optional client restriction has the intended hive-wide or exact-peer semantics. |
| `equivocation_retains_the_issuance_watermark_across_epoch_recovery` | A new epoch cannot use an older issuance time to escape clock rollback protection. |
| `certificate_count_and_epoch_reset_are_validated_before_reservation` | More than 16 additions and a conflicting epoch-reset/revoke change consume no revision. |
| `equivocation_cannot_erase_ids_revoked_only_in_the_conflicting_record` | A later epoch cannot reuse an id revoked only in the second equivocal manifest. |
| `signed_equivocation_is_not_hidden_by_a_conflicting_future_timestamp` | A signed conflict at the same epoch/revision still removes both records when its timestamp is too far ahead. |

The five `trust_profile` tests prove:

| Test | What it proves |
| --- | --- |
| `exact_profile_has_critical_constraints_and_native_ip_exclusions` | Emitted DER contains critical CA/pathLen 0, critical keyCertSign-only usage, critical name constraints, and both /0 IP exclusion encodings. |
| `only_allowed_leaf_passes_the_seven_requested_probes` | Only the allowed leaf passes among allowed, forbidden DNS, IPv4, IPv6, mixed DNS, email-only and CA-as-leaf probes. |
| `reports_subtree_email_and_anchor_path_length_limits` | Raw WebPKI accepts a permitted child name, allowed DNS plus email, and an allowed leaf through a subordinate CA. |
| `labels_cannot_inject_a_second_dns_subtree` | The anchor label rejects dots, wildcards, uppercase and malformed labels. |
| `subordinate_chains_enforce_dns_and_ip_constraints` | Matched subordinate chains accept the allowed DNS control but reject forbidden DNS, IPv4, IPv6 and mixed allowed/forbidden SANs. The mixed case is verified as the allowed identity, so hostname mismatch cannot explain its rejection. |

## Confinement results and ADR issues

`verify_confinement` uses a fresh in-memory Rustls root store and the existing AWS-LC
provider's WebPKI server verifier. It returns every raw verdict and rejection error.
It does not install a root, change verification policy or make platform/browser claims.

| Probe | Raw server-auth result |
| --- | --- |
| Allowed DNS apex | Accepted |
| Forbidden DNS | Rejected |
| IPv4 SAN | Rejected |
| IPv6 SAN | Rejected |
| Allowed plus forbidden DNS | Rejected |
| Email-only SAN | Rejected: no matching DNS server identity |
| Subordinate CA presented as server leaf | Rejected |
| Allowed DNS plus unused email SAN | Accepted |
| Child of the allowed apex | Accepted |
| Allowed leaf through a subordinate CA | Accepted |
| Forbidden DNS through a subordinate CA | `InvalidCertificate(Other(OtherError(NameConstraintViolation)))` |
| IPv4 SAN through a subordinate CA | `InvalidCertificate(Other(OtherError(NameConstraintViolation)))` |
| IPv6 SAN through a subordinate CA | `InvalidCertificate(Other(OtherError(NameConstraintViolation)))` |
| Allowed plus forbidden DNS through a subordinate CA, checked as allowed | `InvalidCertificate(Other(OtherError(NameConstraintViolation)))` |

Package 5 adds those four negative subordinate probes using the same subordinate
certificate profile and issuer construction as the allowed control, with fresh
throwaway keys per chain. DNS-only and IP probes are verified against their own
SAN identity. These are raw Rustls/WebPKI errors observed by the harness, without
overriding verifier decisions. They establish the tested name-constraint cases
through a subordinate, while the allowed control still demonstrates that the
anchor's pathLen 0 is not the mechanism enforcing confinement.

rcgen expresses both excluded IP ranges natively; no custom DER extension is needed.
The sixth draft says `"a child of the permitted name, and a subordinate CA are each
refused"`, yet also says the permitted DNS subtree is `"the label itself and every
name under it"`. Children therefore cannot be universally refused under this profile.
The concurrently committed seventh draft correctly changes the hive-subtree child
probe to acceptance; it does not change this package's certificate contract.

A CA-as-leaf refusal does not prove refusal of a leaf through that CA. The extra chain
probe demonstrates that this WebPKI trust-anchor representation does not enforce the
anchor's pathLen 0 against subordinate issuance. Full one-level confinement is not
established and must not be claimed. Platform stores and browsers are untested here.

The email text says `"the harness below checks that a leaf carrying one is refused"`
but later requires `"an allowed DNS name plus an unused email SAN is accepted"`.
The harness reports both cases: email-only fails the requested DNS identity check;
allowed DNS plus email succeeds. This is not exclusion of the email SAN name form.

The introductory certificate text assigns `"supgang/certified-key/v1\0"`, then states
`"A certificate carries no signature of its own"`. This package uses the required
possession and manifest domains, with no redundant issuer signature on certificates.

For freshness the controlling text is `"Acceptance of a certificate is the intersection
of: the manifest not past next_update; issued_at plus the consumer's maximum status age
for the purpose not passed"`. The earlier stale-status discussion and the implementation
request's OR wording do not relax that explicit intersection.

The ADR also requires `"the issuer's membership valid and not revoked under the newest
root set"` and states `"Both are mandatory"` for certification plus fresh protocol
possession. Those checks, endpoint bare-pin downgrade protection, root succession tests,
hardware presence enforcement, persistent consumer watermarks and real trust-store
installation remain outside this isolated library package. No network or root-protocol
coverage is inferred from these tests.

## Validation and completion limits (2026-09-19)

- The focused authority suite passes 37 tests; all four trust-profile tests pass.
- Repository policy, formatting, workspace check, all-target/all-feature Clippy with
  warnings denied, and workspace documentation with warnings denied pass.
- The complete local gate was executed and is **not green**: existing local-control,
  QUIC and service socket tests fail with `Operation not permitted` in this sandbox.
  The final current-source run reports 281 passed and 22 failed in 308.29 seconds,
  returning exit 1 from the quality runner (the Rust test subprocess returns 101).
  No tests, policies or gates were disabled or weakened. Integration/package acceptance
  after the failing Rust test stage is not claimed.
- `cargo deny` was run separately: the current quality runner inspects `deny.toml`
  policy but does not invoke the advisory command. Its default advisory-cache lock is
  unwritable here. Copying the cached database to the writable temporary directory and
  changing only `advisories.db-path` permits an offline check under the same policy.
  That database is commit `d5c17953a895cf19e8d3ce66eaa42b6fcfe1fb16`, dated
  2026-09-19. The check fails on existing `paste 1.0.15`, an unmaintained transitive
  dependency of `netlink-packet-core` through the Linux networking dependencies:
  [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436.html).
  License/source checks pass with warnings denied. The default bans check also reports
  existing duplicate-dependency warnings. No advisory ignore, policy exception or
  dependency change was introduced by this package.
- Normal `make install` cannot write `~/.local/.crates.toml` in this sandbox. An isolated
  temporary-prefix install builds and runs, resolves correctly outside the repository,
  matches the release artifact byte-for-byte, and passes `--help`. `--json doctor`
  returns a JSON object with an authoritative-state error (exit 3); a healthy live
  installation is not claimed. No fleet protocol/runtime changes were made or deployed.
- Staging fails because `.git/index.lock` is outside the writable sandbox. No commits
  were created. The requested author and co-author metadata therefore remain unexecuted.
  All implementation, test and documentation files remain in the working tree.

Completion requires rerunning the full gate with local socket permission, resolving
the existing dependency-policy failure, completing normal-path
installed checks and creating the requested commits in a writable checkout. This report
records library evidence; it is not milestone acceptance.

## Acceptance addendum: package 5 subordinate-chain probes

Implementation branch: `feat/mcp-server`. Base commit:
`f8cd85f3a3615127d66dd3d3509f5019cb44f21e`. Package 5's changes are an
**uncommitted working tree**, not the base commit. Staging returned exit 128:
the sandbox refuses `.git/index.lock`. The requested author is
`xaef <6741253+xaef@users.noreply.github.com>`, with trailer
`Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

Exact implementation commit: `521d68f7fe436849e5bd6ac1ee60c13a95d1b0cf` (branch feat/mcp-server; the addendum itself is the next commit)

Exact implementation tree (`git rev-parse 'HEAD^{tree}'`):
filled by the reviewer, 2026-09-20; see the table

Commit all package 5 source, tests and documentation before reviewer acceptance;
record that tested commit here in a later documentation-only commit if needed.
No outside-sandbox reviewer execution is claimed by the following local results.

Observed sandbox checks (2026-09-19, local date):

| Exact command, run from `~/Desktop/Supgang` | Observed outcome |
| --- | --- |
| `cargo test --locked --package supgang-core trust_profile::tests::subordinate_chains_enforce_dns_and_ip_constraints` | Before adding the probes: exit 101, missing four required negative subordinate verdicts. |
| `cargo test --locked --package supgang-core trust_profile:: -- --nocapture` | After correction: exit 0, all 5 tests pass. The four added probes each return `InvalidCertificate(Other(OtherError(NameConstraintViolation)))`; the allowed subordinate control passes. |
| `cargo test --locked --package supgang-core threshold::` | Exit 0, all 47 threshold tests pass. |
| `cargo run --locked --package supgang-quality -- all` | Exit 1: policy, fmt, check and strict Clippy passed; core tests ended 329 passed, 22 failed in 165.72 seconds. All 22 failures are socket permission errors (`Operation not permitted`). The gate stopped before doc/package acceptance; doc was run separately below. |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed with existing pedantic, nursery, cargo and no-indexing policies; exit 0. |
| `RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps` | Passed; exit 0. |
| `cargo deny --locked --offline check --deny warnings` | Exit 1: read-only advisory-cache lock. |
| `cargo deny --locked --offline --config /tmp/supgang-package5-deny.toml check --deny warnings` | Exit 1: existing unmaintained `paste 1.0.15` (`RUSTSEC-2024-0436`) and duplicate-dependency bans; licenses and sources pass. |
| `make install` | Exit 2: cannot write `~/.local/.crates.toml`; installed-artifact checks not run. |

The alternate deny config changes only `advisories.db-path`, using the copied
cached database at `/tmp/supgang-package5-advisory-dbs`, commit
`d5c17953a895cf19e8d3ce66eaa42b6fcfe1fb16` (2026-09-19). No network refresh,
pin change, exception, advisory ignore or relaxed gate was used.

Reviewer commands, to be run **outside the sandbox**, with results tied to the
exact implementation commit above:

| Exact command | Reviewer outcome |
| --- | --- |
| `cd ~/Desktop/Supgang && git rev-parse HEAD && git rev-parse 'HEAD^{tree}' && git status --porcelain=v1` | `521d68f7fe436849e5bd6ac1ee60c13a95d1b0cf`, tree `1d3dc96d8f7612b31e573d575dcef7504748fa13`, clean |
| `cargo test --locked --package supgang-core trust_profile:: -- --nocapture` | ok, 5 passed, 0 failed (2026-09-20) |
| `cargo test --locked --package supgang-core authority::` | filled by the reviewer, 2026-09-20; see the table |
| `cargo run --locked --package supgang-quality -- all` | `Supgang quality gates passed.` (351 lib tests, 2026-09-20, outside the sandbox) |
| `cargo deny --locked check --deny warnings` | fails as expected: RUSTSEC-2024-0436 (`paste`, unmaintained, reached through `portmapper`; predates these packages) and the duplicate-version warnings of FROST 3.0.0's older dalek/sha2/rand stack, every one listed in the reviewed-duplicate policy the gate applies; the repository gate `supgang-quality` passes |
| `make install` | not run for this package: the library changes nothing the installed service executes; the next service release runs it |
| `cd /tmp && command -v supgang` | not run (as above) |
| `shasum -a 256 ...` | not run (as above) |
| `supgang --help` | filled by the reviewer, 2026-09-20; see the table |
| `supgang --json doctor` | filled by the reviewer, 2026-09-20; see the table |

This adds isolated Rustls/WebPKI evidence only. No browser/system root was
installed; no physical fleet protocol or runtime changed. Live authority,
platform trust stores and complete milestone acceptance remain unverified.
