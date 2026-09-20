# Threshold root prototype: implementation package 4

This is the isolated ADR 0004 test-key prototype in `threshold` on
`feat/mcp-server`. Every share is disposable `file` custody held in process
memory. No provider, sealed custody, CA, CLI, network, live-service integration,
installation or physical-peer deployment is part of this package. It proves
state-machine rules; it is not production authority or a complete distributed
agreement protocol.

All simulated participants run in one test process, whose memory contains a
quorum of shares. This is not distributed custody, although no dealer or
whole-secret reconstruction is used.

## Implemented contract

- `founding::run` runs each participant's DKG, exchanges packages through a
  mutable in-memory `Channel`, and has each participant construct its complete
  public descriptor and founding digest. Round-two delivery is keyed by both
  sender and recipient. One failed participant aborts the result, without
  returning a partial group. Participants are identified by disposable
  `device_key::FileDeviceKey` P-256 public keys, not by self-asserted node ids.
- `step::RootStep` has canonical CBOR and domain-separated Ed25519 verification.
  `Chain` authenticates against the predecessor's retained context, checks the
  next sequence and recovery generation, holds unknown predecessors in a bounded
  untrusted queue, and drains that queue when ancestry arrives. Authenticated
  conflicting content records both branches and halts ordinary administration.
- `session::Session` records proposals, requires a presence callback, persists
  commitment before issuing public nonces, persists consumption before computing
  a signature share, and persists the cached share before returning it. A
  permanent predecessor lock is set at consumption. This is conservative if a
  crash prevents an already computed share from leaving the process. Exact
  package retries return a cached share; a consumed attempt without a cache can
  only be resumed with a new id and new nonces. A changed package never reuses a
  nonce. Unsigned locks expire at exactly 600 seconds of caller-supplied local
  time; permanent locks do not expire. Clock rollback is refused for mutations.
- `SessionStore` specifies exclusive ownership, scope binding and durable
  compare-and-swap snapshots. `FileSessionStore` uses owner-only files,
  no-follow opens, the existing directory lock and ACL checks, fsync before
  rename and directory fsync afterward. Uncertain writes poison the handle.
  Reopening burns incomplete nonce attempts; signed records retain their cache
  and permanent lock. Records contain public commitments, never nonce secrets
  or private key shares.
- `regroup::fresh_dkg` generates a new roster and next share generation.
  `Succession` binds the new root key, full descriptor and descriptor digest,
  retained-set digest, previous root key, and recovery descriptor. The old root
  authorizes planned succession. Successor possession is required. The next
  step uses the succession digest, continued sequence and advanced epoch;
  `HiveId` stays the existing domain-separated founding identity.
- Recovery uses a second DKG and independently pinned descriptor. Its
  successions can replace an arbitrarily advanced or forked ordinary chain,
  and can name a predecessor the receiver has never seen. Known predecessors
  have their sequence, epoch and old key checked. For an unknown predecessor,
  those fields are an assertion of the authenticated recovery authority;
  the missing ancestry has not been independently verified. Active descendants
  are removed, while authenticated evidence remains available for inspection.
  Recovery retains the empty-set digest. Application revocation, re-enrollment
  and anchor withdrawal are outside this library's opaque payload model.
- Recovery descriptors change only inside recovery succession, with exactly
  the next descriptor sequence, previous descriptor digest, next share
  generation, and new recovery-group possession. Planned succession preserves
  the descriptor exactly. Two different successions at one recovery generation
  halt permanently, even if the first rotated recovery keys: the verifier
  retains the authorizing descriptor for that generation. There is no ordinary
  or further recovery escape from a recovery-group fork in this model.
- `control_auth::Proof` signs a typed `Challenge` through `DeviceSigner` under
  `device_key::CONTROL_AUTH_DOMAIN`, `supgang/control-auth/v1\0`. Verification
  requires the current descriptor and roster, generation, self and peer node
  ids, hive, challenge and channel binding. The test exporter is a fixed-size
  byte value, not a real TLS connection. Proof verification grants no membership.

## Encoding and finite bounds

All protocol CBOR uses definite arrays, minimal unsigned integers, fixed field
order and version 1. Decoders re-encode and compare the complete input, refusing
trailing bytes, indefinite lengths, unknown tags and nonminimal encodings.
Notation: `b32` is a 32-byte byte string; `b64` is a 64-byte byte string.

```text
RootStep:
  [1, hive:b32, predecessor:b32, sequence:u64, epoch:u64,
   recovery_gen:u64, operation:text, payload:bytes, proposed_at:u64, proposer:b32]
GroupDescriptor:
  [1, label:text, k:u16, n:u16, generation:u64,
   [[participant:u16, device:b33, verifying_share:b32, "file"]...], group_key:b32]
RecoveryDescriptor:
  [1, sequence:u64, predecessor_descriptor:b32, group_descriptor:bytes]
Founding digest:
  SHA-256(CBOR([1, group_descriptor:bytes, recovery_descriptor:bytes]))
  The independent recovery DKG uses null for the last field while it is created.
Succession payload:
  [1, kind:text, previous_key:b32, successor_descriptor:bytes,
   successor_descriptor_digest:b32, retained_set_digest:b32,
   recovery_descriptor:bytes, recovery_descriptor_digest:b32,
   successor_possession:b64, new_recovery_possession:b64]
Signing package identity:
  SHA-256(CBOR([1, session_id:b32, descriptor_digest:b32, generation:u64,
               frost_signing_package_serialization:bytes]))
Control challenge:
  [1, hive:b32, descriptor_digest:b32, generation:u64, self_node:b32,
   peer_node:b32, challenge:b32, channel_binding:b32]
```

The root signature signs `supgang/root-step/v1\0 || canonical_step`, not a
prehashed Ed25519 variant. The content digest used for predecessors and locks
is SHA-256 of canonical step bytes, excluding the signature and domain prefix.
Succession possession signs a root step with the same fields and a payload
whose two possession slots are zeroed; the authorizing signature covers the
completed payload. Both new groups prove possession over the same exact
transition, without a circular signature dependency or a new signing domain.

Both groups are bounded to 16 participants. DKG supports the pinned library's
`2 <= k <= n <= 16` range, with explicit acceptance required for `n == k`.
The requested `k == 1` configurations fail explicitly, as explained below.
Labels are 1..=63 visible ASCII bytes, group descriptors at most 4096 bytes,
recovery descriptors at most 4200 bytes, operation payloads at most 12 KiB,
and root steps at most 16 KiB. Participant ids are contiguous from 1; duplicate
device keys are refused. Every participant's custody is encoded as `file`.

The chain retains at most 256 authenticated entries, 256 pending entries and
256 recovery proofs; contexts are bounded by the authenticated entries plus
the founding context. A signer retains at most 256 lifetime attempts and never
prunes permanent locks. Store files are bounded to 5 MiB. Counters use checked
advancement. Exhaustion fails closed, including when another recovery cannot
fit in the evidence store. These are deliberately small prototype ceilings,
not a production retention or compaction policy. The mutable DKG hooks are
trusted test code simulating transport corruption; they are not input decoders.

## Pinned libraries and actual APIs

`frost-ed25519 = "=3.0.0"` and `frost-core = "=3.0.0"` both declare
`MIT OR Apache-2.0`. Only their `serialization` feature is explicitly enabled.
The workspace's existing Ed25519 verifier is `ed25519-dalek = "=3.0.0"`.
See the upstream [Ed25519 API](https://docs.rs/frost-ed25519/3.0.0/frost_ed25519/)
and [DKG API](https://docs.rs/frost-core/3.0.0/frost_core/keys/dkg/index.html).
The installed source for these exact versions was read and compiled.

Library operations actually used in this prototype:

| API | Use |
| --- | --- |
| `frost_core::keys::dkg::part1::<Ed25519Sha512, _>` | Each participant generates its first secret package and broadcast package. |
| `frost_core::keys::dkg::part2` | Consumes each first secret package and peer broadcasts; produces recipient-specific round-two packages. |
| `frost_core::keys::dkg::part3` | Each recipient verifies round-two shares and computes its `KeyPackage` and `PublicKeyPackage`. |
| `frost_ed25519::Identifier::try_from` | Converts bounded nonzero participant numbers. |
| `keys::VerifyingShare::{serialize, deserialize}` and `VerifyingKey::{serialize, deserialize}` | Descriptor public outputs. |
| `keys::PublicKeyPackage::new(shares, key, Some(k))` | Reconstructs the public package with the 3.0.0 threshold argument. |
| `round1::commit` | Generates fresh `SigningNonces` and `SigningCommitments`. |
| `round1::SigningCommitments::{serialize, deserialize}` | Public commitment persistence and equality. |
| `SigningPackage::{new, serialize}` | Exact message/commitment package construction and package identity. |
| `round2::sign` | Computes a share only after durable consumption. |
| `round2::SignatureShare::{serialize, deserialize}` | Durable cached-share retry. |
| `aggregate`, `Signature::serialize` | Test coordinator aggregates and obtains ordinary 64-byte Ed25519 signatures. |
| `ed25519_dalek::VerifyingKey::{verify, verify_strict}` | Interoperability fixture and strict chain verification; `verify` comes from `Verifier`. |

Tests also call `keys::SigningShare::deserialize`,
`keys::dkg::round2::Package::new`, and
`round2::SignatureShare::deserialize` to inject a validly encoded false DKG
share and a false signature share. No dealer generation, secret reconstruction,
same-key refresh, trusted-dealer split, or custom curve arithmetic is used.

FROST 3.0.0 takes `rand_core` 0.6, while the live dependency graph already uses
0.9 and 0.10. `rand_chacha = "=0.3.1"`, with default features disabled, supplies
the matching `ChaCha20Rng`; `frost_ed25519::rand_core::SeedableRng::from_seed`
initializes it from 32 bytes obtained using existing `getrandom::fill` 0.4.3.
The temporary seed buffer is zeroized. No OS-RNG version downgrade, failed
entropy fallback, or infallible adapter that might silently emit zeros was added.
This remains file-custody memory, not protected or attested hardware memory.

FROST pins `curve25519-dalek` 4.1.3 and uses SHA-2/digest 0.10. It therefore
coexists with the current verifier's curve25519-dalek 5 and digest 0.11.
Exact duplicate identities were added to the existing reviewed-identity policy:
base16ct, block-buffer, cpufeatures, crypto-common, curve25519-dalek, digest,
embedded-io, fiat-crypto, rand_chacha, rand_core 0.6.4, serdect, sha2 and spin.
The older serialization graph comes from FROST's `serdect` and `postcard`;
older RNG traits come from FROST and its exact curve dependency. Existing direct
pins remain unchanged. No wildcard duplicate exception, advisory exception,
license exception, warning suppression or disabled quality check was introduced.

## Tests and what each proves

All names below are under `threshold::tests`; each row identifies one test.

| Module and test | Property proved |
| --- | --- |
| `founding_tests::participants_agree_on_dkg_outputs_and_recovery_bound_founding_digest` | Every participant's public output and founding digest agree; label/recovery changes change the digest; descriptor round-trip. |
| `founding_tests::a_tampered_round_two_share_is_refused_by_its_recipient` | A false polynomial evaluation is rejected by FROST final verification. |
| `founding_tests::loss_policy_bounds_and_pinned_library_threshold_one_limit_are_explicit` | 2-of-2 requires the flag, invalid bounds fail, and the actual pinned DKG rejects threshold one. |
| `founding_tests::duplicate_device_identities_and_missing_packages_are_refused` | Repeated identities and incomplete DKG exchange fail. |
| `founding_tests::root_step_has_one_encoding_and_binds_every_field` | Canonical round-trip, nonminimal/trailing input refusal, and signature/digest binding of all nine ADR fields. |
| `session_tests::presence_is_required_before_commitment_or_nonce_release` | Denied presence leaves only a proposal; approved presence reaches durable nonce issuance. |
| `session_tests::another_step_is_locked_until_the_unsigned_ten_minute_deadline` | Competing predecessor lock holds at 599 seconds and releases at 600 with the original attempt discarded. |
| `session_tests::delayed_publication_never_releases_the_shared_signers_lock` | A and B sign X; B refuses Y after a long delay and after discard; delayed X publishes without a fork. |
| `session_tests::identical_package_returns_cached_share_but_changed_commitments_are_refused` | Cached retry is byte-identical; modifying another signer's commitment is refused. |
| `session_tests::substituted_message_and_wrong_generation_are_refused_before_consumption` | Message, generation or descriptor substitution fails before nonce consumption. |
| `session_tests::resumed_session_uses_new_id_fresh_nonces_and_the_same_step_lock` | Resumption after shares were released uses fresh commitments and id; old commitments and reused id fail; new aggregate verifies. |
| `session_tests::expired_signing_attempt_discards_nonces_and_cannot_be_replayed` | A signing request at the deadline discards its nonce attempt and refuses replay. |
| `session_tests::aggregate_is_an_ordinary_ed25519_signature_and_bad_shares_fail` | Dalek normal and strict Ed25519 verifiers accept the aggregate; FROST rejects a false share. |
| `storage_tests::consumption_is_durable_before_share_computation_and_crash_keeps_lock` | Injected cache-publication failure leaves durable consumed state without a returned share; restart cannot reuse nonces or unlock another step. |
| `storage_tests::failed_consumption_write_releases_no_share_and_poisons_the_session` | Consumption-write failure prevents a returned share and poisons further use. |
| `storage_tests::restart_returns_cached_share_and_preserves_permanent_predecessor_lock` | Reopened stores return the same aggregate from cached shares and refuse competing content. |
| `storage_tests::restarted_unsigned_attempt_burns_nonces_and_rejects_clock_rollback` | Restart discards nonce attempts, rejects the old package and backwards time, and resumes with fresh commitments. |
| `storage_tests::store_refuses_parallel_ownership_other_scope_and_restored_old_group_share` | Directory ownership is exclusive; foreign hive/generation state and old-root shares in a successor store fail. |
| `chain_tests::unknown_predecessor_is_held_then_accepted_when_the_chain_arrives` | Child-before-parent delivery grants no authority until the parent arrives; duplicates are idempotent. |
| `chain_tests::disjoint_honest_two_of_four_quorums_fork_and_halt` | Honest disjoint quorums can fork; both branches are retained and ordinary administration halts. |
| `chain_tests::intersecting_two_of_three_fork_requires_a_faulty_signer_and_halts` | A deliberately faulty signer using a fresh store signs conflicting content; the verifier detects the fork. |
| `chain_tests::invalid_signature_or_invalid_sequence_cannot_manufacture_a_fork` | Forged signatures and invalid accepted shape cannot add equivocation evidence or halt. |
| `chain_tests::regroup_advances_epoch_and_sequence_keeps_hive_and_exposes_stale_peer_window` | Fresh new-roster DKG, planned succession, continued sequence, old-key refusal after succession, and old-key acceptance by a stale peer. |
| `chain_tests::planned_succession_requires_possession_and_preserves_pinned_recovery` | Missing successor possession or changed recovery descriptor fails even with an old-root signature. |
| `chain_tests::recovery_discards_planned_descendants_and_outranks_their_epochs` | Recovery from the founding predecessor discards an advanced planned branch; old-generation high epochs cannot recover priority. |
| `chain_tests::recovery_clears_an_ordinary_fork_but_a_recovery_fork_halts_permanently` | Recovery repairs an ordinary halt; same-generation recovery equivocation requires refounding. |
| `chain_tests::ordinary_root_cannot_set_recovery_group_or_advance_recovery_generation` | Ordinary root signatures cannot change recovery authority or authorize recovery. |
| `chain_tests::recovery_descriptor_rotation_needs_old_authority_new_possession_and_monotonic_history` | Existing recovery authorizes descriptor rotation, both successors prove possession, and even current recovery cannot reinstall a stale descriptor. |
| `control_tests::control_proof_is_bound_to_challenge_generation_peer_hive_and_exporter` | Each changed transcript component is refused, with a successful unmodified control. |
| `control_tests::a_valid_device_signature_outside_the_current_roster_grants_nothing` | A valid outsider's device proof cannot gain shareholder admission. |
| `boundary_tests::unknown_predecessor_recovery_is_authoritative_without_the_missing_chain` | Independently authorized recovery is accepted without waiting for unavailable ordinary ancestry. |
| `boundary_tests::untrusted_pending_flood_is_bounded_and_cannot_change_authority` | The pending queue stops at 256 entries without tip, evidence or status mutation. |
| `boundary_tests::malformed_held_child_is_dropped_without_poisoning_a_valid_parent` | A bad held signature is dropped when its valid parent arrives. |
| `boundary_tests::independent_recovery_is_required_and_recovery_forks_use_the_pre_rotation_key` | Root and recovery cannot be the same group; recovery fork checking retains the pre-rotation authorizing key. |
| `boundary_tests::session_history_bound_and_file_corruption_fail_closed` | Attempt 257 is refused; malformed durable state is never silently reset. |
| `boundary_tests::recovery_can_select_the_other_authenticated_fork_branch` | Recovery can select the second recorded branch, preserve its ancestry and discard the first branch from the active path. |

## ADR contradictions, unsupported passages and resolutions

These are implementation choices for the prototype, not silent amendments to
the proposed ADRs. Quotations preserve the relevant text, with line wrapping
normalized. Production integration needs the ADR author to settle these points.

1. **Threshold one is not supported by the specified DKG.** ADR 0004:
   "Supported parameters: `1 <= k <= n <= 16`; a hive founded 1-of-1 is the
   file-held root of today under another name, and `doctor` says so."
   The same section says: "No device ever holds the whole root secret, not at
   founding, not after." FROST 3.0.0 `validate_num_of_signers` rejects every
   `min_signers < 2` before DKG; the test calls the actual API to prove it.
   A threshold-one participant would also possess the complete signing
   authority, conflicting with the absolute secrecy statement. The prototype
   returns `ThresholdOne`. It does not fabricate threshold-one DKG, use a
   dealer, fork the dependency or call this requirement implemented.

2. **The signing message has two descriptions.** ADR 0004: "The root signature
   covers the whole step." Signing round two instead says: "the coordinator
   sends the signing package (the step digest and the exact set of
   commitments)." The prototype signs the domain plus the whole canonical
   step, stores its content digest, and compares the package message byte for
   byte against that recorded step. The package digest separately binds the
   session and commitments. Signing only the digest would produce a different
   protocol message even though both signatures would be Ed25519.

3. **Recovery changes are both standalone and succession-only.** ADR 0004:
   "Changing the recovery group (its roster, threshold or key) is a
   `set-recovery-group` step authorized by the *existing* recovery group with
   the successor group's possession, never by a root quorum"; later:
   "changes to it happen *only inside a recovery succession* (which carries
   the new descriptor and advances the generation)". The latter rule is
   implemented. A standalone `SetRecoveryGroup` is refused regardless of who
   signed it; descriptor rotation is inside recovery succession, independent
   of the ordinary tip, with new-group possession.

4. **The operation inventory omits later operations.** ADR 0004's record lists
   "one of: issue-membership, revoke, trust-anchor, allocate-name, issue-leaf,
   reshare, succession, set-recovery-group". Its regroup section introduces
   "an `admit-roster` step of the old root", and its CA section introduces
   "a `set-ca-holders` step plus an encrypted transfer over the control
   channel". `AdmitRoster` is an explicit reserved payload tag here, but there
   is no real pending-roster channel admission, encrypted delivery or
   `SetCaHolders` implementation in this network-free, CA-free package.
   Unknown tags fail. No test claims a working pending-roster network ceremony.

5. **Same-key reshare is superseded.** ADR 0003: "A reshare produces new shares
   over the *same* public key". ADR 0004: "The first version has no same-key
   reshare." The prototype implements fresh DKG plus key-changing succession;
   the old `Reshare` tag is refused. It does not exercise `keys::refresh`.

6. **Ordinary quorum resolution is superseded by recovery.** ADR 0003 says
   administration halts "until the owner resolves it in person with a quorum."
   ADR 0004 states: "There is no `resolve` or `abort` step under the ordinary
   root" and "The way out of a fork is a **recovery succession**". Only
   independently pinned recovery can clear an ordinary-root halt. A fork of
   recovery itself cannot be cleared by the compromised protocol.

7. **Order is recovery-first, despite the older tuple notation.** ADR 0003:
   "Members persist the greatest (root epoch, recovery generation) seen and
   refuse anything older." ADR 0004 explicitly says: "a member orders state
   by `(recovery_gen, epoch, sequence)`". The latter lexicographic order is
   used. Recovery may reduce the numeric epoch and sequence relative to a
   discarded planned chain while increasing the leading recovery generation.

8. **Succession possession lacked a canonical preimage.** ADR 0003 asks for
   "the successor's possession signature over the rest, and the authorizing
   signature" without defining exclusion of the authorizing signature or its
   embedding inside RootStep. Including that signature creates a circular
   dependency. The zeroed-possession RootStep preimage above excludes both
   possession signatures from their own input; the authorizing signature is
   outside the payload. The retained digest and every descriptor are covered
   by both possession and authorization.

9. **Absolute restored-state refusal needs an external freshness source.**
   ADR 0004: "a restored signer reconciles its `committed`/`consumed` records
   with the chain before it may sign again." ADR 0003 also states: "The durable
   head witness detects a rolled-back state file, not a whole-machine restore".
   This prototype has no network reconciliation or hardware witness. It burns
   incomplete attempts from the state actually present, retains permanent
   locks in that state, and rejects old-root shares against a current group.
   It cannot detect restoration of the whole signing directory to a prior
   version or claim that such a signer has reconciled. Callers must not treat
   `Session::open` as authorization to use a real restored backup.

10. **Root domain inventory and old record formats differ.** ADR 0003's browser
    section specifies "A trust-anchor manifest, root-signed
    (`supgang/trust-anchor/v1\0`)"; its signer inventory instead assigns root
    signatures to "`supgang/root-step/v1`, whose payloads carry membership,
    revocation, trust-anchor, name, succession and roster operations" and says
    "Nothing else signs." This package uses the new root-step domain only
    within the isolated library and leaves existing live root-record signatures
    untouched, as explicitly required by the package scope.

11. **An unrelated browser-profile contradiction remains in ADR 0003.** The
    earlier paragraph says the harness checks that a leaf carrying an email or
    URI SAN "is refused by each platform"; the later test inventory asks
    "that a leaf carrying an allowed DNS name plus an unused email SAN is
    accepted". This threshold package changes neither the CA profile nor its
    harness. It cannot resolve both statements by implementing threshold roots.

## Validation and acceptance boundary

The complete gate was run. Formatting, workspace checks and warnings-fatal
workspace Clippy passed. Its final core test stage had 317 passes and 22 failures:
every failure reported `PermissionDenied`, `Operation not permitted`, at a
socket-related fixture. This sandbox does not permit those existing network
and local-control tests. The gate was not green and did not reach its later
package-verification stage. The threshold tests themselves all passed.
The final isolated command
`cargo test --locked --package supgang-core threshold:: --lib` passed all
36 tests (0 failed, 303 unrelated tests filtered), including the recovery-branch
regression. The recorded run completed in 10.42 seconds after compilation.

`RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps` passed
separately. `cargo deny --offline check licenses sources` passed. For the full
deny check, the cached advisory database was copied to a temporary writable
directory because its normal Cargo-home lock is read-only in the sandbox.
The temporary config changes only `advisories.db-path`, keeping every policy
and exception unchanged. The cached database commit was `d5c17953`, dated
2026-09-19. No advisory data was fetched during this offline check.

The full deny result was `advisories FAILED, bans ok, licenses ok, sources ok`.
Its error is the existing `paste 1.0.15` unmaintained advisory
`RUSTSEC-2024-0436`, through `netlink-packet-core` / `netwatch` / `portmapper`;
`paste` was already in the base lockfile. Duplicate-version warnings also
remain in cargo-deny's separate default bans check. The repository's stricter
exact-identity duplicate policy passes with the reviewed FROST identities.
No advisory was ignored and the dependency scan is not described as green.

The package is intentionally not installed and the live fleet is not touched.
No acceptance result from the running service, physical peers, provider
hardware, TLS exporters or browser trust stores is inferred from these tests.

The requested commit was attempted with author
`xaef <6741253+xaef@users.noreply.github.com>` and trailer
`Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`. Git could not create
`.git/index.lock` (`Operation not permitted`); no commit or staging change was
made. The implementation and report remain in the working tree. No independent
reviewer verdict is claimed by this implementation run.
