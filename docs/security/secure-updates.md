# Sovereign update and peer-report security design

Status: accepted design, implementation blocked on release-key ceremony and reproducible artifacts

Date: 2026-08-17

## Decision

Supgang will use The Update Framework (TUF) 1.0.35 as its software-update trust model. The trusted
root metadata ships inside the binary. Update metadata and artifacts may arrive from a local file,
an authenticated Supgang peer, a user-owned web server, removable media, or an optional public
mirror. Transport is replaceable and untrusted. No account, Agenxy server, Apple service, GitHub,
DNS provider, or public certificate authority is required to decide whether an update is authentic.

No update command will ship until a real root ceremony, signed repository, retained recovery
material, and end-to-end installer tests exist. A partially implemented signature check creates a
false security boundary and is worse than an explicit release blocker.

## Trust roles and key ceremony

Update authority is separate from hive authority. Hive root, device, transport, TUF root, targets,
snapshot, and timestamp keys must never be derived from one another or reused.

The initial repository policy is:

| Role | Threshold | Storage | Purpose |
| --- | ---: | --- | --- |
| Root | 2 of 3 | Offline on separate encrypted media, in separate physical custody | Authorize and rotate every TUF role |
| Targets | 2 of 3 | Offline signing devices, separate from CI | Authorize exact release artifacts and provenance |
| Snapshot | 1 of 1 | Restricted release host | Bind one consistent metadata set |
| Timestamp | 1 of 1 | Restricted release host | Bound metadata freshness |

Root and targets signing must happen from reviewed release inputs after reproducibility checks. CI
may prepare unsigned metadata, but CI never possesses enough root or targets keys to authorize a
binary. Each ceremony produces a redacted record containing metadata versions, signer key IDs,
artifact hashes, source commit, and independent reviewer confirmations. Private material never
enters the repository, CI, shell history, command arguments, or a peer message.

The root metadata uses consistent snapshots. Clients retain the highest trusted version of every
role, process root rotations one version at a time, enforce threshold signatures and expiry, and
reject rollback, freeze, fast-forward, and mix-and-match states according to the TUF client
workflow. Metadata and target downloads have fixed byte ceilings before allocation.

## Release target identity

Every supported target has a distinct TUF target path. Target custom metadata is bounded and
includes:

- Supgang version and wire compatibility range;
- operating system, architecture, and executable format;
- source commit and source-archive SHA-256;
- exact Rust toolchain and committed lockfile SHA-256;
- binary SHA-256 and byte length;
- SBOM SHA-256;
- signed provenance statement SHA-256;
- minimum safe version when a security rollback must be denied.

At least two isolated builders must produce byte-identical stripped artifacts before targets
signers authorize a production release. If the platform prevents exact reproduction, the release
remains blocked until the source of nondeterminism is removed or a narrower, explicitly reviewed
reproducibility statement is adopted. A CI-generated provenance statement alone is evidence, not
authorization.

## Client workflow

The future command surface is intentionally explicit:

```text
supgang update check --source PATH_OR_CONFIGURED_URL
supgang update download --source PATH_OR_CONFIGURED_URL
supgang update apply DOWNLOADED_VERSION
supgang update status
```

There is no forced update, silent source discovery, remote kill switch, or default public egress.
An opt-in policy may later combine check, download, and apply, but it must use the same verifier and
must remain locally revocable.

The verifier will:

1. Start from the root embedded in the running binary and the highest locally trusted metadata.
2. Apply sequential, threshold-authorized root rotations.
3. Verify timestamp, snapshot, and targets roles, expiry, versions, hashes, and byte bounds.
4. Select only the exact local operating-system and architecture target.
5. Stream the target into a new owner-only file while hashing and enforcing its signed length.
6. Compare the artifact and provenance digests with trusted targets metadata.
7. Parse and inspect the candidate executable before any replacement.
8. Run a bounded offline `--version` and self-check from the staged path with no inherited secret
   environment and no network permission where the platform permits isolation.
9. Synchronize the staged file, atomically rename it on the same filesystem, synchronize the parent
   directory, and retain one verified recovery binary.
10. Persist trusted metadata only through the same owner, type, symlink, permission, checksum, and
    rollback checks as other protected state.

A user-local install cannot defend against malware already running as that same user. A system
installation must be owned and replaced by a privileged, narrowly scoped installer whose only
accepted input is a fully verified staged artifact. Make and shell scripts may orchestrate tests,
but they are not an update verifier or privilege boundary.

## macOS signing

TUF artifact authentication does not require an Apple Developer Program membership. Supgang can
verify release signatures and hashes using its embedded public root on any supported Mac.

An ad hoc Mach-O signature may be applied as a structural code seal, but it contains no signing
identity and cannot authenticate Agenxy as publisher. Gatekeeper-recognized Developer ID signing
and Apple notarization require Apple Developer Program membership and Apple infrastructure. If
available later, Developer ID is an optional platform-distribution layer in addition to TUF. The
TUF target identity remains authoritative on every platform.

## Authenticated peer reports

A future live software report will be a bounded canonical object containing:

- hive and stable node ID;
- signed display name;
- Supgang version and current executable SHA-256;
- matching TUF target and trusted metadata versions;
- operating system and architecture;
- random boot-session nonce, monotonic report counter, issuance time, and short expiry;
- the requester's random challenge and the current TLS exporter;
- a device-key signature over the complete report.

The verifier accepts a report only inside an already authenticated QUIC session, verifies the
fresh challenge and TLS exporter binding, checks membership and revocation, and compares the
binary digest against its own trusted TUF targets metadata. Replay, network substitution, and a
peer merely copying another computer's report then fail cryptographically. Conflicting reports at
one counter are retained as equivocation evidence and stop automatic trust.

This proves that the authorized device key signed a fresh statement over the current secure
channel. It does not prove that the operating system, process, or device is uncompromised. A fully
compromised peer that can use its legitimate key can sign a lie. Software alone cannot make that
claim sound.

## Key theft and platform strengthening

Current file-protected Ed25519 device keys remain exposed to same-user compromise and live process
memory. The stronger provider plan is:

- macOS: a non-exportable Secure Enclave P-256 device key when supported, with a Keychain-backed
  key as the explicit fallback;
- Linux: a TPM 2.0 non-exportable signing key when supported, with a Secret Service or owner-only
  file fallback;
- root-authorized device-key rotation that records old and new algorithms, key IDs, epochs, and
  revocation state;
- separate transport-key rotation and short lifetimes;
- cross-peer retention of report counters and equivocation evidence.

Secure Enclave and TPM keys make extraction harder, but do not by themselves attest the entire
boot chain or prevent authorized signing requests from a compromised process. Hardware measured
boot and remote attestation can improve evidence on selected hardware, but must be optional,
inspectable, and based on owner-controlled verification policy. Apple App Attest and mandatory
vendor attestation services are outside strict sovereign mode.

## Library decision

AWS Labs `tough` 0.24.0 is the leading Rust client candidate and is available under Apache-2.0 or
MIT. It implements TUF and has a separate repository-generation tool. It is not yet a dependency.
Its normal graph adds asynchronous, canonical-JSON, URL, filesystem-walk, and other packages,
including an older `untrusted` identity that would change the current supported-target exception.
Before adoption, Supgang requires a feature-level code review, supported-target dependency graph,
RustSec and license results, fixed download bounds, file-only transport proof, malformed-metadata
tests, rollback fixtures, and a comparison against a small isolated updater crate.

Implementing a novel TUF verifier inside Supgang merely to reduce dependency count is rejected.
Update verification is security protocol code, not a suitable place to trade reviewed behavior for
line count. Dependency cost can instead be isolated behind a narrow internal interface and kept
out of the peer protocol and durable identity types.

## Acceptance gates

The update feature remains unavailable until all of these are demonstrated:

- completed and witnessed 2-of-3 root and targets key ceremonies;
- embedded root and signed repository fixtures committed without private material;
- reproducible macOS arm64, macOS x86_64, Linux arm64, and Linux x86_64 release artifacts;
- offline file transport and user-owned HTTP transport tests;
- valid update, interrupted update, disk-full, wrong platform, corrupted binary, bad signature,
  threshold failure, expired metadata, root rotation, rollback, freeze, fast-forward, and
  mix-and-match tests;
- atomic recovery after a process kill at every filesystem transition;
- macOS Gatekeeper behavior documented separately for ad hoc and optional Developer ID builds;
- no public connection in strict mode unless the user configured that exact source;
- two-physical-host peer delivery where the receiver verifies the same TUF target regardless of
  which peer transported it;
- an updated repository threat model and independent security review.

## Primary references

- [The Update Framework specification](https://theupdateframework.github.io/specification/)
- [AWS Labs tough](https://github.com/awslabs/tough)
- [Apple Developer ID](https://developer.apple.com/support/developer-id/)
- [Apple ad hoc signature flag](https://developer.apple.com/documentation/security/seccodesignatureflags/adhoc)
- [Apple Secure Enclave key protection](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
