# Sovereign update and peer-report security design

Status: client and peer-carriage mechanism implemented; physical macOS cross-host delivery and
rollback accepted; production signing ceremony and cross-platform acceptance pending

Date: 2026-08-25

## Decision

Supgang uses The Update Framework (TUF) through `tough` 0.24.0 as its software-update trust model.
Each computer pins its initial self-signed root through an explicit local owner action. Signed
metadata and artifacts may then arrive in a local bundle or from an already authenticated Supgang
peer. Transport is replaceable and untrusted. No account, Agenxy server, Apple service, GitHub, DNS
provider, public certificate authority, or public address is required to decide whether an update
is authentic.

The verification and A/B activation mechanism is implemented. This repository deliberately does
not embed or manufacture an Agenxy production trust root. A public Supgang release using this path
remains blocked on the witnessed threshold-key ceremony, retained recovery material, reproducible
production artifacts, and physical macOS/Linux acceptance described below.

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

Production root metadata will use consistent snapshots. Clients retain the highest trusted version
of every role, process root rotations one version at a time, enforce threshold signatures and
expiry, and reject rollback, freeze, fast-forward, and mix-and-match states according to the TUF
client workflow. After a root rotation succeeds, Supgang atomically promotes the verified root as
the next loader trust anchor before it examines or stages a target. The immutable bootstrap root
remains recovery material rather than active authority. The protected root-state record retains
one previous generation, and missing, corrupt, non-monotonic, or ambiguous current-root state
fails closed without falling back to the bootstrap. Metadata and target downloads have fixed byte
ceilings before allocation.

## Release target identity

The implemented client requires a distinct target name with this exact shape:

```text
supgang-VERSION-OS-ARCH
```

TUF metadata binds its exact byte length and SHA-256. The client rejects a non-advancing semantic
version, a different operating system or architecture, and a target that is not a native Mach-O on
macOS or ELF on Linux. Production target custom metadata is planned to include:

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

The implemented command surface is intentionally explicit:

```text
supgang update trust ROOT.json
supgang update bundle --metadata DIR --targets DIR --target NAME OUTPUT.bundle
supgang update stage OUTPUT.bundle
supgang update status
supgang update apply
supgang update send PEER OUTPUT.bundle
```

There is no forced update, silent source discovery, remote kill switch, or default public egress.
An opt-in policy may later combine check, download, and apply, but it must use the same verifier and
must remain locally revocable.

The verifier:

1. Starts from the atomically promoted current root, which initially equals the root explicitly
   pinned on that computer, and the highest locally trusted metadata.
2. Applies sequential, threshold-authorized root rotations.
3. Verifies timestamp, snapshot, and targets roles, expiry, versions, hashes, and byte bounds.
4. Selects only the exact local operating-system and architecture target.
5. Streams the target into a new owner-only file while enforcing its signed length and TUF hash.
6. Parses the native executable header and verifies the completed file again before publication.
7. Synchronizes and atomically publishes the candidate in a content-addressed slot.
8. Atomically persists the newest verified root before target selection, then commits the complete
   current TUF rollback state as one canonical checksummed owner-only document. Semantic rollback
   uses the compiled, active, previous, staged, and pending slot records rather than a separate
   high-water write that could poison recovery after a failed candidate.
9. Marks a candidate for a fixed installed supervisor, which launches it with a cleared environment
   and retains the prior known-good slot.
10. Requires the candidate to answer on the protected local control socket throughout a 30-second
    probation window; failure returns immediately to the prior payload.

Before step 9, `update apply` verifies without mutation that the service definition, protected
executable, owner state, manager domain, and process-ownership boundary are ready for a restart. A
failed preflight leaves no pending activation. A later restart failure removes only the pending
record and keeps the verified candidate staged for an explicit retry. Staged and pending versions
must be strictly newer than the active version unless they are the exact same version and digest
used to recover an interrupted commit. A local source install clears stale staged and pending
records before replacing its active record, so a supervisor cannot later roll that install back.
Service refresh holds the same protected update lock while it checks the durable version floor,
copies the current command into the fixed supervisor path, and initializes the active slot. An
older command therefore cannot overwrite a newer protected supervisor before rollback rejection.
A higher semantic version with byte-identical content still advances the durable active version;
digest equality alone is not treated as interrupted-commit recovery.

Local refresh additionally requires the invoking executable to satisfy the existing active
macOS signing identity; a source install is not an identity-reset bypass. The supervisor reserves
a durable launch attempt before each pending candidate starts. Three interrupted probation
attempts exhaust that candidate's budget and return to the active release; only a new explicit
activation resets the budget. Ordinary clean exits let the native manager re-execute the
supervisor, and supervised shutdown first allows bounded graceful termination.

An optional administrator-owned macOS boot definition runs the entire service as the ordinary
owner. After the one-time setup approval, restart uses the existing owner-authenticated local
socket and verifies a new random runtime instance. No network request gains administrator
access. Physical reboot and firewall-on signed-update acceptance remain separate gates.

One update operation is admitted per computer at a time. Metadata is capped at 256 KiB per role, a
target at 128 MiB, a complete bundle at 160 MiB, root advancement at 32 versions per load, and a
bundle at 64 entries. Inboxes, prepared outboxes, temporary verification directories, network
tasks, and retained slots are also bounded and recover stale partial work after interruption.

For peer delivery, the sending computer must hold the hive root. It signs a five-minute canonical
authorization containing the hive, authenticated issuer, exact receiver, bundle SHA-256, exact byte
length, issuance and expiry times, and a random nonce. The receiver durably consumes that nonce
before accepting the large body, then independently runs the same TUF verifier. A peer cannot pin or replace TUF trust,
choose a path, carry a shell command, or make an unsigned target executable. Remote delivery is
durably queued for up to 24 hours when the receiver is offline. The sender retains at most four
exact prepared bundles, retries temporary transport or receiver-storage failures after an authenticated reconnection, and creates
the five-minute authorization only when an actual send begins. A temporary not-ready response keeps
the durable queue entry; acceptance or a permanent authorization or verification rejection removes
it. Authorization preflight has a short deadline before fair update admission, and the three-minute
body transfer holds neither the cross-process update lock nor the receiver's durable state owner.
Remote receipt stops after verification and staging. A local owner must run `supgang update apply`
before the stable supervisor can attempt the candidate.

A user-local install cannot defend against malware already running as that same user. A system
installation must be owned and replaced by a privileged, narrowly scoped installer whose only
accepted input is a fully verified staged artifact. Make and shell scripts may orchestrate tests,
but they are not an update verifier or privilege boundary.

## macOS signing

TUF artifact authentication does not require an Apple Developer Program membership. Supgang can
verify release signatures and hashes using its locally pinned public root on any supported Mac.

An ad hoc Mach-O signature may be applied as a structural code seal, but it contains no signing
identity and cannot authenticate Agenxy as publisher. Gatekeeper-recognized Developer ID signing
and Apple notarization require Apple Developer Program membership and Apple infrastructure. If
available later, Developer ID is an optional platform-distribution layer in addition to TUF. The
TUF target identity remains authoritative on every platform.

Ad hoc signatures also do not provide a stable code identity across versions. macOS uses the
designated requirement in a code signature to decide whether updated code is the same previously
authorized program. Physical testing confirmed that an explicitly allowed command path could
receive traffic while an ad hoc content-addressed update slot was denied by the application
firewall.

The install task now accepts an exact 40-character owner-controlled signing-identity hash and
applies the fixed identifier `org.agenxy.supgang.runtime`. This does not depend on Apple membership
or Apple signing infrastructure. The matching private key remains with the owner or release signer,
and each Mac must explicitly trust the public owner certificate once. TUF still authenticates the
release bytes; the platform signature supplies a stable local code identity. macOS staging,
activation, and supervisor handoff also require each candidate to satisfy the currently active
executable's designated requirement. A TUF target with an invalid, ad hoc, or different platform
identity is rejected before execution. Firewall-on update continuity remains unaccepted until a
signed build, activation, rollback, and peer reconnection pass on both physical Macs.

## Authenticated peer reports

A future live software-health report, distinct from update carriage, may be a bounded canonical
object containing:

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

AWS Labs `tough` 0.24.0 is pinned under Apache-2.0 or MIT with default features disabled. Supgang
uses only its filesystem transport; its HTTP client is not compiled. Version 0.24.0 includes the
fix for the delegated-role threshold bypass disclosed as CVE-2026-6966 in older releases and a Jiff
timestamp serialization correction relative to 0.23. The complete locked graph remains subject to
RustSec, source, license, duplicate-identity, and supported-target dependency gates. The exact
lockfile-only `bitflags` exception introduced through Jiff's disabled embedded-formatting edge is
recorded in `docs/security/dependency-exceptions.md`.

Implementing a novel TUF verifier inside Supgang merely to reduce dependency count is rejected.
Update verification is security protocol code, not a suitable place to trade reviewed behavior for
line count. Dependency cost can instead be isolated behind a narrow internal interface and kept
out of the peer protocol and durable identity types.

## Acceptance evidence and remaining gates

Implemented source-level evidence includes a real temporary Ed25519-signed TUF repository, local
root pinning, durable current-root promotion, rejection of an alternate chain signed by a retired
root key after restart, fail-closed missing root state, a streamed valid target, corruption
rejection, semantic rollback rejection, cross-process update-lock contention, and a real loopback
QUIC transfer in which the receiver independently verifies and stages the candidate without remote
activation. The
ordinary repository gate also runs the full unit, Clippy, RustSec, license, dependency, package,
and structural checks.

Physical macOS evidence now includes durable offline queuing, retry-later retention, authenticated
IPv4 carriage, receiver-side TUF verification, successful A/B probation, and rollback from a signed
native executable that failed readiness. Post-update firewall continuity, Linux runtime behavior,
and production signing remain open gates.

The following remain production release gates:

- completed and witnessed 2-of-3 root and targets key ceremonies;
- reviewed production root metadata and signed repository fixtures committed without private
  material;
- reproducible macOS arm64, macOS x86_64, Linux arm64, and Linux x86_64 release artifacts;
- an optional user-owned HTTP source, if added, with the same verifier and strict-mode egress rule;
- interrupted update, disk-full, wrong-platform repository, bad-signature, threshold-failure,
  expired-metadata, root-rotation, freeze, fast-forward, and mix-and-match fixtures beyond the
  implemented valid, corrupt-bundle, and semantic-rollback cases;
- atomic recovery after a process kill at every filesystem transition;
- macOS Gatekeeper behavior documented separately for ad hoc and optional Developer ID builds;
- no public connection in strict mode unless the user configured that exact source;
- an updated repository threat model and independent security review.

## Primary references

- [The Update Framework specification](https://theupdateframework.github.io/specification/)
- [AWS Labs tough](https://github.com/awslabs/tough)
- [Tough delegated-role threshold advisory](https://github.com/advisories/GHSA-8m7c-8m39-rv4x)
- [Tough 0.24.0 changelog](https://github.com/awslabs/tough/blob/tough-v0.24.0/CHANGELOG.md)
- [Apple Developer ID](https://developer.apple.com/support/developer-id/)
- [Apple ad hoc signature flag](https://developer.apple.com/documentation/security/seccodesignatureflags/adhoc)
- [Apple Secure Enclave key protection](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
