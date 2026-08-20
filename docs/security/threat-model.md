# Supgang repository-backed threat model

Status: implemented M1 review

Date: 2026-08-16

Scope: the source, manifests, protocol, foreground service, and CLI in this repository snapshot.
Future LAN discovery, NAT traversal, router mapping, owned relay, hardware key stores, update, and
release packaging are outside this model because they are not implemented.

## Security objectives

Supgang M1 aims to preserve:

- authenticity of hive membership, device identity, endpoint records, and revocation;
- durability and monotonicity of locally generated endpoint sequences;
- deterministic handling of replay and same-version conflict;
- confidentiality of long-term private keys from other operating-system users;
- bounded memory, frames, queues, candidates, peers, retries, and state files;
- no unexpected public infrastructure dependency or telemetry;
- honest distinction between a signed self-claim, a peer-observed address, and proven session
  identity.

Supgang M1 does not promise:

- reconnection across a network cut with no surviving path;
- anonymity from peers, an ISP, or a local network operator;
- isolation from malware already executing as the same operating-system user;
- protection after kernel compromise or live process-memory disclosure;
- full-disk rollback detection when keys and journals are restored together;
- remote service reachability merely because an address is known;
- post-quantum identity authentication.

## Assets and boundaries

| Asset | Implemented protection | Residual exposure |
| --- | --- | --- |
| Hive root key | Separate root type, mode-0600 checksummed file, zeroized owner object | Online on founder, no Keychain or hardware provider |
| Device key | Generated locally, never exported by join, separate signing domain | Owner-only file and process memory |
| Transport key | Separate certificate key, size and permission checks, signed hash pin | Long-lived until file replacement; no automatic rotation |
| Membership | Root signature, hive and device binding, serial, role, expiry, nonce | Founder is the only M1 administrator |
| Revocation | Root-signed complete monotonic set, immediate notice, durable replay | No rescue flow for a falsely revoked device |
| Endpoint record | Device signature, canonical bytes, sequence, generation, expiry, bounds | Addresses visible to authorized peers |
| Local state | Exclusive lock, framed checksummed append, sync, corruption refusal | Whole-state rollback has no external witness |
| Local control | Mode-0600 Unix socket, same-UID kernel credential, bounded messages | Same-user hostile processes are trusted |
| Network service | TLS 1.3, signed pin, app mutual auth, stateless retry, strict budgets | No per-source rate limiter or packet-flood benchmark yet |

Trust boundaries:

1. **Local filesystem to process.** Files can be missing, truncated, corrupt, symlinked, replaced,
   permissive, or owned by another user.
2. **Local process to control socket.** The kernel supplies peer credentials, but every same-UID
   process is inside the M1 trust boundary.
3. **Internet or LAN to QUIC.** Packets, handshakes, streams, timing, and claimed addresses are
   hostile until application authentication completes.
4. **Authorized peer to state owner.** Membership permits participation, not trust in syntax,
   freshness, observations, or forwarded records.
5. **Hive root to every member.** A valid root signature is authoritative. Root compromise can
   admit, revoke, or equivocate and cannot be repaired by endpoint signatures.
6. **Build inputs to binary.** The Rust toolchain, registry packages, AWS-LC build, CI action, and
   release process can compromise the result.

## Adversaries

- an unauthenticated host sending UDP, QUIC, or malformed stream input;
- an active network intermediary redirecting, replaying, delaying, or dropping traffic;
- a hostile device on the same network;
- an authorized but compromised hive member;
- another local user attempting filesystem or socket access;
- same-user malware, which is explicitly outside the local isolation guarantee;
- an attacker with an old disk image, copied authorization artifact, or stolen device key;
- a compromised dependency, toolchain, CI action, or release credential.

## Implemented invariants

1. No network input changes membership, local sequence, or revocation without the appropriate root
   or device signature and canonical validation.
2. Root, device, transport, membership, invitation, endpoint, session, and revocation roles use
   distinct types or domain strings.
3. A signed endpoint is returned only after its sequence append has synchronized.
4. Exact generation and sequence conflicts preserve evidence and stop automatic resolution.
5. A revoked stable device key is denied dialing, resolution, import, session authentication,
   re-admission, and service startup.
6. 0-RTT is disabled. Application authentication binds both contacts and nonces to the TLS exporter
   and peer-observed sockets.
7. Canonical decoders reject oversize, wrong count, unsupported version, trailing bytes, and
   re-encoding differences before trusted state import.
8. Every current collection and channel has a fixed ceiling. The personal hive is capped at 256
   members, active neighbors at eight, queued peer events at 32, contact pages at eight, endpoint
   candidates at eight, and control replies at 64 KiB.
9. The state directory and sensitive entries must be owner-only regular files or sockets. Symlinks
   and unsafe modes are rejected.
10. Strict mode has no code path for a public resolver, telemetry endpoint, vendor relay, account,
    forced update, or remote kill switch.

## Threat analysis

### T01: root or device key theft

**Attack.** Read the founder root or a device seed and sign valid authorization or endpoints.

**Controls.** Owner and mode validation, checksummed fixed-size key files, separate key types,
zeroization on drop, no secret debug output, recipient-generated join keys, and permanent device
revocation.

**Residual risk.** The owner-only file provider is weaker than Keychain, Secret Service, or hardware
keys. Root theft is catastrophic until a root-rotation and recovery protocol exists. `doctor` keeps
the file provider visible as a warning.

### T02: join artifact interception or replay

**Attack.** Copy, alter, redirect, or replay a request or response bundle.

**Controls.** The request proves possession of a locally retained private key and carries a 256-bit
nonce. The root certificate binds that public key and nonce. A response can be installed only beside
the matching pending secret. Canonical signatures reject alteration. Repeating the same completed
join is idempotent; conflicting state fails closed. Artifact creation is owner-only and no-overwrite.

**Residual risk.** M1 artifacts are signed and recipient-bound, not encrypted. They disclose public
hive and membership metadata to someone who obtains them. The CLI does not automatically erase
carried files.

### T03: endpoint replay and disk rollback

**Attack.** Present an older valid address or restore an old local snapshot.

**Controls.** Generation, strict sequence ordering, expiry, durable reservation before signing,
newest-record merge, and expired-record exclusion from `resolve`.

**Residual risk.** A remembered expired record remains a dial hint because it may recover a newer
record. Authentication still prevents address reassignment from becoming identity takeover. A full
snapshot rollback is not detected externally and generation recovery is not implemented.

### T04: endpoint or root equivocation

**Attack.** A compromised signer emits different valid content at one logical version.

**Controls.** Endpoint conflict is arrival-order independent, retained in bounded evidence, and
removed from automatic dialing and resolution. Different root-signed revocation sets at one serial
are fatal. A newer revocation set cannot remove an existing denial or roll issue time backward.

**Residual risk.** There is no operator command to export or reconcile conflict evidence yet.

### T05: dishonest observed address

**Attack.** An authorized peer lies about the socket address it observed.

**Controls.** Only a global, correctly typed address from an authenticated session can become a
reflexive candidate. It remains a signed self-published hint after the device adopts it. Every later
connection still requires the expected device, membership, certificate pin, and TLS exporter proof.

**Residual risk.** M1 does not retain separate multi-witness observation objects, so it cannot rank
or expose independent witness confidence. A malicious member can waste bounded dial attempts.

### T06: transport impersonation, downgrade, or replay

**Attack.** Redirect to another certificate, weaken TLS, replay early data, or splice application
authentication across sessions.

**Controls.** TLS 1.3 only, signed certificate hash pin, no early data, exact ALPN, random nonces,
domain-separated Ed25519 proofs, and TLS exporter binding. Session parsing and time are bounded.

**Residual risk.** The self-signed transport certificate is stable on disk and has no automatic
rotation policy. Classical Ed25519 authentication remains vulnerable to a future cryptographically
relevant quantum attacker.

### T07: malformed input and memory exhaustion

**Attack.** Send large lengths, nested CBOR, trailing bytes, excessive contacts, candidates,
streams, or events.

**Controls.** Length prefixes are checked before allocation. All canonical objects re-encode exactly.
QUIC receive windows, stream counts, peers, queue capacity, frames, contacts, artifacts, members,
revocations, and journal frames have explicit ceilings. Arbitrary-byte tests cover wire and session
decoders without panics.

**Residual risk.** Coverage-guided fuzzing, allocation instrumentation, and long packet-flood tests
have not run. The QUIC stack and crypto provider remain substantial attack surface.

### T08: connection storm and simultaneous dial

**Attack.** Trigger duplicate application handshakes, retry churn, or control starvation.

**Controls.** One deterministic initiator per node pair, stateless QUIC retry when available,
four-second connect and twelve-second session deadlines, jittered bounded retries, eight active
neighbors, and duplicate rejection.

**Residual risk.** No source token bucket exists. Deterministic direction may lose a path under an
unusual asymmetric firewall where only the higher identifier can initiate; coordinated traversal is
a later milestone.

### T09: unauthorized local control

**Attack.** Another user connects to the service or replaces its socket.

**Controls.** Protected parent directory, non-following type checks, mode-0600 socket, same-UID peer
credential validation on macOS and Linux, bounded request and response, timeouts, and inode-aware
cleanup.

**Residual risk.** Same-UID software is authorized. The socket is not a capability boundary between
applications owned by the user.

### T10: hostile filesystem and crash window

**Attack.** Substitute symlinks, permissive files, partial writes, checksum corruption, multiple
writers, or a stale socket.

**Controls.** Directory ownership and `0700` validation, file ownership and `0600` validation,
nonblocking no-follow opens before file-type validation, safe create semantics, exclusive state
lock, checksummed frames, final-tail recovery only, sync before return, atomic peer compaction, and
stale-socket removal only after ownership and type checks.

**Residual risk.** Filesystem or kernel implementations that lie about durability are outside the
model. Crash injection has covered unit-level tails and initialization windows, not every system
call on every supported filesystem.

### T11: revocation suppression or forgery

**Attack.** Drop a revocation, replay an older list, send an invalid list, or keep a revoked live
connection.

**Controls.** Complete monotonic root-signed snapshots ride every reconciliation. A newer commit is
also pushed immediately on a bounded one-way stream. Invalid peer snapshots close that connection.
The authority filters the target before delivery; after acknowledged delivery it closes the target.
The target persists self-revocation and refuses readiness on restart.

**Residual risk.** A partitioned target cannot learn revocation until it reaches a member with the
new snapshot. It may continue acting within its isolated stale partition. This is inherent without
a reachable authority or third party.

### T12: privacy and unexpected egress

**Attack.** Leak addresses, topology, keys, or identifiers through public services, logs, errors,
URLs, or broad status output.

**Controls.** No telemetry or public service client exists. The service dials only user-supplied or
cryptographically imported candidate sockets. Endpoint addresses enter through a bounded owner-only
file rather than process arguments. Ordinary startup output has no address, ordinary operation has
no logger, and `peers` hides addresses; only exact `resolve` reveals them. Debug implementations
redact secret bytes.

**Residual risk.** Authorized peers necessarily learn endpoint and timing metadata. CLI JSON can be
captured by the caller. Strict-mode egress has not yet been proved inside a Linux network namespace.

### T13: supply-chain compromise

**Attack.** Replace a crate, toolchain, CI action, build script, or release artifact.

**Controls.** Exact direct pins, committed lockfile, deny-by-default dependency-source and permissive
licence policy, reviewed duplicate identities, warnings as errors, forbidden unsafe Rust in
Supgang-owned source, no shell programs, a typed self-hosting quality gate, and commit-pinned CI
actions for RustSec and cargo-deny.

**Residual risk.** The lockfile includes transitive build scripts and AWS-LC native code. Advisory
and licence checks rely on their upstream databases and classifiers. No signed reproducible release
exists, and a compromised toolchain or CI runner remains capable of replacing build output.

## Verification evidence in this snapshot

- 60 library tests cover canonical encoding, signature mutation, cross-hive replay, invitation
  recipient binding, merge ordering, corruption, partial-tail recovery, safe permissions, special
  file rejection, endpoint configuration bounds, locks, transport pinning, mutual authentication,
  revocation monotonicity, control framing, and arbitrary decoder input.
- The quality binary runs format, all-target check, all-feature Clippy with warnings denied, every
  test target, rustdoc warnings, repository policy, exact direct pins, duplicate review, text limits,
  shell exclusion, and unsafe-source exclusion.
- RustSec scanned all 167 locked dependency identities with warnings denied, while cargo-deny
  accepted every supported-target licence and rejected unknown registries and Git sources.
- A macOS two-process scenario proved offline join, bilateral contact import, authenticated QUIC,
  sequence convergence, local control while the service owns state, live root revocation, immediate
  signed notice, target persistence and exit, authority-side resolution denial, `doctor` error, and
  restart denial.
- A separate two-physical-host macOS scenario proved recipient-bound enrollment, direct
  authenticated QUIC, signed-record convergence, bilateral restart recovery, address-redacted
  process surfaces, and contact-tamper rejection without accepted-state change. The redacted record
  is in `docs/validation/2026-08-17-two-host-e2e.md`.

## Release blockers beyond M1

- Native protected key providers and root recovery.
- External rollback witness and generation transition.
- Linux live two-process acceptance, network namespace egress proof, packet-flood ceilings, and
  coverage-guided fuzzing.
- Release-lockfile software bill of materials and retained third-party notices.
- Automatic LAN discovery, difficult-NAT recovery, and owned relay threat models before those
  features exist.
- Signed, reproducible, provenance-bearing packages and service lifecycle acceptance.

Repository: Supgang
Version: source-policy snapshot sha256:2d33c8745ccc9e62492da8af801af04b9aad7275e8509f10bd8f5d6e10526985
