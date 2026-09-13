# Supgang repository-backed threat model

Status: corrective WAN review; layered traversal is implemented but physical WAN acceptance is pending

Date: 2026-08-25

Scope: the source, manifests, protocol, foreground and native per-user background service, CLI,
local MCP server, signed computer names, owner-only peer aliases and settings, local interface
discovery, automatic interface-change publication, automatic local-router mapping, and bounded
signed-address history, candidate racing, synchronized bilateral recovery, authenticated
observed-socket introduction, and user-owned anchor mode in this repository snapshot. Future
encrypted LAN discovery, hard-NAT port prediction, owned control relay, hardware key stores,
production release-key ceremonies, reproducible release packaging, and hardware-backed rollback
witnesses are outside this model because they are not implemented.

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
| Revocation | Root-signed complete monotonic set, priority gossip, durable replay | No rescue flow for a falsely revoked device |
| Endpoint record | Device signature, canonical bytes, sequence, generation, expiry, bounds | Addresses visible to authorized peers |
| Display name | Device-signed portable ASCII, bounded bytes, visible fingerprint | A compromised peer can choose a deceptive or duplicate label |
| Local profile | Owner-only atomic replacement, hostname fallback, strict parser | Same-user software can rename the device |
| Peer aliases | Owner-only atomic replacement, unique bounded tags, strict parser | Local convenience only; not authenticated peer identity |
| Address history | Original signed contacts, newest-first deduplication, fixed retry budget | Old endpoints remain locally visible to the dialing process |
| Route-family filtering | Active physical-interface families and directly attached prefixes | Does not claim that a compatible address passes NAT or firewall policy |
| Local settings | Owner-only bounded TOML, strict schema, lock, atomic replacement | Same-user software may change the retry budget within safe bounds |
| Local state | Exclusive lock, framed checksummed append, durable head witness, signed compaction checkpoint, sync, ACL and corruption refusal | Whole-state rollback has no external monotonic witness |
| Local control | Mode-0600 Unix socket, same-UID kernel credential, bounded messages | Same-user hostile processes are trusted |
| Background definition | Protected owner-only executable copy, ancestor validation, atomic mode-0600 definition, direct native manager arguments, bounded readiness wait | Same-user software can replace the binary or definition |
| Local MCP | Bounded stdio, exact protocol revisions, strict schemas, read-only snapshot access | The configured MCP client controls where returned addresses are sent |
| Network service | TLS 1.3, signed pin, app mutual auth, stateless retry, separate task pools including remembered-source reserve, per-source admission, strict buffers | Distributed packet-flood benchmark remains pending |
| Router mapping | Explicit owner opt-in, PCP/NAT-PMP only, global-address validation, signed-update rate limit, unverified provenance, network-change replacement, orderly release | Local gateway protocols are unauthenticated and mapping does not prove outside reachability |
| Peer-assisted traversal | Existing authenticated QUIC channel, directly observed sockets, single-use local intent, normal pin and device proof | Authorized introducer can still lie or suppress; some NATs block the attempt |
| User-owned anchor | Same member authentication, revocation, bounded outbound recovery, and fixed 64-neighbor ceiling | Anchor metadata and availability remain user responsibilities |
| Update authority | Explicit local pin of self-signed TUF root, sequential root rotation, role thresholds, expiry, persistent metadata versions | No Agenxy production root or completed threshold-key ceremony in this source snapshot |
| Update carriage | Owner-only bounded file or typed stream inside an authenticated peer session; root authorization binds issuer, target, digest, length, durable nonce, and short expiry; remote receipt cannot activate | A root holder can authorize repeated valid transfers; transport availability is not guaranteed |
| Installed payload | Exact OS/architecture target, streamed TUF hash and length verification, native executable check, content-addressed owner-only slot, A/B probation and rollback | Same-user malware can replace user-owned code; whole-disk rollback can restore updater state and binaries together |

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
7. **Local process to MCP client.** A same-user client launches `supgang mcp` and receives requested
   peer addresses and identifiers over inherited standard I/O. The client and its model boundary are
   not controlled by Supgang.
8. **Local process to attached gateway.** Automatic mode sends PCP or NAT-PMP requests to the current
   gateway. UPnP is disabled. Gateway replies are untrusted address and lease inputs, not identity
   or proof of outside reachability.
9. **Local process to operating-system service manager.** The user explicitly installs an
   owner-scoped launchd or systemd definition. Manager acceptance is not readiness; the protected
   local control channel must answer before installation or restart succeeds.
10. **Authenticated member to traversal scheduler.** A member may forward a socket observation only
    inside an authenticated connection. The receiving process treats it as one short-lived dial
    hint, never as identity, authorization, reachability proof, or durable endpoint state.
11. **Update courier to local release policy.** A peer may carry bytes only after mutual session
    authentication and a short-lived hive-root authorization for the exact issuer, receiver, and
    digest. That authorization permits bounded processing, not execution. The receiver's separately
    pinned TUF root and persisted metadata state decide whether the candidate may run.

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
   members, active neighbors at eight or 64 in explicit anchor mode, unauthenticated inbound and
   recovery outbound sessions at separate eight-task ceilings, pending transport handshakes at 64
   and 1 MiB total, pending traversal intents at 16, queued peer events at 32, contact pages at eight,
   endpoint candidates at eight, and control replies at 64 KiB.
9. The state directory, persisted service executable, service definition, endpoint policy, and
   sensitive entries must be below non-replaceable ancestor directories and must have the required
   owner-only file or socket type and mode. Unsafe symlinks and writable ancestors are rejected.
10. Strict mode has no code path for a public resolver, telemetry endpoint, vendor relay, account,
    forced update, or remote kill switch.
11. Peer names and local tags are labels only. Authorization, merge, session authentication,
    revocation, and durable lookup remain keyed by the full stable node ID.
12. Automatic interface discovery enumerates the local kernel table. Automatic router mapping sends
    only PCP or NAT-PMP traffic to the attached gateway; UPnP is disabled. Only a globally routed
    mapping result can enter the current signed record, with mapping changes limited to four signed
    updates per five minutes and labeled unverified until independently observed through an
    authenticated session. An interface change removes the old mapping and peer observations before
    the replacement set is signed. Four candidate slots remain available for the most recent
    authenticated public-address observations. Known tunnel, container, peer-to-peer, and virtual
    bridge interfaces are not automatically published.
13. Historical recovery uses only previously device-signed contacts, retains at most the configured
    8 through 64 unique old addresses per peer, and never presents them as current output.
14. MCP exposes exactly three read-only tools. Requests, responses, and structured values have
    separate fixed ceilings, unknown arguments fail closed, standard output carries protocol only,
    and offline snapshots never create or repair durable state.
15. Traversal datagrams are canonical, versioned, capped at 256 bytes, and accepted only on a
    mutually authenticated session. Each connection parses at most 20 frames per second, accepts at
    most one request per second and four offers per second, and stores frames only in fixed transport
    and event buffers. An offer can schedule a dial only after a recent local recovery choice for
    that exact stable target, only globally routed sockets are accepted, and that choice is consumed
    once.
16. The first TUF root can be pinned only through an explicit local owner-only file. A peer cannot
    create or replace that trust root. TUF metadata and targets have fixed byte and entry ceilings;
    expiry, role signatures, thresholds, sequential root updates, metadata rollback, exact target
    length and SHA-256, operating system, architecture, semantic-version advance, and native binary
    format all fail closed.
17. Peer-carried updates use a typed post-authentication QUIC stream. The root authorization is
    verified before a large body is accepted, transfer length and digest are exact, trailing bytes
    are rejected, and one shared admission permit plus a cross-process filesystem lock permits only
    one update operation at a time. The stream carries no command, shell text, destination path, or
    trust root.
18. The installed supervisor remains at a fixed protected path while payloads occupy
    content-addressed slots. A candidate must answer through the owner-only control socket for the
    full probation window. Candidate failure clears its activation record, removes its unused slot,
    and returns to the last known-good payload. Supervisor and candidate update state cannot race.
16. A traversal offer never enters a signed record or peer history. It can only start a bounded
    attempt using the target's independently verified membership, stable identity, and transport
    key pin.

## Threat analysis

### T01: root or device key theft

**Attack.** Read the founder root or a device seed and sign valid authorization or endpoints.

**Controls.** Owner and mode validation, checksummed fixed-size key files, separate key types,
fixed-ceiling reads whose temporary secret buffers are cleared immediately after decoding,
zeroization on drop, no secret debug output, recipient-generated join keys, and permanent device
revocation. The service creates one independently zeroized process-local device-key copy for its
bounded network-session actor; it is never serialized or shared outside the process.

**Residual risk.** The owner-only file provider is weaker than Keychain, Secret Service, or hardware
keys. Root theft is catastrophic until a root-rotation and recovery protocol exists. `doctor` keeps
the file provider visible as a warning.

### T02: join artifact interception or replay

**Attack.** Copy, alter, redirect, or replay a request or response bundle.

**Controls.** The request proves possession of a locally retained private key and carries a 256-bit
nonce. The root certificate binds that public key and nonce. A response can be installed only beside
the matching pending secret. Canonical signatures reject alteration. Repeating the same completed
join is idempotent; conflicting state fails closed. Before mutation, the authorizing computer also
requires the operator-confirmed joining `NodeId`, and the joining computer requires the
operator-confirmed `HiveId`. The documentation requires comparing those values over a separate
channel. Artifact creation is owner-only and no-overwrite.

**Residual risk.** M1 artifacts are signed and recipient-bound, not encrypted. They disclose public
hive and membership metadata to someone who obtains them. The CLI does not automatically erase
carried files.

### T03: endpoint replay and disk rollback

**Attack.** Present an older valid address or restore an old local snapshot.

**Controls.** Generation, strict sequence ordering, expiry, durable reservation before signing,
newest-record merge, expired-record exclusion from `resolve`, and a newest-first, deduplicated,
bounded history of the original signed contacts for recovery attempts only. Authoritative history
compacts at 1 MiB to a canonical device-signed checkpoint binding the full membership and revocation
snapshot, generation, sequence, hive, and node. Replay rejects checkpoint tampering and later
non-monotonic events.

**Residual risk.** A remembered expired record remains a dial hint because it may recover a newer
record. Its transport-key pin and fresh mutual session authentication still prevent address
reassignment from becoming identity takeover. A full snapshot rollback is not detected externally
and generation recovery is not implemented.

### T04: endpoint or root equivocation

**Attack.** A compromised signer emits different valid content at one logical version.

**Controls.** Endpoint conflict is arrival-order independent, retains only the first conflicting
record as bounded evidence, and is removed from automatic dialing and resolution. Further conflict
variants append nothing, and legacy duplicate histories compact deterministically. Different
root-signed revocation sets at one serial are fatal. A newer revocation set cannot remove an existing
denial or roll issue time backward.

**Residual risk.** There is no operator command to export or reconcile conflict evidence yet.

### T05: dishonest observed address

**Attack.** An authorized peer lies about the socket address it observed.

**Controls.** Only a public, correctly typed address from an authenticated and admitted session can
become a short-lived reachability claim. The observing reporter signs the claim and its current
root-authorized membership travels with it. The claim names reporter and subject separately, is
memory-only, expires quickly, and never advances or rewrites the subject's durable signed endpoint
sequence. Self-claimed reflexive observations are rejected. Duplicate or over-capacity connections
cannot mutate durable state. Every later connection still requires the expected device,
membership, certificate pin, and TLS exporter proof.

**Residual risk.** M1 does not require a witness quorum. A malicious authorized reporter can waste
bounded dial attempts or suppress an observation, but cannot forge the subject's signature, make
the report durable, or impersonate the target.

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
QUIC receive windows, stream counts, pending Initials, per-attempt and total handshake buffers,
peers, queue capacity, frames, contacts, artifacts, members, revocations, and journal frames have
explicit ceilings. Arbitrary-byte tests cover wire and session decoders without panics.

**Residual risk.** Coverage-guided fuzzing, allocation instrumentation, and long packet-flood tests
have not run. The QUIC stack and crypto provider remain substantial attack surface.

### T08: connection storm and simultaneous dial

**Attack.** Trigger duplicate application handshakes, retry churn, or control starvation.

**Controls.** Either peer may make a bounded recovery attempt when the pair has no active session,
which avoids making reconnection depend on node-ID ordering. The preferred lower-ID outbound
direction retries every round. The secondary direction probes once per four rounds. Every member of
one hive derives the same retry boundary, with a hive-specific phase to spread unrelated fleets.
Each attempt races at most four ranked candidates with 125 ms spacing. Stateless QUIC retry is used
before application admission. Four-second connect and twelve-second session deadlines, eight active
neighbors or 64 in explicit anchor mode, separate eight-task general inbound and outbound pools,
plus two remembered-source inbound slots, and
bilateral fallback admission plus deterministic preferred-connection replacement bound simultaneous
dialing. Both endpoints classify the same reverse-direction connection as fallback, so one side
cannot discard a session that the other side retained. One IPv4 source or
native IPv6 `/64` can start at most one session in 30 seconds. The 64-entry source table evicts its
oldest window rather than locking out new sources when full. QUIC and application handshakes run
outside the state-owning loop, and network acceptance is selected concurrently with same-user local
control. Any reconciliation, revocation, or traversal listener exit closes the QUIC transport and
cancels its siblings with a bounded closure notification.

**Residual risk.** A distributed attacker with enough distinct IPv4 addresses or IPv6 `/64`
prefixes can still fill the globally bounded inbound pool. Reserved outbound recovery remains
available, but application code cannot guarantee availability against volumetric denial of service.
Router mapping can create a path only when the attached gateway supports it and the host firewall
permits inbound UDP. Bilateral attempts cannot cross every CGNAT, endpoint-dependent NAT, closed
inbound firewall, or topology with no reachable path.

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

**Controls.** The full normalized ancestor chain rejects directories writable by another user and
replaceable non-platform symlinks before state creation or open. Directory ownership and `0700`
validation, file ownership and `0600` validation, descriptor-based rejection of non-owner extended
ACL grants, inherited-ACL clearing on new protected objects, nonblocking no-follow opens before
file-type validation, safe create semantics, exclusive state lock, checksummed frames, a durable
head witness that rejects committed-tail rollback, sync before return, atomic authoritative and peer
compaction, and stale-socket removal only after ownership and type checks.

**Residual risk.** Filesystem or kernel implementations that lie about durability are outside the
model. A coherent restore can roll back journal and witness together without an external monotonic
anchor. Crash injection has covered unit-level tails and initialization windows, not every system
call on every supported filesystem.

### T10a: background-service substitution or false readiness

**Attack.** Replace the executable or service definition, inject shell syntax through a path, run a
second unmanaged process, collect peer data from service logs, or make manager registration look
like successful startup.

**Controls.** Installation opens the current executable without following the final symlink,
validates the stable file descriptor, copies at most 128 MiB into a dedicated owner-only directory,
synchronizes it, and atomically replaces the protected service executable. Every later status,
start, and restart revalidates that copy and its complete ancestor chain. Definition directories
must be real and owner-controlled. Definitions are bounded, written mode 0600, synchronized, and
atomically replaced. Arguments are encoded directly for launchd or systemd without a shell. Paths
with unsafe encoding or control characters are rejected. An optional endpoint policy and its parent
chain are validated before its canonical path enters the definition. Ordinary output goes to the
null device.
Install and start reject an already responsive unmanaged process. Success requires a bounded answer
from Supgang's owner-only, same-user control socket after the native manager accepts the request.
Uninstall removes only the background definition and preserves Supgang state.

An optional macOS boot installation has a separate root-owned definition under
`/Library/LaunchDaemons`. Its complete property list is checked against the allowed owner UID,
executable, state path, arguments, null output destinations, and startup policy. No extra program,
environment, group, Mach service, or socket grants are accepted. The network program and supervisor
run as the ordinary owner; they never acquire root privileges. The administrator setup script is
a locally reviewed trust decision, not an unattended privileged broker. It uses the macOS-owned
isolated Python interpreter for its privileged portion and drops to the target UID before executing
Supgang. Same-user compromise during an administrator's approval remains outside the protection
of an owner-controlled install.

The owner-only IPC restart command is absent from the network protocol. A random runtime instance
identifier must change before restart is reported complete. System boot registrations cannot be
stopped, replaced, or removed by the unprivileged CLI. The reviewed owner setup script performs
those operations with explicit administrator authorization. Migration preserves a recovery copy
and removes the login registration from the directory scanned at login.

**Residual risk.** Same-user malware remains trusted and can replace owner-controlled files. The
per-user service starts only within a user session. macOS boot registration requires administrator
setup, and FileVault may require disk unlock after reboot before owner state is available.
Linux persistence after logout also depends on
the system's user-session policy. Definition rendering and protected-copy behavior have unit
coverage, but live Linux systemd acceptance remains pending.

### T11: revocation suppression or forgery

**Attack.** Drop a revocation, replay an older list, send an invalid list, or keep a revoked live
connection.

**Controls.** Complete monotonic root-signed snapshots ride every reconciliation and are processed
before contact or reachability mutations. A paced bounded intake stream avoids per-peer detached
fanout tasks and serial-only durable churn. Invalid peer snapshots close that connection. Local
authorization is invalidated before a revoked connection can emit more work. The target persists
self-revocation and refuses readiness on restart.

**Residual risk.** A partitioned target cannot learn revocation until it reaches a member with the
new snapshot. It may continue acting within its isolated stale partition. This is inherent without
a reachable authority or third party.

### T12: privacy and unexpected egress

**Attack.** Leak addresses, topology, keys, or identifiers through public services, logs, errors,
URLs, or broad status output.

**Controls.** No telemetry or public service client exists. Interface discovery reads only the
kernel table. Router mapping is default-off, requires explicit owner opt-in, and is limited to PCP or NAT-PMP traffic with the attached
gateway; UPnP is disabled. The service dials only locally discovered, gateway-mapped, user-supplied,
authenticated-peer-observed, or cryptographically imported candidate
sockets. Explicit addresses enter through a bounded owner-only file rather than process arguments.
Startup has no address output and ordinary operation has no logger. The user-invoked bare command
and `peers` intentionally display a compact local fleet view. `peers --all`, `resolve`, and JSON
expose only the latest accepted address set; historical recovery addresses are never returned by
CLI, control, or MCP output. Detailed human rows include `device-signed` provenance. Debug
implementations redact secret bytes.

**Residual risk.** Authorized peers necessarily learn endpoint and timing metadata. CLI JSON can be
captured by the caller. Strict-mode egress has not yet been proved inside a Linux network namespace.

### T13: supply-chain compromise

**Attack.** Replace a crate, toolchain, CI action, build script, or release artifact.

**Controls.** Exact direct pins, committed lockfile, deny-by-default dependency-source and narrow
licence policy, reviewed exact duplicate identities, warnings as errors, forbidden unsafe Rust in
portable Supgang source, one policy-checked descriptor-ACL FFI boundary, no shell programs, a typed self-hosting quality gate, and commit-pinned CI
actions for RustSec and cargo-deny. The disabled transitive UPnP implementation still brings an
MPL-2.0 HTTP client into the dependency graph; it is allowed only by exact package exception and
requires retained release notices. One exact unmaintained-only RustSec notice for the Linux
`netlink-packet-core` compile-time macro is documented in
`docs/security/dependency-exceptions.md`; every other audit warning remains fatal.

**Residual risk.** The lockfile includes transitive build scripts and AWS-LC native code. Advisory
and licence checks rely on their upstream databases and classifiers. No signed reproducible release
exists, and a compromised toolchain or CI runner remains capable of replacing build output.

### T14: deceptive names and identity confusion

**Attack.** An authorized or compromised device chooses another computer's name, a control
sequence, a terminal escape, or a visually confusable label so an operator acts on the wrong node.

**Controls.** Names are restricted to 1 through 63 portable ASCII letters, digits, spaces, dots,
underscores, and hyphens. They are signed in endpoint record v2, but every human row also shows an
immutable eight-character node fingerprint. Owner-only local tags use a smaller shell-friendly
alphabet and are unique case-insensitively. CLI selection first uses exact name, tag, fingerprint,
or full node ID, then returns every significantly matching partial or fuzzy name and tag instead of
silently choosing one. Revocation still requires the full 64-character node ID.

**Residual risk.** Names remain device-controlled labels and tags remain same-user-controlled local
labels. Similar allowed ASCII names can still mislead a hurried operator. The short fingerprint is
a usability checksum, not the full collision security of the node ID.

### T15: update forgery and false peer health

**Attack.** A mirror, CI runner, release credential, compromised peer, or network intermediary
delivers a malicious or old binary, or a peer signs a false claim that it runs trusted software.

**Controls.** The updater starts only from a root explicitly pinned on the receiving computer and
uses `tough` 0.24.0 with file-only transport, safe expiry enforcement, fixed metadata limits,
persistent rollback state, and sequential root rotation. Target naming binds semantic version,
operating system, and architecture; TUF binds exact length and SHA-256. Verified bytes stream into a
new owner-only content-addressed slot and are parsed as the expected native executable before an A/B
supervisor may launch them. A peer-carried bundle additionally needs a short-lived hive-root
authorization bound to the authenticated issuer, exact receiver, digest, byte length, and a durably
single-use nonce. Receipt verifies and stages only; only a separate local owner command writes the
activation request. The peer is not a release authority. No network message can pin the first TUF
root, select a filesystem path, invoke a shell, or trigger execution. The complete workflow and remaining production gates are in
`docs/security/secure-updates.md`.

**Residual risk.** The repository does not yet contain a production Agenxy root or evidence of the
planned threshold-key ceremony and reproducible cross-platform artifacts. A compromised threshold
of TUF targets keys can authorize malicious code. A compromised hive root can authorize repeated
processing of an otherwise valid bundle but cannot forge TUF metadata. Same-user malware can alter
the user-owned installation, and a restored full-disk snapshot can roll back binaries and local TUF
state together. A software-health attestation protocol is not implemented; a legitimate device key
still cannot prove that its operating system is uncompromised.

### T16: MCP disclosure, confused agency, and local denial of service

**Attack.** A same-user MCP client requests private topology and transmits it to an unintended model
or service, presents a signed address as proof of reachability, passes malformed or oversized JSON,
or attempts to turn the server into a write or network primitive.

**Controls.** The MCP process communicates only through inherited standard input and output. It has
no HTTP listener, remote authentication surface, subprocess bridge, telemetry, or public client.
It exposes only `fleet`, `resolve`, and `status`, with closed input schemas and read-only,
non-destructive, idempotent, closed-world annotations. Requests stop at 16 KiB, responses at 256 KiB,
and structured values at 96 KiB. Offline access uses validating no-repair snapshots. Server
instructions distinguish device signatures from reachability and state that the client controls the
result destination.

**Residual risk.** The user authorizes a configured MCP client to receive peer addresses and stable
identifiers. Supgang cannot prevent that client, its model provider, terminal capture, or same-user
malware from retaining or forwarding them. Tool annotations guide clients but are not a sandbox.
The MCP process can briefly contend for CPU and filesystem reads within its fixed per-message and
fleet-size ceilings.

### T17: malicious gateway or false mapping result

**Attack.** A hostile local gateway answers an unauthenticated PCP or NAT-PMP request with a false
public address, redirects the mapping, withholds renewal, or keeps a lease after the computer
changes networks.

**Controls.** Supgang requests a mapping only for its own bound UDP port and disables UPnP's
redirectable HTTP discovery. It accepts only a globally routed IPv4 mapping, removes only its own
prior automatic candidate before signing a replacement, and limits gateway-driven signatures to
four per five minutes. It restarts discovery after an interface change and requests lease deletion
during orderly shutdown. The gateway result is labeled `router-mapped-unverified` and is tried ahead
of incidental global-looking interface addresses when the peer is off-link. It becomes
`peer-confirmed-address` only after an authenticated peer independently reports the public socket.
Any incoming connection must still complete pinned TLS and channel-bound mutual device
authentication before it counts as connected or changes peer state.

**Residual risk.** These gateway protocols do not authenticate the router. A hostile gateway can
waste bounded connection attempts, expose the local UDP listener, lie about lease state, or ignore
deletion. It cannot forge a member identity without the corresponding device key. Abrupt process or
power loss may leave a lease until the gateway's own expiry.

### T18: malicious introducer, traversal replay, or anchor exhaustion

**Attack.** A compromised authorized member sends forged or replayed socket offers, causes peers to
send traffic to a victim, enumerates connection metadata, floods an anchor's neighbor table, or
claims that an observed socket proves a peer is reachable or uncompromised.

**Controls.** Traversal messages exist only as QUIC datagrams after mutual hive authentication.
Frames are canonical, versioned, and capped at 256 bytes. Each connection parses at most 20 frames
per second, accepts at most one request each second, and accepts four offers each second. The
built-in response to a request produces at most two offers, only when both named members are
currently authenticated, and copies sockets from the introducer's QUIC connection objects.
Receivers still treat every offer as untrusted. The receiver
must have independently selected that stable target for recovery within 30 seconds, and the first
accepted offer consumes the intent. Private, loopback, and link-local sockets are rejected. At most
16 intents and 16 session tasks exist. The offered socket is never persisted and the resulting QUIC path must match the signed transport key,
root-authorized member, channel-bound device proof, and non-revoked stable identity. Anchor mode
accepts at most 64 authenticated members, participates in the same bounded recovery dial schedule,
and never relays general application traffic.

**Residual risk.** An authorized introducer can lie about an offer it originates, withhold an
introduction, reveal that two authorized members are online, or spend one bounded attempt after a
member has already chosen that target. A compromised member with a valid key remains authorized
until root revocation reaches the partition. Source-address spoofing, QUIC implementation defects,
and packet floods below the application authentication boundary require transport and operating
system defenses. The anchor is a user-operated availability point, not a claim that its host or
network is uncompromised. Endpoint-dependent NAT, blocked UDP, anchor failure, or simultaneous loss
of every known edge can still prevent recovery.

## Verification evidence in this snapshot

- More than 120 library tests cover canonical encoding, v1-to-v2 verification, signed names, owner-only tags
  and settings, exact and fuzzy peer selection, compact fleet output, dual-era MCP lifecycle and
  metadata, bounded MCP framing, read-only offline snapshots, hidden historical addresses,
  newest-first bounded recovery, current-address retry priority, interface-change publication,
  direction-prioritized bilateral recovery attempts, stale connection-event rejection,
  interface-prefix selection, signature mutation, cross-hive replay, invitation recipient binding,
  merge ordering, corruption, partial-tail recovery, safe permissions, special-file rejection,
  endpoint configuration bounds, locks, transport pinning, mutual authentication, revocation
  monotonicity, control framing, global router-mapping validation, mapping retirement after network
  change, mapped-candidate dial and display priority, synchronized retry boundaries, candidate race
  spacing, canonical traversal datagrams, arbitrary traversal bytes, single-use intent gating,
  symmetric observed-socket forwarding over real QUIC, anchor connection selection, and arbitrary
  decoder input.
- The quality binary runs format, all-target check, all-feature Clippy with warnings denied, every
  test target, rustdoc warnings, repository policy, exact direct pins, duplicate review, text limits,
  shell exclusion, and unsafe-source exclusion.
- RustSec scans the complete locked dependency graph with every warning denied except the one
  documented unmaintained-only Linux packet-macro notice. Cargo-deny accepts every supported-target
  licence and rejects unknown registries and Git sources.
- A macOS two-process scenario proved offline join, bilateral contact import, authenticated QUIC,
  sequence convergence, local control while the service owns state, live root revocation, immediate
  signed notice, target persistence and exit, authority-side resolution denial, `doctor` error, and
  restart denial.
- A separate two-physical-host macOS scenario proved recipient-bound enrollment, direct
  authenticated QUIC, signed-record convergence, bilateral restart recovery, address-redacted
  process surfaces, and contact-tamper rejection without accepted-state change. The redacted record
  is in `docs/validation/2026-08-17-two-host-e2e.md`.
- A network-denied macOS sandbox run proved automatic endpoint publication succeeds using only the
  local interface table, with every network operation denied by the operating system.
- A physical outside-network rerun failed: Laptop A published its new local state and attempted its
  remembered Home B addresses, but no authenticated session formed and no newer Home B record
  arrived. The redacted record is in
  `docs/validation/2026-08-17-wan-acceptance-failure.md`. Router mapping has unit coverage but has
  not passed the required installed-build physical WAN rerun.

## Release blockers beyond M1

- Installed-build Laptop A-to-Home B acceptance from separate networks, including current
  connection reporting, mapped-address replacement, and address convergence after roaming.
- Host-firewall diagnosis and acceptance for the mapped UDP listener.
- Native protected key providers and root recovery.
- External rollback witness and generation transition.
- Linux live two-process acceptance, network namespace egress proof, packet-flood ceilings, and
  coverage-guided fuzzing.
- Release-lockfile software bill of materials and retained third-party notices.
- Encrypted LAN discovery, hard-NAT port prediction, and owned control-relay threat models before
  those features exist.
- TUF root ceremony, signed reproducible provenance-bearing packages, adversarial update
  acceptance, and cross-host background-service lifecycle acceptance.

Repository: Supgang
Version: 0.2.0-alpha.10 source snapshot; same-build physical WAN acceptance pending
