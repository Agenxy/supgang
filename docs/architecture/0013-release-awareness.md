# ADR 0013: Gang release awareness

Status: Accepted for implementation

Date: 2026-11-24

## Context

The owner's request (2026-11-24):

> make sure supgang works and is updated across all members of the gang (supgang should be noticing it's out of date automatically)

Today every installed binary knows only its Cargo package version (`CARGO_PKG_VERSION`, e.g. `0.2.0-alpha.21`). Two problems follow:

1. Rebuilds that share a package version string cannot be told apart by `supgang --version`, `supgang doctor`, or `supgang status`. In the live gang, members running the same version string ran different compiled commits (`93c6a99c...` vs `d959b920...`) with no visible indication.
2. Connected gang members never tell each other what release they are running. When one computer is updated to a newer release, the other members stay silent until someone checks each machine manually.

Supgang already has a verified TUF update and peer-carriage mechanism (`docs/security/secure-updates.md` and `supgang update stage|send|apply|status`). What is missing is lightweight, sovereign, non-enforcing awareness across authenticated gang peers so a computer notices automatically when it is behind or running a different build.

## Decision

Add three pieces, all strictly advisory and bounded:

1. **Build-time release identity.** Every binary embeds both its SemVer package version (`CARGO_PKG_VERSION`) and its source commit at build time.
2. **Ephemeral authenticated-session gossip.** Each running member advertises its release identity to its currently connected, mutually authenticated gang peers over a small bounded QUIC datagram frame on the existing session.
3. **Local notice computation and surfacing.** Each running service compares connected peers' reported release identities against its own using full SemVer 2.0.0 precedence (prereleases included) and commit equality, exposes a structured `update_notice` across CLI, local control, and MCP outputs, and logs one concise notice per newly seen newer version.

Release awareness never fetches from the Internet, never installs or stages a binary, never modifies durable state, and never blocks or degrades any connection or command.

## 1. Build-time release identity

`crates/supgang/build.rs` resolves the source commit at build time with zero extra build dependencies:

1. `.cargo_vcs_info.json` in `CARGO_MANIFEST_DIR` when present (produced by `cargo package` from a clean checkout) and containing a valid 40-character hexadecimal `sha1`. Preferring `.cargo_vcs_info.json` ensures a packaged crate unpacked inside another Git repository never reports that outer repository's `HEAD`.
2. Otherwise, `git rev-parse --verify HEAD` only when `CARGO_MANIFEST_DIR` is inside this workspace's own Git repository (`<git-toplevel>/crates/supgang`) and `git` is available and returns a valid 40-character hexadecimal SHA-1 (normalized to lowercase). In that case, `build.rs` emits `cargo::rerun-if-changed` for the resolved Git `HEAD`, its symbolic ref target when present, and `packed-refs` when present so the embedded commit is never stale.
3. Otherwise, the packaging environment variable `SUPGANG_BUILD_COMMIT` (tracked via `cargo::rerun-if-env-changed=SUPGANG_BUILD_COMMIT`), when set to a valid 40-character hexadecimal string.
4. Otherwise, `"unknown"`.

A crate packaged for crates.io builds cleanly without `git` installed and without a `.git` directory.

Public constants in `supgang_core`:

- `VERSION`: unchanged `CARGO_PKG_VERSION` SemVer string (preserved for update probation health checks, macOS `Info.plist`, and MCP server info).
- `SOURCE_COMMIT`: 40 lowercase ASCII hex characters or `"unknown"`.
- `VERSION_DISPLAY`: `"<VERSION> (<short_commit>)"`, where `<short_commit>` is the first 7 hex characters of `SOURCE_COMMIT` or `"unknown"` (e.g. `0.2.0-alpha.21 (ddf00d8)`).

Surfacing of local release identity:

- `supgang --version` displays `supgang <VERSION> (<short_commit>)`.
- `supgang --json doctor` includes `version` and `commit`.
- `ControlStatus` (local control socket), `supgang status` / `supgang --json status`, `supgang service status`, and MCP `status` include the local and running commit alongside the version. Additive fields carry `#[serde(default)]` so a newer CLI continues to read status from an older running service.

## 2. Authenticated-session gossip

### Channel choice and backward compatibility

Why not change the persisted signed `EndpointRecord` (ADR 0001 / ADR 0002)?

- Endpoint records are persisted in journals, synced across peers, and version-gated (`ENDPOINT_RECORD_VERSION`). Changing them would force a format bump, rewrite durable state for ephemeral runtime telemetry, and risk rejection by older peers.

Why not open a new bidirectional `StreamKind` (`peer_stream.rs`) or unidirectional stream (`sync.rs`)?

- In existing releases, `peer_stream::accept` rejects unknown stream kinds with `StreamError::Invalid`, which terminates `peer_actor` and closes the QUIC connection. Likewise, `revocation_listener` closes the connection on any unidirectional stream that does not decode as a revocation notice.

Why authenticated-session QUIC datagrams (`rendezvous` datagram channel)?

- Every Supgang QUIC connection already enables bounded datagrams (`DATAGRAM_BUFFER_BYTES = 16 KiB`) and runs a single datagram listener (`service/rendezvous.rs`) after mutual device authentication.
- Existing peers explicitly ignore any datagram that fails decoding (the same property `service/liveness.rs` relies on for its 1-byte liveness probe): invalid, unknown, or future-version datagrams are discarded without closing the session.
- Therefore, sending a release-identity datagram to an older peer is completely non-disruptive: the older peer ignores it and keeps the session, sync, and tunnels working normally. When a newer peer connects to an older peer that sends no release identity, the newer peer simply records `None` for that peer.

### Wire format and bounds

A release-identity datagram is a canonical definite-length CBOR array of exactly 4 elements, encoded under the same datagram frame budget and re-encode verification rules as `rendezvous.rs`:

```text
[version:u8 = 1, kind:u8 = 3, release_version:text, source_commit:text-or-null]
```

Bounds and validation enforced before acceptance:

- Total frame length: 1 through `MAX_RELEASE_FRAME_BYTES = 160` bytes (well below `MAX_RENDEZVOUS_FRAME_BYTES = 256` and QUIC datagram MTU).
- Version byte must equal `1`; kind must equal `3` (distinct from rendezvous `REQUEST = 1` and `OFFER = 2`, and from the 1-byte liveness probe `[0]`).
- `release_version`: 1 through `MAX_RELEASE_VERSION_BYTES = 64` ASCII bytes, no control or whitespace characters, and must parse as a valid SemVer 2.0.0 version (`semver::Version::parse`).
- `source_commit`: either CBOR `null` (representing `"unknown"`) or a UTF-8 string of exactly 40 lowercase ASCII hexadecimal characters (`0-9`, `a-f`).
- Canonical CBOR round-trip check and no trailing bytes.

Any frame that violates these rules, exceeds the byte ceiling, or carries an unknown version is silently discarded by the datagram listener without closing or disrupting the authenticated session.

### Emission and retention

- Only sent after mutual device authentication completes (`supervise_connection` / `peer_actor`).
- Sent once immediately on session admission (and on local identity change if ever refreshed), then rate-limited to at most once every 5 minutes (`RELEASE_GOSSIP_INTERVAL = 300 s`) while the session remains live.
- On receive, frames are length-bounded before decoding (`<= MAX_RELEASE_FRAME_BYTES = 160` bytes); anything over the cap or malformed is silently ignored without closing the session. Inbound release updates are rate-limited per connection (at most once per 5 seconds, inside the existing 50 ms global datagram pacing).
- Stored solely in memory on `ActiveConnection` (`peer_release: Option<ReleaseIdentity>`):
  - At most one entry per currently connected authenticated peer (bounded by `max_active_peers`: 8 in device mode, 64 in anchor mode).
  - Automatically cleared when a peer disconnects, expires, is revoked, or is replaced.
  - Never written to journals, peer directories, or any other durable state.
  - Never triggers any update download, staging, or installation.

## 3. Noticing and surfacing

### SemVer precedence and commit comparison

For each currently connected, authorized peer that has reported a valid `ReleaseIdentity`, the service compares the peer's version against the local version using full SemVer 2.0.0 precedence (`semver::Version::cmp_precedence`, which orders major, minor, patch, and prerelease identifiers and ignores build metadata):

1. **Strictly higher SemVer (`peer > local`):**
   - This computer is out of date.
   - `UpdateNotice.kind = "update-available"`.
   - `peer_version` is the highest SemVer reported across all connected peers.
   - `peers` lists the connected peer(s) reporting that highest version (sorted deterministically by `node_id`), each identified by `name`, 8-hex `fingerprint`, `node_id`, `version`, and `commit`. Network addresses are never included.
2. **Equal SemVer (`peer == local`) with differing known commits:**
   - Only when no connected peer has a strictly higher SemVer.
   - Only when both local and peer commits are known (40 hex, not `"unknown"`) and unequal.
   - `UpdateNotice.kind = "build-differs"` (informational: `"build differs"`).
   - `peers` lists the connected peer(s) whose commit differs from the local commit, sorted by `node_id`.
3. **Otherwise (all connected peers are equal commit, unknown commit at equal version, older SemVer, or have not reported):**
   - `update_notice` is `None`.

### Surfaces

`update_notice` (nullable object) is exposed across every requested surface:

- `ControlStatus` (local control socket)
- `supgang --json doctor` and `supgang doctor` (as an advisory `release-awareness` check: `"warning"` for `update-available`, `"ok"` for `build-differs` or up-to-date; never `"error"`)
- `supgang status` and `supgang --json status` (plus `supgang service status`)
- Fleet output (`supgang`, `supgang peers`, `supgang --json peers`), along with optional per-row `release: { version, commit }` for `this_computer` and connected peers that reported one
- MCP `status` and `fleet` tools (with updated `outputSchema` in `assets/mcp-tools.json` and synchronized SDK transcript fixtures)

### Concise logging

The running service keeps a bounded in-memory set of already-logged newer SemVer precedence keys (capped at `MAX_LOGGED_VERSIONS = 64`). When a connected peer reports a strictly higher SemVer not yet in that set, the service emits one concise line to `stderr` naming the newer version, the local version, and the peer's display name and short fingerprint (never an address or secret). Repeated reports of the same version from any peer do not re-log. Equal-version commit differences are not logged to `stderr`.

## Security properties and invariants

- **No telemetry or public egress:** strictly local-gang peer-to-peer over already authenticated QUIC sessions; zero public connections in strict mode.
- **No forced update:** notices are purely advisory; no command, connection, tunnel, or health check is blocked when out of date, and no binary is ever downloaded or installed from a peer-reported identity.
- **Unverified peer-reported claim:** a peer's reported version and commit are treated as self-reported informational data only, separate from TUF-verified update bundles (ADR 0007 and `docs/security/secure-updates.md`). A compromised peer can lie about its version; the worst effect is one bounded advisory notice naming that peer, with zero durable state change and zero execution impact.
- **No address or secret leakage:** `UpdateNotice`, `UpdateNoticePeer`, doctor checks, and log lines identify peers only by display name, short fingerprint, and stable `node_id`, never by IP address, port, or key material.
- **Bounded memory and CPU:** 160-byte wire cap, 64-byte version cap, 40-hex commit cap, 1-second per-peer intake rate limit, 1 in-memory entry per active connection, and 64-entry cap on logged-version deduplication.

## Consequences

Positive:

- Operators immediately see exact version and commit identity in `--version`, `doctor`, and `status`.
- Any gang member running an older release or different build notices automatically once connected to an updated peer, across CLI, service status, fleet output, and MCP tools.
- Older peers keep interoperating without protocol breakage or durable format migration.

Costs:

- Awareness is live-session only: a computer that is stopped or never connects to an updated peer has no `update_notice`.
- Peer reports are self-claimed; verified update provenance remains the job of `supgang update` (TUF).
