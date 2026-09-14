# Supgang

Supgang is a sovereign address plane for a person's own computers. It gives each computer a stable
cryptographic identity and lets authorized members exchange fresh, signed network addresses even
when the addresses themselves change.

Supgang has no account, telemetry, public discovery service, DNS publisher, vendor relay, remote
kill switch, or required server. Strict operation uses only the computers and network paths the
user supplies.

Status: failed wide-area acceptance. Version 0.1.0 exchanged signed addresses on one local network,
but it did not reconnect Laptop A and Home B after Laptop A moved to an outside network. That
release therefore does not satisfy Supgang's primary use case. The redacted failure record is in
[the WAN acceptance report](docs/validation/2026-08-17-wan-acceptance-failure.md).

This unreleased tree adds owner-enabled local-router mapping, raced address attempts, synchronized
bilateral recovery, authenticated peer-assisted UDP hole punching, an explicit user-owned anchor
mode, honest live connection status, and native per-user background service management. Those
changes are not accepted until installed builds reconnect Laptop A and Home B from separate
networks. Native key stores, topology health, an owned control relay, and the production release-key
ceremony remain later work. Do not treat the current source or 0.1.0 as a production remote-access
guarantee.

## What works now

- One self-certifying hive root and stable Ed25519 identity per computer.
- Recipient-generated, proof-of-possession join requests. A private device key never leaves the
  computer that created it.
- Root-signed, expiring membership certificates and permanent root-signed device revocation.
- Canonical, size-bounded CBOR for memberships, invitations, endpoint records, gossip, and
  revocation snapshots.
- Crash-safe sequence reservation and checksum-framed journals with a durable head witness,
  committed-tail rollback detection, corruption refusal, exclusive ownership, and atomic
  peer-cache compaction.
- TLS 1.3 QUIC with a signed certificate pin, disabled 0-RTT, channel-bound mutual application
  authentication, bounded streams, and small authenticated anti-entropy pages.
- Automatic active-interface discovery for private local, global IPv4, and global IPv6 candidates,
  with live interface-change detection and an owner-only explicit configuration override. Tunnel,
  container, peer-to-peer, and virtual bridge interfaces are excluded from automatic publication.
- Explicitly owner-enabled renewable UDP router mapping through PCP or NAT-PMP when the local
  gateway supports it. Mapping is off unless `--router-mapping` was selected.
  A scope-checked gateway result is rate-limited and advertised with unverified mapping provenance;
  it becomes peer-confirmed only after an authenticated connection reports the public socket. The
  lease is replaced after a network change or removed on orderly shutdown. UPnP is disabled because
  an unauthenticated LAN responder can redirect its HTTP discovery. Physical wide-area acceptance
  is still pending.
- Device-signed, bounded computer names derived from the operating-system hostname and replaceable
  by the user. Stable node fingerprints remain visible and authoritative.
- Authenticated peer observation of global source addresses. An observation is never accepted as a
  device identity or authorization by itself.
- Deterministic long-lived connection selection, hive-synchronized bilateral recovery attempts,
  tightly staggered candidate racing, graceful shutdown, and bounded root-signed revocation gossip
  over established links. Network handshakes run in fixed-size general and remembered-source task
  sets so a dead or hostile address cannot freeze local control.
- Members explicitly authorized as introducers can introduce two other currently authenticated
  members by forwarding only the source sockets they directly observe. Both computers use the same bound UDP socket for a
  simultaneous attempt. An offer is short-lived, single-use, and accepted only after that computer
  independently chose to recover the named peer. Only globally routed sockets are accepted, and an
  offer never becomes durable address state.
- `supgang anchor` and `supgang service install --anchor` turn an ordinary user-owned member into an
  always-on meeting point with a fixed 64-neighbor ceiling. Devices connect outward to it, exchange
  signed records through it, and use it to coordinate direct-path attempts. It is not a public
  service or a general traffic relay.
- An owner-only local Unix socket with same-UID peer checks, allowing `status`, `doctor`, `peers`,
  `resolve`, and `revoke` while the service owns mutable state.
- Native per-user background operation through launchd on macOS and systemd on Linux, with a
  protected owner-only executable copy, validated ancestor directories, bounded readiness checks,
  automatic restart, suppressed ordinary logs, and uninstall behavior that preserves identity and
  peer history.
- Sovereign signed updates carried by a file or an already authenticated peer. Each computer pins
  its initial TUF root through an explicit local command, persists rollback state, streams a bounded
  OS-and-architecture-specific target into an owner-only content-addressed slot, and independently
  verifies signatures, thresholds, expiry, versions, lengths, and hashes. A stable installed A/B
  supervisor keeps the last known-good payload and rolls back a candidate that cannot stay healthy.
  A peer is only a courier: the hive root authorizes one exact digest and length for one connected
  computer, while the separate TUF authority decides whether those bytes may run. Remote receipt
  only verifies and stages bytes. Only an explicit local `supgang update apply` can request A/B
  activation. There is no shell, arbitrary path, forced update, default Internet source, or vendor
  kill switch.
- A zero-argument fleet view with this computer, peer names, short fingerprints, and the most useful
  local and public addresses. Complete candidates and provenance remain one explicit command away.
  There is no background logging of secrets or peer addresses.
- Owner-only local peer tags, such as `home`, plus bounded partial and typo-tolerant lookup. Tags
  never replace, modify, or synchronize the peer's stable cryptographic identity.
- A configurable history of authenticated peer addresses. The default is 16 per peer, with a fixed
  supported range of 8 through 64. Old addresses are retry hints only and are never shown as current.
- A local read-only MCP server for Codex and other compatible agents. It supports the 2025-11-25
  lifecycle and the stateless 2026-07-28 protocol without an account, listener, hosted service, or
  subprocess bridge.

## The irreducible boundary

Supgang does not create information from nothing. If every remembered address is dead, every live
connection is gone, and no authorized computer remains reachable from another partition, there is
no path over which a changed address can travel.

The implemented guarantee is conditional:

> If an authenticated path survives across each relevant partition, newer valid endpoint and
> revocation records converge. If no path survives, Supgang retains signed hints and waits for a
> path to return.

This is why two computers behind one router are less resilient than computers across independent
sites. The implemented user-owned anchor and peer-introduction modes add paths, but they cannot
eliminate the same network cut. If two isolated computers both change to unknown addresses while no
third member is reachable, automatic recovery may have nothing to contact.

## Build and install

Rust 1.97.1 is pinned in `rust-toolchain.toml`. Direct Rust dependencies are exactly pinned and the
lockfile is committed.

```text
make check
make install
supgang --version
supgang --help
```

`make install` replaces the current source installation in `$HOME/.local/bin`, which should precede
package-manager paths in `PATH`. It uses Cargo's frozen mode and therefore does not refresh the
registry or download dependencies. Milestone acceptance uses this installed command from outside
the repository; invoking `target/release/supgang` is build evidence, not installation evidence.

On macOS, an owner-controlled code-signing identity can give successive local builds one stable
application identity without an Apple Developer Program subscription. Pass the exact 40-character
identity hash shown by `security find-identity -v -p codesigning`:

```text
make install MACOS_CODESIGN_IDENTITY=0123456789ABCDEF0123456789ABCDEF01234567
```

The signing identity must be that exact 40-character hash; Supgang's stable identifier is fixed and
cannot be overridden. If a background service was already installed, propagate the newly signed
bytes into its protected supervisor and active A/B slot, then verify the running service:

```text
supgang service refresh
supgang service status
```

`service refresh` preserves the installed service's endpoint, anchor, and router-mapping settings
exactly. Use `service install` only when you intend to choose those settings again.

The corresponding owner certificate must be trusted through an explicit local macOS approval.
This is separate from TUF release authorization. TUF decides which bytes are an authorized Supgang
release; the local code signature lets macOS recognize an approved program across updates. Every
macOS update target must retain the same approved designated requirement. Staging, activation, and
the supervisor all reject a target with an invalid or different macOS identity before execution.

The crates.io `0.1.0` package is the failed WAN build described above. Do not use it to evaluate the
corrective source tree. After a corrected version passes the physical WAN gate and is published, the
registry install form will be:

```text
cargo install --locked supgang
```

The registry command uses Cargo's configured binary directory. Installation itself does not install
a background service, change the firewall, alter a router, create a TUN device, or contact a
Supgang service. `supgang service install` is the separate, explicit background-service step. When
automatic discovery runs with `--router-mapping`, the process asks only the attached local gateway
for a renewable UDP port mapping through PCP or NAT-PMP. UPnP is disabled because its unauthenticated discovery can
redirect clients to another LAN service. A scope-checked gateway-reported address is shared as a
rate-limited, unverified dial hint. It is reported as peer-confirmed only after an authenticated peer
independently reports the public socket. Supgang does not contact a hosted service.

Secure updates require the background service because its protected supervisor performs the
health-checked handoff. Before accepting any local or peer-carried release, each computer pins the
same reviewed initial root locally:

```text
supgang update trust ./root.json
supgang update status
```

An operator with a separately signed TUF repository can create a portable bundle and either stage
it locally or queue it for one peer. The background service retains at most four deliveries for 24
hours and retries when an authenticated connection becomes available:

```text
supgang update bundle --metadata ./metadata --targets ./targets \
  --target supgang-VERSION-OS-ARCH ./supgang-update.bundle
supgang update stage ./supgang-update.bundle
supgang update apply
supgang update send home ./supgang-update.bundle
```

The `send` command authorizes only that bundle digest, byte length, and peer. The receiver repeats
the full TUF verification and stages the candidate without activating it. The receiving owner runs
`supgang update apply` locally before the supervisor may try it. Supgang does not generate or hold release
keys. Agenxy's production threshold-key ceremony, reproducible multi-platform release artifacts,
and two-physical-host update acceptance remain release gates; temporary test keys are never pinned
into user state.

To run without installing:

```text
cargo run --locked --package supgang -- --help
```

## Create and join a hive

On the first computer:

```text
supgang --state-dir "$HOME/.local/share/supgang" init
```

On the computer that will join, create a request:

```text
supgang --state-dir "$HOME/.local/share/supgang" join-request ./computer-b.request
```

Carry that owner-only request file to the first computer. Authorize it there:

```text
supgang --state-dir "$HOME/.local/share/supgang" invite ./computer-b.request ./computer-b.bundle \
  --expect-node <NODE_ID_SHOWN_ON_COMPUTER_B>
```

Carry the new bundle back and install it on the joining computer:

```text
supgang --state-dir "$HOME/.local/share/supgang" join ./computer-b.bundle \
  --expect-hive <HIVE_ID_SHOWN_ON_THE_EXISTING_MEMBER>
```

Compare both full identifiers through a separate trusted channel, such as reading them aloud or
viewing the two screens together. Do not copy the expected value from the request or bundle being
checked. This confirmation prevents a replaced file from enrolling the wrong computer or silently
moving the joining computer into an attacker's hive.

Artifacts are created with owner-only permissions and never overwrite an existing path. The request
and bundle are sensitive authorization material even though neither contains the joining device's
private key. Move or destroy them according to your own backup policy after the join succeeds.

## Name each computer

The default name is derived from the computer hostname. Inspect it or replace it before publishing:

```text
supgang --state-dir "$HOME/.local/share/supgang" name
supgang --state-dir "$HOME/.local/share/supgang" name set "Home B"
```

Names are signed human labels, not authorization identities. Supgang accepts portable ASCII names
and always shows a short stable fingerprint beside them. Duplicate names are allowed on the wire,
but ambiguous CLI selection fails closed and asks for the fingerprint.

## Advertise the services a computer runs

Other software on a member can be found through the same signed record: a short service name,
the port it listens on at this computer's addresses, and the SHA-256 of the TLS key it presents.
Like `name set`, this is changed while the service is stopped and signed on the next start:

```text
supgang --state-dir "$HOME/.local/share/supgang" advertise dibs 4777 --key-pin <64 hex digits>
supgang --state-dir "$HOME/.local/share/supgang" unadvertise dibs
```

`supgang peers`, `supgang resolve`, and the MCP `resolve` tool return `services` beside the
addresses. An advertisement is a claim by the computer that signed it, bounded to four per record;
Supgang never dials the port, and a consumer that connects and finds the pinned key has exactly the
assurance Supgang gives about the computer's own transport. See
[ADR 0002](docs/architecture/0002-service-advertisements.md).

## Bootstrap direct contact

The current milestone intentionally requires one explicit initial contact exchange. On each
computer, publish a signed contact. Supgang discovers active non-loopback interface addresses
without contacting any network service and uses UDP port 44330 by default:

```text
supgang --state-dir "$HOME/.local/share/supgang" publish ./this-computer.contact
```

For explicit policy, create an owner-only endpoint file without putting addresses in process
arguments:

```text
{
  "listen": "0.0.0.0:44330",
  "candidates": [
    {"kind": "local", "address": "192.168.1.20:44330"}
  ]
}
```

Set the file to mode `0600`. Use `kind: "direct"` with `[PUBLIC_IPV6]:44330` only when the address
belongs directly to that computer. Use `kind: "mapped"` with `PUBLIC_IPV4:44330` when the gateway
forwards that UDP port to the computer. Then publish with the override:

```text
supgang --state-dir "$HOME/.local/share/supgang" publish ./this-computer.contact \
  --endpoints ./endpoints.json
```

Carry each signed contact to the other computer and import it:

```text
supgang --state-dir "$HOME/.local/share/supgang" import ./other-computer.contact
```

Install and start the per-user background service on each computer. Local interface discovery is
the default; gateway configuration is not changed:

```text
supgang --state-dir "$HOME/.local/share/supgang" service install
supgang --state-dir "$HOME/.local/share/supgang" service status
```

On macOS, a normal user installation starts when that account signs in to the desktop.
An always-on home computer needs startup before login. For a default-state macOS installation,
review [the owner setup script](tools/setup_macos.py), then run it from the checkout:

```text
uv run --script tools/setup_macos.py --apply
```

The script asks macOS for administrator approval once, creates a system boot registration,
and approves the verified installed runtime in the firewall. The program still runs as its
ordinary owner, with owner-only state and control. The script preserves the previous login
registration for recovery and verifies an unattended restart. A real reboot and separate-network
connection must still be tested. Use `--stop` or `--uninstall` on the same script to disable boot
startup; `supgang service restart` and verified updates do not need administrator access.

For builds signed with a single self-issued owner certificate, add `--trust-certificate` with its
macOS identity fingerprint and `--certificate-sha256` with its SHA-256 fingerprint after reviewing
them. Commercial certificate chains are rejected by this owner-trust option. No Apple Developer Program membership is
required. Certificate trust is limited to code signing. This approval does not configure the router
or establish a public IPv4 path.

If startup migration fails, its previous startup configuration is restored where possible.
The separately approved certificate trust and firewall entries remain, and the script says so.
Recovery copies are kept outside directories that launchd scans. Physical signed-update
acceptance still needs a connection through the firewall after the runtime moves to a new slot.

On a trusted network, explicitly allow a PCP or NAT-PMP request to the attached gateway:

```text
supgang --state-dir "$HOME/.local/share/supgang" service install --router-mapping
```

If the home gateway does not support owner-enabled mapping, an owner-managed firewall opening or port
forward can use the same validated endpoint policy as foreground mode:

```text
supgang --state-dir "$HOME/.local/share/supgang" service install \
  --endpoints ./endpoints.json
```

The file must be an owner-only regular file. Its path, not its addresses, is stored in the native
service definition. This fallback does not detect a later change to a manually entered public
address; owner-enabled mapping, an authenticated surviving path, or user-owned rendezvous remains
necessary for that change to propagate.

For fleets that need a stable meeting point without changing every local router, run Supgang on one
user-owned computer that already has a reachable address, such as a small server at another site or
a server in the user's own cloud account:

```text
supgang --state-dir "$HOME/.local/share/supgang" service install --anchor
```

Foreground operation is `supgang anchor`. The anchor uses the same hive identity, signatures,
transport pinning, revocation, and private state as every other member. It participates in the same
bounded, synchronized outbound recovery rounds and accepts inbound sessions, but does not host an
account system, publish a directory, or relay general application traffic. The anchor itself still
needs one reachable path. That can be native
IPv6, an already-open public interface, an owner-enabled gateway mapping, or an owner-declared mapped
address. Supgang cannot make a machine with no reachable path into a rendezvous point.

Supgang evaluates addresses against the computer's current physical network before selecting one.
For example, an IPv6-only home address remains visible but is reported as unavailable when the
laptop is on an IPv4-only network. This check means the operating system can try the address; it is
not proof that NAT or a firewall will admit the connection. Only an authenticated peer session is
reported as connected.

The installed macOS service runs in that account's native background launch domain, so it does not
require the account to own the graphical desktop after installation. It restarts after a failure
and uses the exact Supgang binary and state directory selected during installation. On Linux,
staying active after logout also depends on the computer's systemd user-session policy. Stop,
restart, or remove only the background definition with:

```text
supgang --state-dir "$HOME/.local/share/supgang" service stop
supgang --state-dir "$HOME/.local/share/supgang" service restart
supgang --state-dir "$HOME/.local/share/supgang" service uninstall
```

Uninstalling the service does not delete the hive identity, peer history, tags, or settings. For a
temporary foreground session instead, use:

```text
supgang --state-dir "$HOME/.local/share/supgang" run
```

The `--router-mapping` option asks the current local gateway to map the listening UDP port through
PCP or NAT-PMP. Mapping changes are coalesced into at most four signed updates per five minutes, and status
remains `router-mapped-unverified` until another authorized computer independently reports the
public socket through an authenticated session. Mapping is disabled by default. Enable it only on
a network whose local gateway you intend to configure:

```text
supgang --state-dir "$HOME/.local/share/supgang" run --router-mapping
```

The explicit configuration remains available:

```text
supgang --state-dir "$HOME/.local/share/supgang" run \
  --endpoints ./endpoints.json
```

Either computer may make a bounded authenticated recovery attempt. The lower stable node
identifier retries in the preferred direction every round. The other computer probes once per
four rounds, leaving quiet time for the preferred direction after a restart or firewall delay. Both
ends retain a successfully authenticated reverse-direction connection as a fallback. If a preferred
connection later arrives, it replaces that fallback deterministically. This avoids simultaneous-dial
livelock without making recovery depend on one direction.

Inspect non-secret state:

```text
supgang --state-dir "$HOME/.local/share/supgang"
supgang --state-dir "$HOME/.local/share/supgang" status
supgang --json --state-dir "$HOME/.local/share/supgang" doctor
supgang --state-dir "$HOME/.local/share/supgang" peers
supgang --state-dir "$HOME/.local/share/supgang" peers --all
supgang --state-dir "$HOME/.local/share/supgang" tag Home B home
supgang --state-dir "$HOME/.local/share/supgang" home
supgang --state-dir "$HOME/.local/share/supgang" sol
supgang --state-dir "$HOME/.local/share/supgang" resolve home
```

The bare command and `peers` show this computer followed by every known peer. `connected` means an
authenticated session exists now. `not connected` means Supgang has saved addresses but none has
produced a current authenticated session. The concise view shows one preferred address and, when
the preferred address is local, one useful public alternative. Secondary interfaces are collapsed.
`peers --all`, `resolve`, and JSON expose the complete current candidate set; the detailed human
view also shows security provenance.

`supgang PEER` searches signed computer names, local tags, shown fingerprints, and stable node IDs.
An exact match wins. A partial name or small typo returns every significant match, ordered by match
quality, so a fuzzy lookup never silently hides another candidate. Use `tag PEER TAG` to add a local
nickname and `untag TAG` to remove it.

Supgang remembers 16 historical authenticated addresses per peer by default. Change the bounded
retry budget for the next service start with:

```text
supgang config set --address-history 32
supgang config
```

Historical addresses retain the signed contact and transport-key pin that originally authenticated
them. They are tried only to recover a fresh record. They never appear as a current address in
`supgang`, `resolve`, or MCP output.

`local` means a private or non-global interface candidate. `public` means a direct globally routed
interface address, an address learned from an authenticated peer, an address returned by the local
gateway for Supgang's UDP port, or a user-owned relay. In the detailed view, `device-signed` means
the address is integrity-bound to that device's authorized key; it does not mean Supgang proved that
the address is reachable from the Internet.

When a private candidate is on one of this computer's attached IP prefixes, Supgang marks it
preferred. Outside that prefix, a user-owned relay or gateway mapping outranks peer-observed and
direct-interface candidates. This keeps a global-looking tunnel or virtual interface from
displacing the path the gateway explicitly opened. Other candidates remain visible and are retried
within fixed bounds. A direct public address can still be blocked by a firewall. A NAT public
address can come from the attached gateway's answer to a mapping request or from an authenticated
peer on the far side observing a connection. Supgang does not query a public IP service. Automatic
mode reserves room for the four most recent peer observations. When the computer's interfaces
change, Supgang removes the old gateway mapping and old public observations from its current signed
record, probes the new local gateway, and publishes the resulting candidate set within the
mapping-update rate limit. Other peers retain older signed records only as bounded recovery hints.

After contact, the reached peer observes the caller's new public source address, the caller signs a
fresh endpoint record, and normal gossip carries that record to other reachable members. This still
requires at least one remembered address or surviving authenticated path to work. NAT, CGNAT, a
firewall, or a complete network partition can make every remembered address unreachable. If both
members are connected to a third member, that member can exchange their directly observed sockets
for a synchronized UDP attempt. A reachable user-owned anchor makes that path predictable. Hard
NATs, blocked UDP, or simultaneous loss of every known edge can still defeat direct reconnection;
Supgang has no third-party service that can bypass that cut.

`resolve` accepts a computer name, local tag, significant partial match, fingerprint prefix of at
least eight characters, or the full node ID. Selection fails when multiple peers match. It returns
addresses only while the signed record is fresh, non-conflicting, and non-revoked.

## Use Supgang from an MCP client

Supgang exposes three bounded, read-only tools over newline-delimited standard I/O:

- `fleet` returns this computer and every known peer with complete signed address candidates;
- `resolve` selects one peer by name, local tag, significant partial match, shown fingerprint, or
  stable node ID;
- `status` returns the local identity and service state without returning secret keys.

Register the installed binary with Codex:

```text
codex mcp add supgang -- supgang mcp
codex mcp get supgang
```

The server implements exactly MCP 2025-11-25 and 2026-07-28. Legacy clients use
`initialize` followed by `notifications/initialized`. Modern clients use `server/discover` and
self-contained request metadata. Tool lists use JSON Schema 2020-12 and advertise explicit
read-only, non-destructive, idempotent, closed-world annotations.

`supgang mcp` opens no network listener and makes no public request. Each process serves one client
over its inherited standard input and output. Requests are capped at 16 KiB, responses at 256 KiB,
and structured tool values at 96 KiB. Offline reads validate immutable snapshots and do not create,
append, truncate, or repair state. When `supgang run` is active, the MCP process uses the protected
same-user local control socket.

MCP clients may send tool results to a model or another system according to their own configuration.
Supgang does not control that destination. Peer addresses and stable identifiers are intentionally
returned only after a tool call, so configure the client according to the privacy boundary you want.
As elsewhere in Supgang, `device-signed` proves which authorized device made a claim; it does not
prove that the address is reachable or that the device is uncompromised.

## Revoke a computer

Run this on the root-authority computer:

```text
supgang --state-dir "$HOME/.local/share/supgang" revoke NODE_ID
```

Revocation is permanent for that stable device key. The authority persists a new monotonic snapshot
before responding, stops dialing and resolving the target immediately, and pushes the signed proof
over established authenticated links. A target that receives proof of its own revocation persists
it, exits, and refuses future startup. Repeating the command is idempotent.

## Security posture

- State directories must be owned by the current user and mode `0700`; sensitive files and the
  control socket must be mode `0600`. Descriptor-based checks also reject extended ACL grants;
  newly created protected objects have inherited ACL state removed. Symlinks and permissive state
  are rejected.
- Endpoint configuration must be an owner-only mode-`0600` regular file. It is bounded to 4 KiB,
  rejects unknown fields and duplicate or invalid candidates, and keeps private topology out of
  process arguments and ordinary startup output.
- Peer tags and `settings.toml` are owner-only, size-bounded, strict-schema files replaced atomically
  under nonblocking locks. Symlinks, unsafe modes, malformed data, unknown fields, and excess limits
  fail closed.
- Historical retries accept only root-authorized, device-signed contacts. Revoked or conflicting
  peers are excluded, duplicate addresses are removed, and every retry still requires the original
  transport-key pin and a fresh channel-bound device proof.
- Root, device, and transport signing roles use separate Rust types and signature domains.
- The TLS provider prefers the standardized hybrid key exchange supported by rustls/AWS-LC, but
  device signatures are Ed25519. Supgang is not fully post-quantum.
- The current key provider is an owner-only file. `doctor` reports this as a warning because macOS
  Keychain, Linux Secret Service, and hardware-backed providers are not implemented.
- A same-user malicious process is inside the local trust boundary. Filesystem permissions and
  same-UID socket credentials do not isolate hostile software already running as the owner.
- A separate durable journal-head witness detects truncation or replacement of committed journal
  tails. A restored full-disk snapshot can still restore the journal, witness, keys, and update
  state together. Generation recovery and an external monotonic witness are not implemented yet.
- The update mechanism uses a locally pinned TUF root, persistent rollback state, an untrusted
  transport boundary, exact platform targets, and a health-checked A/B supervisor. The repository
  does not yet contain an Agenxy production trust root or claim a completed release-key ceremony.
  Apple Developer ID may later be an optional second layer, not a sovereign requirement.

Read the repository-backed [threat model](docs/security/threat-model.md) before exposing a listener
beyond a trusted network.

## Project records

- [Architecture decision](docs/architecture/0001-sovereign-address-plane.md)
- [Stack and prior-art research](docs/research/stack-and-prior-art.md)
- [Threat model](docs/security/threat-model.md)
- [Sovereign update and peer-report security design](docs/security/secure-updates.md)
- [Dependency identity exceptions](docs/security/dependency-exceptions.md)
- [Two-host end-to-end validation](docs/validation/2026-08-17-two-host-e2e.md)
- [Human peer and automatic address validation](docs/validation/2026-08-17-human-peer-address-e2e.md)
- [Dual-protocol MCP acceptance](docs/validation/2026-08-17-mcp-dual-protocol-e2e.md)
- [Layered traversal and user-owned anchor validation](docs/validation/2026-08-20-layered-traversal.md)
- [Hostile-network security review](docs/validation/2026-08-21-security-review.md)
- [External-network reverse-recovery validation](docs/validation/2026-08-25-external-network-recovery.md)
- [Sovereign peer-update validation](docs/validation/2026-08-25-sovereign-peer-updates.md)
- [Security policy](SECURITY.md)

Supgang is an [Agenxy](https://github.com/Agenxy) project and is licensed under Apache-2.0.
