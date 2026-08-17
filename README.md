# Supgang

Supgang is a sovereign address plane for a person's own computers. It gives each computer a stable
cryptographic identity and lets authorized members exchange fresh, signed network addresses even
when the addresses themselves change.

Supgang has no account, telemetry, public discovery service, DNS publisher, vendor relay, remote
kill switch, or required server. Strict operation uses only the computers and network paths the
user supplies.

Status: pre-release M1 implementation for macOS and Linux. The direct peer protocol and CLI are
working and adversarially tested, including a
[two-physical-host macOS run](docs/validation/2026-08-17-two-host-e2e.md) and a
[human-name and automatic-address rerun](docs/validation/2026-08-17-human-peer-address-e2e.md).
Local interface address discovery is automatic. Encrypted LAN rendezvous, NAT hole punching,
router mapping, user-owned relay mode, topology health, native key stores, secure updates, and
service packages remain later milestones. Do not treat this snapshot as a production remote-access
guarantee.

## What works now

- One self-certifying hive root and stable Ed25519 identity per computer.
- Recipient-generated, proof-of-possession join requests. A private device key never leaves the
  computer that created it.
- Root-signed, expiring membership certificates and permanent root-signed device revocation.
- Canonical, size-bounded CBOR for memberships, invitations, endpoint records, gossip, and
  revocation snapshots.
- Crash-safe sequence reservation and checksum-framed journals with partial-tail recovery,
  corruption refusal, exclusive ownership, and atomic peer-cache compaction.
- TLS 1.3 QUIC with a signed certificate pin, disabled 0-RTT, channel-bound mutual application
  authentication, bounded streams, and small authenticated anti-entropy pages.
- Automatic active-interface discovery for private local, global IPv4, and global IPv6 candidates,
  with an owner-only explicit configuration override.
- Device-signed, bounded computer names derived from the operating-system hostname and replaceable
  by the user. Stable node fingerprints remain visible and authoritative.
- Authenticated peer observation of global source addresses. An observation is never accepted as a
  device identity or authorization by itself.
- Deterministic single-initiator connections, bounded retries, graceful shutdown, and immediate
  root-signed revocation notices over established links.
- An owner-only local Unix socket with same-UID peer checks, allowing `status`, `doctor`, `peers`,
  `resolve`, and `revoke` while the service owns mutable state.
- A zero-argument fleet view with this computer, peer names, short fingerprints, and the most useful
  local and public addresses. Complete candidates and provenance remain one explicit command away.
  There is no background logging of secrets or peer addresses.

## The irreducible boundary

Supgang does not create information from nothing. If every remembered address is dead, every live
connection is gone, and no authorized computer remains reachable from another partition, there is
no path over which a changed address can travel.

The implemented guarantee is conditional:

> If an authenticated path survives across each relevant partition, newer valid endpoint and
> revocation records converge. If no path survives, Supgang retains signed hints and waits for a
> path to return.

This is why two computers behind one router are less resilient than computers across independent
sites. Future owned-introducer and relay modes improve the number of possible paths, but they cannot
eliminate the same network cut.

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

After the first crates.io release, the equivalent registry install is:

```text
cargo install --locked supgang
```

The registry command uses Cargo's configured binary directory. Neither install form installs a
daemon, changes the firewall, alters a router, creates a TUN device, or contacts a Supgang service.

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
supgang --state-dir "$HOME/.local/share/supgang" invite ./computer-b.request ./computer-b.bundle
```

Carry the new bundle back and install it on the joining computer:

```text
supgang --state-dir "$HOME/.local/share/supgang" join ./computer-b.bundle
```

Artifacts are created with owner-only permissions and never overwrite an existing path. The request
and bundle are sensitive authorization material even though neither contains the joining device's
private key. Move or destroy them according to your own backup policy after the join succeeds.

## Name each computer

The default name is derived from the computer hostname. Inspect it or replace it before publishing:

```text
supgang --state-dir "$HOME/.local/share/supgang" name
supgang --state-dir "$HOME/.local/share/supgang" name set "Solis"
```

Names are signed human labels, not authorization identities. Supgang accepts portable ASCII names
and always shows a short stable fingerprint beside them. Duplicate names are allowed on the wire,
but ambiguous CLI selection fails closed and asks for the fingerprint.

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

Set the file to mode `0600`. Use `kind: "direct"` with `[PUBLIC_IPV6]:44330` or
`PUBLIC_IPV4:44330` only for a genuinely globally routed address. Then publish with the override:

```text
supgang --state-dir "$HOME/.local/share/supgang" publish ./this-computer.contact \
  --endpoints ./endpoints.json
```

Carry each signed contact to the other computer and import it:

```text
supgang --state-dir "$HOME/.local/share/supgang" import ./other-computer.contact
```

Then run the service in the foreground on each computer. Automatic discovery is the default:

```text
supgang --state-dir "$HOME/.local/share/supgang" run
```

The explicit configuration remains available:

```text
supgang --state-dir "$HOME/.local/share/supgang" run \
  --endpoints ./endpoints.json
```

The lower stable node identifier is the canonical connection initiator for a pair. This avoids
simultaneous-dial livelock and duplicate sessions. Both computers still listen for authenticated
inbound QUIC.

Inspect non-secret state:

```text
supgang --state-dir "$HOME/.local/share/supgang"
supgang --state-dir "$HOME/.local/share/supgang" status
supgang --json --state-dir "$HOME/.local/share/supgang" doctor
supgang --state-dir "$HOME/.local/share/supgang" peers
supgang --state-dir "$HOME/.local/share/supgang" peers --all
supgang --state-dir "$HOME/.local/share/supgang" resolve Solis
```

The bare command and `peers` show this computer followed by every known peer. The concise view shows
one preferred address and, when the preferred address is local, one useful public alternative.
Secondary interfaces are collapsed. `peers --all`, `resolve`, and JSON expose the complete retained
candidate set; the detailed human view also shows security provenance.

`local` means a private or non-global interface candidate. `public` means a direct globally routed
interface address, an address learned from an authenticated peer, an explicit router mapping, or a
user-owned relay. In the detailed view, `device-signed` means the address is integrity-bound to that
device's authorized key; it does not mean Supgang independently proved the address reachable.

When a private candidate is on one of this computer's attached IP prefixes, Supgang marks it
preferred. Otherwise it marks the first public candidate preferred. Both remain visible. A direct
public address can still be blocked by a firewall. A NAT public address appears as a reflexive
candidate only after an authenticated peer on the far side observes it; Supgang does not query a
public IP service.

`resolve` accepts an exact computer name, a unique fingerprint prefix of at least eight characters,
or the full node ID. It returns addresses only while the signed record is fresh, non-conflicting,
and non-revoked.

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
  control socket must be mode `0600`. Symlinks and permissive state are rejected.
- Endpoint configuration must be an owner-only mode-`0600` regular file. It is bounded to 4 KiB,
  rejects unknown fields and duplicate or invalid candidates, and keeps private topology out of
  process arguments and ordinary startup output.
- Root, device, and transport signing roles use separate Rust types and signature domains.
- The TLS provider prefers the standardized hybrid key exchange supported by rustls/AWS-LC, but
  device signatures are Ed25519. Supgang is not fully post-quantum.
- The current key provider is an owner-only file. `doctor` reports this as a warning because macOS
  Keychain, Linux Secret Service, and hardware-backed providers are not implemented.
- A same-user malicious process is inside the local trust boundary. Filesystem permissions and
  same-UID socket credentials do not isolate hostile software already running as the owner.
- A restored full-disk snapshot can restore old counters and revocation state. Generation recovery
  and an external rollback witness are not implemented yet.
- Secure updates are designed around an embedded TUF root, offline threshold keys, reproducible
  artifacts, and untrusted replaceable transports. No updater is shipped before the signing
  ceremony and adversarial installer acceptance gates are complete. Apple Developer ID may later
  be an optional second layer, not a sovereign requirement.

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
- [Security policy](SECURITY.md)

Supgang is an [Agenxy](https://github.com/Agenxy) project and is licensed under Apache-2.0.
