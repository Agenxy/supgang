# Supgang

Supgang keeps track of where a person's own computers currently are. It gives each computer a stable
cryptographic identity and lets authorized members exchange fresh, signed network addresses even
when the addresses themselves change.

Supgang has no account, telemetry, public discovery service, DNS publisher, vendor relay, remote
kill switch, or required server. Strict operation uses only the computers and network paths the
user supplies.

Status: pre-release M1 implementation for macOS and Linux. The direct peer protocol and CLI are
working and adversarially tested. Automatic LAN rendezvous, NAT hole punching, router mapping,
user-owned relay mode, topology health, native key stores, and service packages are later
milestones. Do not treat this snapshot as a production remote-access guarantee.

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
- Direct local, global IPv4, and global IPv6 candidates supplied by the user.
- Authenticated peer observation of global source addresses. An observation is never accepted as a
  device identity or authorization by itself.
- Deterministic single-initiator connections, bounded retries, graceful shutdown, and immediate
  root-signed revocation notices over established links.
- An owner-only local Unix socket with same-UID peer checks, allowing `status`, `doctor`, `peers`,
  `resolve`, and `revoke` while the service owns mutable state.
- Human output and versioned JSON output with no ordinary logging of secrets or peer addresses.

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

After the first crates.io release, the equivalent registry install is:

```text
cargo install --locked supgang
```

Both install forms use Cargo's normal user-local binary directory. They do not install a daemon,
change the firewall, alter a router, create a TUN device, or contact a Supgang service.

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

## Bootstrap direct contact

The current milestone intentionally requires one explicit initial contact exchange. On each
computer, publish the address on which its foreground service will listen:

```text
supgang --state-dir "$HOME/.local/share/supgang" publish ./this-computer.contact \
  --local 192.168.1.20:44330
```

Use `--direct [PUBLIC_IPV6]:44330` or `--direct PUBLIC_IPV4:44330` only after replacing the
placeholder with a genuinely globally routed address. Carry each signed contact to the other
computer and import it:

```text
supgang --state-dir "$HOME/.local/share/supgang" import ./other-computer.contact
```

Then run the service in the foreground on each computer:

```text
supgang --state-dir "$HOME/.local/share/supgang" run \
  --listen 0.0.0.0:44330 \
  --local 192.168.1.20:44330
```

The lower stable node identifier is the canonical connection initiator for a pair. This avoids
simultaneous-dial livelock and duplicate sessions. Both computers still listen for authenticated
inbound QUIC.

Inspect non-secret state:

```text
supgang --state-dir "$HOME/.local/share/supgang" status
supgang --json --state-dir "$HOME/.local/share/supgang" doctor
supgang --state-dir "$HOME/.local/share/supgang" peers
supgang --state-dir "$HOME/.local/share/supgang" resolve NODE_ID
```

`peers` deliberately hides addresses. `resolve` reveals candidates only for the exact requested
node and only while its signed record is fresh, non-conflicting, and non-revoked.

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
- Root, device, and transport signing roles use separate Rust types and signature domains.
- The TLS provider prefers the standardized hybrid key exchange supported by rustls/AWS-LC, but
  device signatures are Ed25519. Supgang is not fully post-quantum.
- The current key provider is an owner-only file. `doctor` reports this as a warning because macOS
  Keychain, Linux Secret Service, and hardware-backed providers are not implemented.
- A same-user malicious process is inside the local trust boundary. Filesystem permissions and
  same-UID socket credentials do not isolate hostile software already running as the owner.
- A restored full-disk snapshot can restore old counters and revocation state. Generation recovery
  and an external rollback witness are not implemented yet.

Read the repository-backed [threat model](docs/security/threat-model.md) before exposing a listener
beyond a trusted network.

## Project records

- [Architecture decision](docs/architecture/0001-sovereign-address-plane.md)
- [Stack and prior-art research](docs/research/stack-and-prior-art.md)
- [Threat model](docs/security/threat-model.md)
- [Dependency identity exceptions](docs/security/dependency-exceptions.md)
- [Security policy](SECURITY.md)

Supgang is an [Agenxy](https://github.com/Agenxy) project and is licensed under Apache-2.0.
