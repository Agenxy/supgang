# Tags, address history, and restart recovery acceptance

Date: 2026-08-17 America/Los_Angeles

This record covers the installed release after local peer tags, significant partial matching,
bounded signed-address history, background handshakes, and direction-prioritized recovery were
added. Private addresses, public addresses, full node identifiers, and account details are omitted.

## Accepted artifact

- Version: `supgang 0.1.0`
- SHA-256: `fca14ff882bdaca2d9dff0bd519a7e71b6ecf9a522e568cf5b788243424bcc5c`
- Hosts: Laptop A and Home B, both Apple silicon computers in the existing two-member hive.
- Paths: the normal user-local binary directory on each host.
- Both installed files produced the same hash after atomic replacement.
- Both services used automatic interface discovery, strict mode, address-history limit 16, and no
  hosted discovery, account, DNS publisher, STUN service, vendor relay, or public-IP service.

## Results

| Check | Result |
| --- | --- |
| Bare command | Each host showed itself first, then the other computer with one preferred local and one useful public address. |
| Local tag | Laptop A displayed Home B with the owner-only tag `home`. |
| Exact tag lookup | `supgang home` returned only Home B. |
| Partial lookup | `supgang macsol` returned only Home B. |
| Complete view | `peers --all` retained the complete current signed candidate set and its provenance. |
| Signed convergence | Each host imported the other host's newest sequence after authenticated QUIC synchronization. |
| Offline responsiveness | With Home B stopped and connection attempts timing out, repeated local status requests completed in less than one second. |
| Restart priority | Laptop A ran alone long enough to enter secondary recovery before Home B started. Both reported one active peer within eight seconds. |
| Session bound | Incoming and outgoing handshakes share one 16-task ceiling; a full set defers the next retry without spinning. |
| Current priority | Unit coverage retries the newest signed contact three times before each historical hint. |
| Direction priority | Unit coverage retries the preferred lower-ID outbound direction each round and the secondary direction once per eight rounds. |
| MCP 2025 | The installed command completed 2025-11-25 initialization and returned the three-tool read-only surface. |
| MCP 2026 | The installed command completed 2026-07-28 discovery and resolved `home` with its local tag and current signed candidates. |
| Stale event defense | A close or data event from an old connection cannot affect a replacement session for the same peer. |
| Repository gate | Formatting, locked all-target checks, all-feature Clippy with warnings denied, 93 core tests, policy self-test, and rustdoc passed. |

The final installed services remained running, with each host reporting one known and one active
authenticated peer.

## Firewall evidence

Home B has a managed macOS Application Firewall. Read-only system inspection showed the firewall
enabled, no Supgang allowlist entry, and repeated queued inbound flows for the unsigned executable.
The policy could not be changed from the command line and was left untouched. A direct LAN UDP probe
from Home B to Laptop A succeeded. The preferred Home B outbound Supgang session also succeeded
after secondary probes left a quiet window.

This proves the priority scheme can recover the tested fleet without changing managed firewall
policy. It does not prove that unsolicited inbound Supgang traffic to Home B is allowed.

## Limits

- Both computers shared one LAN. This run does not prove a path through a remote NAT, CGNAT, or
  firewall.
- A signed public address is an authenticated claim, not a reachability guarantee.
- Historical contacts are covered by unit and persistence tests. This run did not move a host to a
  second physical network and recover through an old address.
- Local tags are intentionally neither signed nor synchronized. They cannot change peer identity.
- The release is not signed by an Apple Developer ID. Hardware-backed device keys, boot-service
  packaging, a secure updater, executable attestation, and peer-compromise voting are not current
  security claims.
