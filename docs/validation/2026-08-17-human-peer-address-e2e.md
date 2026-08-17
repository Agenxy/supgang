# Human peer and automatic address validation: 2026-08-17

This record covers the physical-host acceptance run for signed computer names, automatic interface
discovery, zero-argument peer display, local/public address classification, and named resolution.
Private hive, full node, account, and network identifiers are intentionally omitted.

## Scope

- Candidate source: the tree containing this record.
- Release-mode binary SHA-256:
  `80eff0823726bd6a1b45b6e9b20823223043469f5494ed37d64f6e744981b217`.
- Hosts: `MacMarine` and `MacSolis`, two Apple silicon computers in the existing two-member hive.
- Installation: the same 4,282,400-byte executable on both hosts, verified after replacement.
- Network configuration: none. Both services used automatic discovery and default UDP port 44330.
- External runtime services: none. No account, hosted discovery, DNS publisher, STUN service,
  vendor relay, public-IP service, or overlay network participated.

## Results

| Check | Result |
| --- | --- |
| Automatic names | Both devices derived and retained their operating-system computer names. |
| Signed identity cue | Every human peer row paired the name with an eight-character node fingerprint. |
| Self visibility | Each bare view put its own computer first and labeled it `this computer`. |
| Bare command | `supgang` printed each computer's preferred address plus at most one public alternative. |
| Progressive detail | The compact view hid six secondary candidates per computer and pointed to `peers --all`. |
| Complete view | `supgang peers --all` retained every address, preference marker, kind, and provenance. |
| Machine view | JSON schema `supgang.peers/v3` included `this_computer` and the complete peer candidate sets. |
| Local preference | Each host selected the other host's same-prefix private address as preferred. |
| Public visibility | Each host also displayed the peer's globally routed interface candidates as public. |
| Honest provenance | Detailed and JSON rows said `device-signed`; none claimed independent reachability proof. |
| Named resolution | `resolve MacSolis` and `resolve MacMarine` returned the intended fresh signed records. |
| Ambiguity defense | Unit coverage proved duplicate names fail closed and require a longer fingerprint. |
| Stale defense | Unit coverage proved expired, revoked, or conflicted rows cannot mark an address preferred. |
| Dial ordering | Unit coverage kept one on-link private and a public candidate inside the bounded dial set. |
| Live rename safety | Each running service returned a stop-first error and retained its existing signed name. |
| Replacement recovery | After replacing and restarting both binaries, each host reported one active peer. |
| Peer restart | A later `MacSolis` restart advanced its signed sequence and re-established the session. |
| No-egress discovery | Automatic publication succeeded under a macOS sandbox denying all network operations. |
| Installed command | From `/tmp`, `command -v supgang` selected `$HOME/.local/bin/supgang`. |
| Installed behavior | The installed command passed help, doctor, status, name, compact and complete peer views, and named resolution. |
| Offline install | `make install` succeeded under a macOS sandbox denying every network operation. |

The final services remained running in the foreground from their installed paths and each reported
one known, active, authenticated peer.

## Security interpretation

The device Ed25519 signature covers the display name, candidate set, sequence, timestamps, transport
pin, capabilities, hive, and stable node ID in endpoint-record version 2. Membership and
revocation remain rooted in the separate hive key. QUIC authentication additionally checks the
root-authorized device identity, pinned transport key, fresh nonces, and TLS-exporter binding.

This prevents a network intermediary from substituting a different name or address record without
detection. It does not prove that a legitimately authorized computer is uncompromised. A fully
compromised peer able to use its device key can sign a lie; software-only self-reporting cannot
remove that boundary.

## Limits of this evidence

- Both computers shared a LAN. This run does not prove reachability through a remote firewall, NAT,
  or CGNAT.
- `public` means globally routed address scope, not independently verified reachability.
- Automatic discovery sees public addresses assigned to local interfaces. A NAT external address
  requires a surviving authenticated path for peer observation; no public-IP lookup service exists.
- Endpoint record v2 readers accept retained v1 records, but a v1 binary does not understand v2.
  This pre-release fleet was upgraded together rather than through a mixed-version rolling upgrade.
- The service runs in the foreground. Boot-time lifecycle packaging remains future work.
- The secure updater and live executable-attestation report are accepted designs, not implemented
  security claims.
