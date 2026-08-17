# Changelog

All notable project changes are recorded here. Supgang has not published a release.

## Unreleased

### Added

- Rust 2024 workspace, Apache-2.0 licence, exact dependency pins, and typed repository gate.
- Stable hive and device identities with domain-separated Ed25519 roles.
- Recipient-generated offline join requests and root-signed membership bundles.
- Canonical bounded endpoint, contact, session, gossip, and revocation protocols.
- Crash-safe authoritative journal, exclusive state ownership, and atomic peer-cache compaction.
- TLS 1.3 QUIC transport with certificate pins, disabled 0-RTT, exporter-bound mutual
  authentication, deterministic connection direction, and strict resource limits.
- Foreground macOS and Linux service with graceful signal handling and an owner-only local control
  socket.
- Direct signed contact bootstrap, bounded peer reconciliation, exact-node resolution, and
  authenticated global-source observation.
- Permanent monotonic device revocation with immediate acknowledged notice, disconnect, target
  persistence, and restart refusal.
- Versioned JSON for automation and address-redacted ordinary peer status.
- Repository-backed architecture, prior-art research, threat model, security policy, and CI.

### Known limitations

- No automatic LAN rendezvous, NAT hole punching, router mapping, or owned relay.
- No native key store, root recovery, generation recovery, or external rollback witness.
- No service package, GUI, manpage, or completion bundle.
- Live multi-process acceptance is complete on macOS only in this snapshot.
