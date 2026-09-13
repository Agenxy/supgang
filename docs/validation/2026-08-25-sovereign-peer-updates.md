# Sovereign peer-update implementation validation

Date: 2026-08-25  
Build: `0.2.0-alpha.10`  
Status: source and two-physical-macOS-host delivery and rollback accepted; platform continuity and
Linux acceptance pending

Machine names, addresses, account names, hive identifiers, and private signing material are
intentionally omitted because this is a public project record.

## 2026-08-27 security-hardening addendum

This record describes the earlier physical experiment and remains evidence for carriage, TUF
verification, supervisor probation, and rollback. The current corrective source deliberately no
longer lets remote receipt create an activation request. A receiver now verifies and stages the
candidate, and its owner must run `supgang update apply` locally. Authorizations also bind exact
bundle length and use a durable single-use nonce ledger; body transfer no longer holds the update
lock. The current repository gate has 195 core tests plus three platform ACL tests. The earlier
statements below about a receiver producing a pending record are historical, not the current remote
activation policy.

## Implemented boundary

- The first TUF root is pinned only from an owner-only local file and is never accepted from a
  peer.
- File and authenticated-peer carriage feed the same `tough` 0.24.0 verifier with filesystem-only
  transport, safe expiry enforcement, persistent rollback state, fixed metadata and target limits,
  exact operating-system and architecture selection, and a native executable check.
- The hive root authorizes one authenticated issuer to offer one exact bundle digest to one exact
  connected receiver for five minutes. The separate TUF root remains the execution authority.
- A peer stream contains no command, shell text, destination path, trust root, or automatic public
  source. Authorization is checked before the large body, and length, digest, and stream completion
  are exact.
- One shared service permit and one cross-process filesystem lock serialize update work. Partial
  inbox, verification, bundle-output, and target files remain owner-only and are cleaned after
  failure or restart. Prepared bundles and retained slots have fixed bounds.
- Up to four peer deliveries survive service restart for 24 hours. Their exact bundles are protected
  from outbox eviction, transport failures retry only after an authenticated reconnect, and a fresh
  five-minute authorization is signed for each actual send attempt.
- A receiver that is temporarily unable to activate an update returns a distinct retry-later result.
  The sender keeps its durable queue entry. Only acceptance or a permanent authorization or
  verification rejection removes the entry.
- The fixed installed supervisor launches content-addressed payloads with a cleared environment,
  requires 30 seconds of local-control health, keeps the prior known-good payload, and removes a
  failed candidate. Foreground services reject remote activation because no supervisor could
  restart them.

## Evidence

- A temporary Ed25519 TUF repository was constructed with signed root, timestamp, snapshot, and
  targets roles. The production verifier pinned its root, streamed a real native test executable,
  staged it mode `0700`, rejected a one-byte bundle mutation, and rejected the same semantic
  version as rollback.
- A real loopback QUIC connection carried the root-authorized bundle over the typed peer-update
  stream. The receiver independently ran TUF verification and produced a pending A/B activation
  record before acknowledging acceptance.
- Authorization tests reject a different hive, issuer, receiver, digest, signature, future issue
  time, or expired interval. A second process cannot acquire the update-state lock.
- A local reinstall with changed binary bytes but the same prerelease version replaces the active
  content-addressed payload instead of silently continuing to run stale bytes.
- A disconnected-peer test durably queued a delivery without any active connection, reopened it as
  a simulated service restart, and proved that later bundle preparation could not evict its bytes.
- The complete repository gate passed: formatting, locked all-target checks, Clippy with warnings
  denied, 174 core tests, the repository-policy self-test, and warning-free documentation.
- A fresh RustSec database scan found no advisory other than the documented unmaintained Linux
  compile-time macro notice. License and source policy passed. A redacted Gitleaks scan of source,
  documentation, workflow, lockfile, and manifests found no secret.
- The release command, fixed supervisor, and content-addressed active payload were installed with
  identical SHA-256 digests and mode `0700`. Launchd showed the supervisor as the manager-owned
  process and the active payload as its child; local service, status, doctor, and update-status
  commands all answered from outside the source tree.
- Two physical macOS computers formed a fresh isolated hive over IPv4. While the receiver was
  offline, the sender durably queued a root-authorized alpha.12 bundle. A temporarily unsupervised
  receiver rejected multiple attempts without losing that queue entry. A supervised receiver then
  independently verified the bundle, acknowledged it, and completed the A/B probation on the exact
  signed candidate digest.
- A second root-authorized bundle contained a valid native executable that exited immediately.
  The receiver verified and staged it, the supervisor rejected it at readiness, removed its slot,
  and resumed the exact alpha.12 known-good digest. Both sender queues ended empty.
- Automatic gateway mapping was exercised on a physical home router with no configuration change.
  The router reported the capability unavailable, so this environment does not prove a zero-config
  public IPv4 mapping. The separately configured mapped endpoint remains unverified until the next
  outside-network run.

## External-network observation

While one computer was on an external network with no route to the home peer's private address, the
installed alpha.10 service authenticated the home peer through its remembered mapped public IPv4 endpoint. Over a
24-second sample the active-neighbor count was `0`, `0`, then `1`: automatic WAN recovery occurred,
but the connection was not continuously present for the whole sample. This improves the earlier
one-shot observation but does not satisfy persistent same-build WAN acceptance. A second 24-second
sample after reinstall was `0`, `1`, then `0`, independently confirming both recovery and the
remaining connection instability.

## Remaining physical gates

1. Give macOS release builds a stable code identity and repeat post-update peer reconnection with
   the application firewall enabled. Ad hoc signatures identify one exact build; during this run,
   the firewall accepted an explicitly allowed stable command path but blocked content-addressed
   update-slot paths. Delivery, activation, and rollback passed, but seamless post-update network
   continuity did not.
2. Repeat the external-network run with the corrected retry protocol and require a connected peer
   across several retry and gossip intervals.
3. Run the same source gate and live two-process update lifecycle on Linux. The repository CI matrix
   is configured for Ubuntu, but no Linux runtime was available in this session.
4. Complete the production threshold-key ceremony and reproducible release-signing process. Test
   trust roots remain confined to isolated acceptance state and are not pinned by the personal hive.

No production root was generated or pinned, no package was published, and no claim of production
release readiness is made by this record.
