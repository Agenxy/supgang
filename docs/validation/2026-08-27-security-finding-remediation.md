# Security finding remediation: hostile-network alpha.10

Date: 2026-08-27  
Build: `0.2.0-alpha.10` corrective source  
Verdict: **source hardening accepted; WAN product acceptance failed**

This record reconciles the 46 occurrences, representing 41 distinct rules, from deep scan
`1e1eed19-e24f-4764-a989-33922d88c868`. That scan had partial coverage and was run before these
changes. This is a source-traced remediation record, not a claim that the old scan re-ran against
the corrected tree or that an Internet-facing program is flawless.

## Disposition

| Rules | Status | Corrective control and evidence |
| --- | --- | --- |
| `authorization.join-bundle-revocation-substitution`, `authorization.revoked-peer-active-session`, `authorization.session-expiration`, `revocation-rollback.peer-directory` | Remediated | Enrollment binds the intended hive and node to current revocation authority. Live session authority checks both expiry and cancellation; rollback, equivocation, and restoration fail closed. |
| `authorization.peer-update-local-activation`, `authorization.update-nonce-replay`, `concurrency.update-blocking-materialization-timeout`, `denial-of-service.update-admission-starvation`, `denial-of-service.update-preauthorization-admission`, `improper-exception-handling.update-reply-handoff`, `resource-exhaustion.update-admission-starvation`, `supgang/transient-receiver-failure-terminal` | Remediated | Version-two authorization binds the exact bundle length; the bounded nonce ledger commits before receipt. Preface, admission, and body stages have separate finite budgets. Bundle transfer does not hold the update lock. Reply failure preserves a verified staged artifact. Remote receipt never requests activation; only the local owner can apply it. |
| `durable-delivery.deferred-expiry-pins-outbox`, `race-condition.update-semantic-rollback-floor`, `update-lifecycle.atomic-ab-commit`, `update-rollback-watermark.failed-candidate-poisoning` | Remediated | Expired deliveries are removed durably and no longer pin outbox artifacts. Semantic floors include compiled, active, previous, staged, and pending states without permanently trusting a failed candidate. A/B commit and discard are digest-bound and recovered commit is idempotent. |
| `supgang/tuf-rollback-state-not-durable`, `tuf-datastore-child-symlink-follow`, `tuf-retired-root-trust-revival` | Remediated | TUF client state is atomically persisted with a fixed size ceiling, reopened through a fresh datastore, and rejects corruption or child symlinks. Promoted roots are the only restart anchor; missing promoted state cannot fall back to a retired bootstrap root. |
| `availability.expired-contact-rendezvous-recovery`, `information-exposure.preproof-server-contact`, `missing-authorization.rendezvous-introducer`, `missing-authorization.rendezvous-introducer-role`, `ssrf.rendezvous-offer-correlation` | Remediated | Expired contacts retain only pin authority needed for authenticated recovery. The server reveals no contact before current-channel proof. Introducer and target roles are bound, offers require recent single-use local intent, and only globally routed offered sockets are accepted. |
| `peer-forged-reflexive-reachability`, `provenance.self-claimed-reflexive`, `supgang.peer-candidate.on-link-blind-udp` | Remediated | Reachability observations are reporter-signed, short-lived, memory-only, target-bound, and revocation-aware. Self-claimed local or reflexive addresses are not automatic off-link dial hints. Route compatibility rejects off-link private addresses and unavailable address families. |
| `insecure-defaults.router-mapping-policy-loss`, `network.router-mapping-shutdown-reactivation-race`, `network.stale-candidate-resigning-on-interface-failure`, `unauthenticated-state-mutation.router-mapping` | Remediated | Router mapping is explicit opt-in, preserves the service policy, and cannot mutate the durable signed peer record. Shutdown owns and awaits lease teardown; failed interface refresh cannot re-sign stale candidates. |
| `durable-state.continue-after-ambiguous-append`, `resource-bounds.growing-file-read`, `resource-bounds.revocation-broadcast-task-amplification`, `resource-exhaustion.authenticated-sync-write-amplification` | Remediated | Ambiguous authoritative writes poison the state until a clean reopen. Security-sensitive reads are exact and bounded. Sync coalesces repeated peer updates, prioritizes revocations, enforces mutation cadence, and uses bounded periodic authenticated gossip rather than detached fanout. |
| `incorrect-permissions.extended-acl-secret-state` | Remediated | Descriptor-based checks reject macOS allow ACLs and Linux POSIX access/default ACLs throughout identity, state, update, transport, settings, profile, tags, service, and executable paths. New objects have inherited grants cleared before use. Live macOS allow, deny-only, and owner-only ACL tests pass. |
| `ci.action-pin-workflow-coverage-gap`, `release-pipeline.missing-security-gate-dependency`, `supply-chain.duplicate-exception-name-only` | Remediated | Every workflow is scanned for privileged triggers and full-length action pins. Publish depends on the full repository gate and exact RustSec policy. Duplicate exceptions bind full package identity and source. |
| `resource-exhaustion.inbound-authentication-pool` | Mitigated; residual remains | Handshakes are bounded, QUIC Retry validates source ownership, one source cannot monopolize admission, proof times out quickly, and remembered sources have reserved capacity. A distributed set of validated new sources can still occupy every general lane and deny a legitimate peer arriving from an unknown address. Solving that fully requires pre-QUIC membership authentication or an independently reachable rendezvous path. |
| `rollback-protection.authoritative-journal` | Tail rollback remediated; whole-state rollback remains | A durable head witness binds the committed journal prefix by length, frame count, and SHA-256; committed truncation fails closed and only an unwitnessed crash tail may be repaired. An attacker who coherently restores the journal, witness, keys, and all other local state to one older snapshot cannot be detected without a monotonic anchor outside that snapshot. |

## Closing source gates

The corrected tree passed, from the locked dependency graph:

- formatting, every workspace target, and Clippy across all targets and features with warnings denied;
- 195 core tests, three live filesystem-ACL tests, and the repository policy self-test;
- documentation and the 700-line Rust source ceiling;
- RustSec with warnings denied except the exact documented `RUSTSEC-2024-0436` maintenance
  exception; and
- dependency licence and source policy.

The lockfile was advanced from the yanked `chacha20 0.10.1` to `0.10.2` during this pass.

## Product acceptance remains failed

These gates show that the traced source-level findings were addressed to the limits above. They do
not prove Supgang's principal use case. The current outside-network run formed no authenticated
session with the home peer, received no return UDP traffic, and could not exercise peer-carried
updates. The required next evidence is a same-build, two-machine physical WAN run that observes the
home-side ingress, authenticates both peers, converges signed address records, and delivers then
locally applies a TUF-verified peer update. Linux service and firewall acceptance also remain
pending.
