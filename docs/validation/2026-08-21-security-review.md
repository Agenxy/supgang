# Historical security review: hostile-network corrective build

Date: 2026-08-21; live corrective validation updated 2026-08-25  
Build under review: `0.2.0-alpha.9` corrective source  
Status: historical alpha.9 evidence; superseded by the
[alpha.10 finding remediation](2026-08-27-security-finding-remediation.md). Same-build WAN and
physical Linux acceptance remained pending.

This review treats Supgang as an Internet-facing identity and discovery service, even though it is
intended for small personal fleets. Passing this review does not mean the program is flawless. It
means the listed attack paths were traced to their sinks, corrected where reachable, and exercised
by the evidence below.

## Reviewers and scope

- A Codex Security Standard scan reviewed the full repository and reported ten reachable findings:
  seven High and three Medium.
- Separate adversarial source-to-sink reviews covered network admission, authenticated sessions,
  durable state, local control, storage, native service installation, rendezvous, router mapping,
  MCP, enrollment, and dependency policy.
- An independent `claude-opus-5` review read the current security-critical flows after the first
  remediation pass. It found no Critical or High issue, independently verified the original
  vulnerability classes as fixed, and reported two Low hardening gaps.
- A final local review covered the two Low fixes, key-buffer handling, gossip invalidation, mapping
  capacity, source and documentation secrets, and the complete quality gate. Attempts to obtain a
  second independent targeted report after the final Low fixes did not return a usable report, so
  they are not counted as evidence here.

## Corrected attack paths

| Attack path | Corrective control |
| --- | --- |
| Pending QUIC Initials and unauthenticated sessions exhaust recovery work | Fixed Quinn pending-handshake and byte ceilings, address validation with Retry, separate eight-task inbound and outbound pools, and per-source IPv4 or IPv6-prefix windows |
| Rejected or duplicate sessions mutate durable state | Connection admission now precedes revocation merge, contact import, and address observation; a live QUIC regression asserts all durable surfaces remain unchanged |
| Connection reconciliation exits while sibling listeners retain the transport | One tracked supervisor owns reconciliation, revocation, and rendezvous listeners; any exit closes the connection, and shutdown cancels and awaits the task sets |
| The secondary recovery direction authenticates but the receiver discards the same connection | Both endpoints now classify the reverse-direction connection as a retained fallback; a later preferred connection replaces it deterministically |
| A peer drives unbounded signed address or journal growth | Duplicate observations coalesce, peer observations and gateway updates have fixed time windows, journals compact atomically, and equivocation evidence is retained only once |
| An attacker substitutes a persistent service executable or state path | The service executes an atomically installed owner-only copy; the executable, service definition, endpoints, state directory, and complete resolved ancestor chains are revalidated |
| Offline enrollment authorizes the wrong device or hive | Invite and join require separately confirmed exact node and hive identifiers before mutation |
| A malicious gateway turns UPnP discovery into LAN SSRF or silently creates trusted address claims | UPnP is disabled; PCP and NAT-PMP target only the selected gateway; globally routed results remain `router-mapped-unverified` until peer confirmation |
| Rendezvous offers turn a member into an internal-network packet source | Offers require a recent single-use recovery intent and now accept only globally routed sockets; private, loopback, and link-local destinations fail closed |
| Secret files grow during a read or leave temporary decoded key bytes behind | Identity, pending-join, and transport-key reads have exact byte ceilings, reject trailing growth, and clear temporary secret buffers immediately after decoding |

## Verification evidence

The final repository gate passed:

- formatting check;
- every workspace target compiled from the locked dependency graph;
- Clippy across all targets and features with every warning denied;
- 153 unit, protocol, persistence, transport, and adversarial regression tests;
- documentation build;
- repository policy, including the 700-line source ceiling;
- RustSec with all vulnerability, unsoundness, yanked, and maintenance warnings denied except the
  documented `RUSTSEC-2024-0436` maintenance exception;
- dependency licence, source, and duplicate-version policy; and
- scoped secret scans across source, documentation, workflows, manifests, and the lockfile.

Notable adversarial regressions include live duplicate and capacity rejection before durable
mutation, saturated connection-event teardown, bounded handshake memory, IPv4-mapped and IPv6-prefix
admission, near-full journal compaction and restart, terminal equivocation compaction, wrong-node and
wrong-hive enrollment rejection, private rendezvous-address rejection, root-path ancestor rejection,
key-file trailing-growth rejection, bilateral reverse-direction classification, and a live two-ended
QUIC fallback-retention test.

## Residual limits

- A device with a stolen live key remains an authorized member until a root-signed revocation
  reaches the partition. A signed device claim proves authorship, not reachability or an
  uncompromised machine.
- Whole-state rollback cannot be detected without a trusted monotonic anchor outside the rolled-back
  state. The current checkpoint detects tampering, gaps, and rollback after the retained checkpoint,
  not restoration of an entire older valid snapshot.
- A distributed volumetric packet flood remains an operating-system and QUIC transport problem.
  Application work and memory are bounded, but availability cannot be guaranteed under arbitrary
  link saturation.
- Revocation and address convergence are partition-dependent. No sovereign design can guarantee
  reconnection after every known edge changes simultaneously without a surviving user-owned anchor
  or reachable member.
- The macOS implementation has passed the source and local runtime gates. Physical Linux service,
  upgrade, recovery, and end-to-end acceptance have not yet been run.
- An outside-network run authenticated the remembered mapped route and exposed a bilateral fallback
  admission defect, which is now corrected and covered by live QUIC regression tests. The remote
  physical peer still needs the same corrected artifact before persistent two-machine WAN acceptance
  can be rerun; a mixed-version authentication is not final acceptance.

These limits are product behavior, not hidden guarantees. They are also recorded in the
[threat model](../security/threat-model.md) and architecture documentation.
