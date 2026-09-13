# Home-side WAN failure diagnosis

Date: 2026-08-30  
Build: `0.2.0-alpha.10` corrective source  
Verdict: **root causes reproduced; external WAN acceptance still pending**

This record omits machine names, account names, addresses, and hive identifiers. Machine A is the
mobile computer. Machine B is the home peer.

Correction, 2026-09-08: the Background-domain change below proved manual headless operation,
not boot restoration. A subsequent reboot left the service stopped. See the
[mobility and owner-startup follow-up](2026-09-08-mobility-and-owner-startup.md) for the corrected
startup design, sleep-related expiry defect, and remaining physical acceptance gates.

## Reproduced failures

Machine B's per-user launchd service was installed but stopped. Supgang had registered the
`LaunchAgent` in that account's graphical login domain, but another account owned the desktop.
macOS also provides a native `user/UID` background launch domain that may exist independently of a
graphical login. Supgang now registers a session-type-constrained Background agent there, avoiding
both a root daemon and a requirement that the service account own the desktop.

Both commands reported the same prerelease version, but their executable hashes differed. The exact
current command bytes are now installed on both physical Macs. Comparing version strings alone was
not a valid fleet deployment check. Before the background-domain correction, Machine B's protected
service copy intentionally remained on the previous build because the graphical-domain preflight
refused to mutate it.

Machine B's macOS Application Firewall allowed the user-facing command path. The process that owned
UDP 44330 actually ran from a content-addressed A/B slot with an ad hoc signature and a build-specific
identifier. UDP bytes reached the kernel socket, but Quinn never received a valid incoming
connection and sent no address-validation retry. An isolated pinned QUIC probe completed over
loopback and timed out across the LAN, confirming a host-boundary failure below the Supgang session
protocol.

## Protocol defect and live proof

Anchor mode accepted inbound sessions but disabled every outbound retry. That removed the reverse
direction that could work through an asymmetric firewall and prevented an anchor from taking part
in synchronized UDP recovery.

Machine B was run temporarily in ordinary outbound-capable mode while both machines used the same
binary. Within ten seconds they mutually authenticated, refreshed their signed records, exchanged
peer-observed addresses, and each reported one active peer. This proved the stored identities,
transport pins, session protocol, revocation state, signed-record merge, and gossip path.

The source now keeps anchor mode in the same bounded retry schedule. Its larger 64-neighbor ceiling
and inbound connection preference remain unchanged. A regression test ensures an idle service wait
cannot suppress the outbound retry deadline. Machine B then ran the current command in foreground
anchor mode. Within twenty seconds both physical machines reported an authenticated active peer and
fresh mutually signed records, confirming the repaired outbound recovery path on the LAN.

## Sovereign macOS signing

The install task now accepts only an exact 40-character owner-controlled code-signing identity hash
and applies the fixed identifier `org.agenxy.supgang.runtime`. The current command artifacts have
one designated requirement rooted in the same owner certificate and identical SHA-256 hashes. No
Apple Developer Program identity or notarization service is involved.

The first review of that change found that a TUF-authorized content slot could still carry a missing
or different macOS identity. Staging, activation, and supervisor handoff now validate the candidate
signature and require it to satisfy the active executable's designated requirement. A focused
negative test re-signs a valid Mach-O with a different identity and confirms rejection; the exact
same-identity copy remains accepted. TUF trust promotion was moved after this platform check so an
identity failure cannot advance the locally committed repository state.

The review also found that signing the command path alone could leave an older protected supervisor
and slot running. A dedicated `service refresh` operation now replaces those bytes and restarts the
service without rewriting its endpoint, anchor, or router-mapping policy. The running process path,
protected supervisor, active slot, hashes, designated requirements, and unchanged service-definition
hash are compared after propagation.

The domain check runs before a per-user macOS install creates or replaces any service artifact. A
physical attempt against the unavailable graphical domain returned a specific error while the
protected executable, active record, and LaunchAgent retained their exact hashes and modification
times. After switching to the native background domain, Machine B installed, started, and retained
the anchor while its graphical domain remained absent. The command, protected supervisor, and
active slot had identical signed hashes; the definition retained anchor and router-mapping policy
and explicitly selected the Background session type.

A final review found two more delayed-activation paths. `update apply` used to create its durable
pending record before discovering that the background manager could not restart, and a later local
install could leave an older staged or pending slot behind. Apply now performs a read-only restart
preflight before arming the candidate and disarms it if the restart fails while retaining the
verified staged release. Activation, supervisor startup, status, and commit require a candidate to
be strictly newer than the active release unless the version and digest are the exact same
idempotent recovery record. A local install clears non-newer staged and pending records before it
  publishes its active record. The refresh operation holds the update lock while checking the
  version floor and replacing protected bytes, so an older command cannot partially downgrade the
  supervisor. A higher semantic version with byte-identical content still advances the durable
  active version. Focused tests cover all five invariants.

The public owner certificate still requires one explicit administrator trust decision on each Mac.
Machine B has not completed that decision. The signed runtime must then pass a firewall-on inbound
connection, signed update activation, rollback, and reconnection test before stable firewall
identity is accepted.

## Remaining acceptance work

- Complete the one-time owner-certificate trust and firewall approval on Machine B.
- Confirm automatic Background-agent restoration across a physical Machine B reboot. Operation
  without the graphical desktop is physically accepted; reboot restoration has not been exercised.
- The tested gateway reports PCP and NAT-PMP mapping unavailable, and bounded multicast and direct
  SSDP discovery returned no UPnP Internet Gateway Device response. Public IPv4 without a manual
  forward therefore still depends on compatible synchronized NAT traversal or an owner-operated
  rendezvous peer; native IPv6 remains a separate direct path.
- Repeat from a separate IPv4 network and require home-side ingress, mutual authentication,
  refreshed signed records, stable reconnection across several retry windows, and a TUF-verified
  peer-carried update followed by local activation.

Source gates passed after the protocol and release-boundary corrections: formatting, locked
all-target compilation, warnings-as-errors Clippy, 203 core tests, three live filesystem-ACL tests,
repository policy, and documentation. RustSec policy and dependency licence/source policy are rerun
as separate release checks.
