# Mobility recovery and owner-approved startup

Date: 2026-09-08  
Build: `0.2.0-alpha.10` corrective source  
Verdict: **LAN recovery reproduced; boot and external-network acceptance pending**

This record intentionally omits computer names, account names, addresses, signing-identity
fingerprints, and hive identifiers. Machine A is mobile; Machine B stays at home.

## Failures reproduced

The previous outside-network test found an installed but stopped service after a reboot.
Manually loading a Background agent into `user/UID` had demonstrated headless operation,
not automatic restoration at boot. The earlier home-side validation record must not be
read as evidence of boot acceptance. New ordinary user installations use the graphical
login domain and declare that limitation. Existing definitions are preserved by refresh.

At home, both services could be running without an authenticated connection. Machine A
was still advertising a signed contact whose wall-clock expiry had passed, despite an
in-process refresh deadline. Restarting it produced a fresh signed record and restored
mutual authentication on both physical Macs. A monotonic timer that pauses through sleep
cannot, by itself, maintain a wall-clock signature lifetime.

The service now checks signed validity before scheduling new sessions, refreshes interface
candidates, signs a fresh contact, and resumes the hive-aligned retry schedule. Tests
exercise an expired signed contact while the monotonic deadline remains in the future.
They verify the replacement signature and sequence, not only a Boolean expiry predicate.
An expired membership is terminal: it cannot create a signing loop, publish invalid
contacts, or continuously postpone outbound dialing.

Machine B's firewall also contained an explicit block for an old content-addressed
runtime. Allowing only the command path does not prove permission for the running slot.
The laptop's firewall was already disabled; this work did not disable either firewall.
Current LAN success therefore does not establish firewall-on update acceptance.

## Owner-approved boot service

The reviewed macOS setup script creates a narrowly validated, administrator-owned boot
definition. The network process still runs as the ordinary owner. There is no privileged
network listener, password storage, or remote administrative command broker. FileVault
unlock and availability of the owner's home remain operating-system prerequisites.

The script validates the supervisor, active-slot digest, signature, and selected signing
certificate before granting permissions. Optional self-issued certificate trust is
restricted to code signing and requires both an exact identity fingerprint and SHA-256
certificate fingerprint. It rejects commercial certificate chains for that owner-trust
operation. The certificate's private key is never exported.

Migration waits for the outgoing service to stop answering before bootstrapping the new
one. Its restart check requires a different random service instance, so an old process
cannot satisfy the restart test. Recovery copies and temporary definitions stay outside
launchd's scanned directories. Stop addresses boot and available login registrations
without requiring a damaged definition to parse. Uninstall also removes login definitions
for accounts not signed in. Peer identity and history are preserved.

The system-boot service accepts restart only through owner-authenticated local IPC.
Verified remote updates use that existing boundary; they do not gain root access.
Clean exits restart under the native manager on macOS and Linux. Local refresh enforces
the existing signing identity and semantic version floor. Interrupted update probation
has a durable three-attempt limit before returning to the active release.

Apple documents Application Firewall tracking through a designated requirement and an
initial trusted-anchor decision. This supports owner signing without purchasing an Apple
Developer Program membership, but does not substitute for a live firewall-on update test.
See [Apple's code-signing subsystem requirements](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/AboutCS/AboutCS.html).

## Verification boundary

The complete local Rust gate passed with 210 core tests, platform ACL tests, policy
checks, formatting, all-target checks, warnings-as-errors Clippy, and documentation.
Seven non-privileged setup tests cover argument substitution, root-account refusal,
bounded file validation, safe ancestors, stop coverage, and outgoing-process readiness.
The owner-setup preview passed on both physical Macs without changing permissions.

Independent Claude Opus 5 reviews found expiry, migration, shutdown, and recovery defects;
those findings drove the corrections above. Its final verdict was **ACCEPT FOR OWNER-APPROVAL
TESTING**, explicitly excluding physical boot, firewall continuity, and WAN acceptance.
Source review is not physical acceptance.

The installed command, protected supervisor, and active runtime on both physical Macs
were byte-identical after deployment, with SHA-256
`5d70229f9f6cd5615287fadd4e3475bad77f01fa3b1feb04120d5a4a5a6245c1`.
Both reported one authenticated active peer after restarting into that build. Machine A
now has graphical-login startup. Machine B still needs administrator-approved boot
startup; neither machine is claimed to have passed a physical reboot test.

Remaining gates are explicit:

- Apply owner-approved boot and firewall setup on both Macs.
- Prove boot restoration and headless operation after a physical reboot.
- Activate a separately signed update slot with the firewall enabled, verify recovery,
  and confirm an authenticated session afterward.
- Establish a compatible Internet path and test from a separate network. The observed
  gateway did not grant automatic PCP/NAT-PMP mapping; no manual router change has been
  made during this work. A reachable owner-operated peer is another possible path.
- Run equivalent lifecycle and network acceptance on physical Linux hosts.

No public IPv4 reachability, unattended-update firewall continuity, or external-network
success is claimed by this record. Two disconnected peers without a compatible reachable
address or reachable owner-operated member cannot guarantee rediscovery.
