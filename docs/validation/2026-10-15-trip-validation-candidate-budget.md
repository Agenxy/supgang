# Trip validation: a published forward stopped the home service

Date: 2026-10-15
Verdict: **defect found by the pre-trip validation pass, fixed and reinstalled on both computers**

## Failure

A requested restart of the home computer's boot service never came back. launchd had started it 49
times; each run exited 3 with "service configuration is invalid" within 0.1 s. Automatic interface
discovery now found eight addresses: two private IPv4 (the LAN and the macOS VM bridge), the
bridge's private IPv6, and five public IPv6, as macOS had accumulated temporary addresses since
the 13 October acceptance. Adding the owner-published UDP forward made nine against the
eight-candidate limit, and `with_mapped_addresses` rejected the whole configuration. The
five-second interface refresh already reserved room for owner-declared addresses; only startup
did not. Any restart during the owner's trip would have left the home computer unreachable over
Supgang.

## Correction

Owner-declared addresses (mapped forwards and owned relays) always fit; discovered interface
addresses yield by the rule the periodic refresh applies, keeping both families represented. A
configuration is refused only when owner-declared addresses alone exceed the limit. A regression
test reproduces the home computer's address set.

## Installation and recovery

The complete gate passed (420 core tests). Artifact
`5fa50f1de86e3a59689ac47540dd9c9096c0995a37baa7b85f5187ede154450e` was installed on the laptop
and, hash- and signature-verified, on the home computer. The crash-looping boot service could not
take a refresh, which hands over through the running service, so recovery used owner state only:
the forward was removed from the protected tunnel policy (byte-exact backup kept), the previous
build started, `service refresh` installed the fix, `endpoint add-mapped` restored the forward,
and the backup was removed after verification.

## Results

- Home computer's signed record: eight candidates including the mapped forward.
- A home service restart reconnected in 7 s; a laptop service restart in 11 s.
- A QUIC version-negotiation probe to the home public address was answered through the forward.
- Four concurrent tunnelled SSH masters and a 20 MiB hash-verified transfer passed.
- The simulated travel suite passed (24 tests).

Not covered: repeated sleep and wake off the home network, an unattended reboot (FileVault is on,
so nothing starts before console unlock), a home public-address change while away, and sshd
loopback penalties under many reconnects (the owner's sshd change is pending).

A crash-looping boot service also cannot be refreshed without administrator rights or manual
state repair; a refresh path that does not depend on the running service is a follow-up.
