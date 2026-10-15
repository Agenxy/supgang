# Background scheduling class starved the service under load

Date: 2026-10-12
Verdict: **root cause fixed on both physical peers; WAN acceptance still open**

## Failure

On the laptop, `supgang connect solis ssh`, `status` and `peers` all failed with
`local control socket operation failed`. The service process was alive and its QUIC session to the
home computer stayed up, but a raw client found the control socket never accepted within 12 seconds.
The process accumulated 0.02 seconds of CPU in 10 seconds while the machine's load average was 355
on 12 cores, driven by unrelated simulation and CI work. Its thread ran at Darwin priority 4.

The launchd definition requested `ProcessType` `Background`. macOS confines that class to
efficiency cores and throttles its I/O, so under sustained load the single-threaded runtime reached
its control-accept point only rarely. Lifting the policy on the live process with `taskpolicy -B`
did not change its priority. A remote-access service must not be in this class: the failure
removes exactly the path the owner needs while away.

## Correction

Both the per-user agent and the administrator-owned boot definition now request `Standard`.
`service refresh` rewrites only a legacy `Background` value in an installed per-user definition and
preserves every other key. The boot-definition validator compares an approved definition as if its
legacy class were upgraded, so a definition approved before this change stays valid; any other
class is still refused. The owner setup tool writes `Standard` on the next approval. Tests cover the
rendered class, the byte-exact fixture, upgrade of only the legacy class, and boot validation of
`Background`, `Interactive` and `Adaptive`.

## Installed artifact

The complete local gate passed: `cargo run --locked --package supgang-quality -- all`, with the
pinned 1.97.1 toolchain. Its first run failed one existing control-client test that does not touch
this change (`client_treats_a_safe_stale_socket_as_service_stopped`, `UnexpectedEof` during a
378-second test run under the load above); it passed three isolated reruns and the full rerun.

`make install` produced `0.2.0-alpha.10` signed with the existing owner identity. SHA-256 on both
computers, with strict signature verification on each:

```text
1e299699c592648118e1199be7ce91bc0045b2f33af8ea4a698a46a0bd204c96
```

The laptop's refresh rewrote its definition to `Standard`. At load average 151, five consecutive
`status` requests then succeeded in 0.46–1.22 seconds, the peer reconnected, and SSH through
`supgang connect solis ssh` passed with strict existing host-key trust and no multiplexing.

The home computer was refreshed through its system-boot service and runs the same slot. Its
root-owned boot definition still says `Background` (priority 4) until the owner re-runs the
administrator setup; its load was about 18 on 24 cores at the time.

## Related observations

- The home computer's sshd intermittently reset connections during these checks: `MaxStartups`
  is `10:30:100` and `PerSourcePenalties` has no exempt list. Tunnelled sessions all reach sshd
  from loopback, so a loopback penalty would refuse every tunnelled session at once.
- The home computer's owner-mapped public IPv4 was published with `endpoint add-mapped` from the
  owner-only file; the laptop holds it in a fresh device-signed record. No gateway forward exists
  yet, so this is not reachability evidence.
- An apparent host-key mismatch during diagnosis came from a malformed probe that connected to
  the laptop itself; the home computer's host key matched existing trust.
