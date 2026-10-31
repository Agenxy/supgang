# Opt-in service tunnel: installed physical LAN acceptance

Status: physical LAN passed; WAN acceptance open. Dibs request 52763, milestone 2.
Measured 6 October 2026, approximately 16:25–16:32 UTC.
This is a local source installation, not a published release or a production remote-access guarantee.

## Artifact and installation

The complete local gate passed: `cargo run --locked --package supgang-quality -- all`.
The core had 392 passing tests and two existing ignored tests. Workspace checks, all-feature
warnings-as-errors linting, documentation, policy and package verification passed.

The normal `make install` flow produced version `0.2.0-alpha.10`, signed using the same existing
owner-controlled signing identity already present on both physical acceptance computers.
The exact signed artifact was copied to the second computer and verified before installation.
Both background services were refreshed using `supgang service refresh`, preserving their settings.

SHA-256 of the artifact on both computers:

```text
a2b23274297c8916e1e5383c76e52d45d159f853ce2a4055438be5827d439bb5
```

Outside the repository, the normal command paths, help and doctor were checked on both hosts.
Strict macOS signature verification passed. Normal command, protected supervisor and active-slot
payload hashes matched. Each control-socket owner's running executable path matched the active
payload, and manager ownership was reported as `supervisor-child`.

Doctor exited zero on both computers. Identity, authoritative state and public-dependency checks
were `ok`. Internet reachability remains unproved, and the existing file key provider remains
extractable; both checks correctly reported warnings. These do not constitute WAN or hardware-key
acceptance.

An installation check also exposed an existing lifecycle defect: full launchd login inventories
exceeded the 64 KiB capture bound even though the caller needed only an exit status. The correction
discards output for status-only commands, retains the five-second process deadline, and preserves
ESRCH-only missing-target semantics. Data-bearing capture remains bounded at 64 KiB. Regression
tests cover large output and authorization/signal failures; the complete gate above includes the fix.

## Physical behavior

Both computers remained on the home LAN. The actual authenticated QUIC connection used IPv6;
a native destination route query selected a source in the same home /64. This is LAN evidence,
even though both addresses are globally scoped. No off-network connection was measured.

1. Before exposure, `supgang connect solis ssh` returned exit 3, static refusal text on stderr,
   and zero stdout bytes. The destination had no tunnel policy file.
2. The destination owner explicitly enabled the fixed loopback target with `supgang expose ssh 22`.
   Existing peer sessions closed and reconnected under the new policy.
3. SSH through the Supgang ProxyCommand used the existing trusted host key and approved account,
   with strict host-key checking, batch authentication, and connection reuse disabled for the proof.
   The remote installed-artifact digest matched the local artifact.
4. A 131072-byte synthetic input was echoed through SSH exactly after stdin EOF. SSH exited zero
   and emitted no stderr. Fixture SHA-256:
   `73b0f6df253ed8fe4cd4396e864429a84a2782f6175cffa9fb4a710f62e644f5`.
5. Removing exposure terminated an already authenticated SSH fixture. The client exited nonzero
   within approximately 15 ms after the removal acknowledgement and emitted no late application
   bytes. The requested `ssh` exposure was restored, and the peer reconnected.
6. The ordinary existing SSH alias also worked cleanly with the ProxyCommand override below.
   `supgang doctor --peer solis` reported a signed public endpoint and its expiry, explicitly
   stating that this is no proof of WAN reachability.

```sh
ssh -o 'ProxyCommand=supgang connect solis ssh' solis
```

The acceptance commands additionally forced strict host-key checking and disabled SSH multiplexing
to prove the tunnel was used. The temporary test configuration retained existing usable identity
files; nonexistent optional default key paths were omitted to avoid artificial missing-file errors.
No host key was accepted anew. No public TCP SSH forwarding or gateway changes were made.

## Source tests and remaining acceptance

Real paired QUIC runtimes cover default denial, signed mapped-endpoint gossip, 96 KiB transfer and
half-close, admission refusal, exposure removal and root revocation during active transfer.
Native stdio tests cover response after stdin EOF and cancellation on peer EOF. Session-authority
tests cover shared renewal, no shortening, no expired/revoked revival, transport-key/generation/node
binding, and a waiter surviving the original expiry before revocation. Injected route tests cover
missing family, ULA-only/no-route, explicit/on-link/default routes and changed route results.

WAN milestone 3 remains open. The owner must configure the narrow inbound UDP 44330 rule on the
home gateway, publish an owner-mapped public IPv4 fallback if forwarding is used, and provide a
phone-tether acceptance slot. Exact IPv6 UI fields and PCP/NAT-PMP support on the observed gateway
remain unverified. The [design note](../architecture/0003-opt-in-service-tunnels.md) records the
router boundary and the bootstrap gap when every authenticated edge and remembered path is lost.

Neither this LAN result nor a public candidate, router declaration, passing gate or UDP probe
satisfies separate-network SSH acceptance.
