# Service tunnel: physical WAN acceptance

Date: 2026-10-13
Verdict: **passed over IPv4 through the owner's UDP forward**; request 52763 milestone 3.

## Configuration

Both physical Macs run artifact
`3f528aac5b21b231ad7b4850ce6388cf444d73299fb5b421f2c57d46ae24fc5c`, signed by the existing owner
identity, with tunnel limits of 40 per peer, 64 total and an 86,400-second idle deadline. It
includes the scheduling-class correction, the departed-LAN retirement, and the raised stream
and window limits recorded in the [simulation record](2026-10-12-simulated-travel-scenarios.md).

The home gateway hosts UDP 44330 on the home computer. Its signed record carries the gateway's
public IPv4 as an owner-mapped candidate, read from the gateway's own status page.

An earlier attempt from a phone hotspot failed although the forward existed. The home computer's
application firewall blocked inbound connections to the running build slot: the owner signing
certificate was not trusted, so "allow signed software" did not apply and each new slot was an
unlisted background executable. LAN sessions had masked this because the home computer could
dial out. The owner ran `tools/setup_macos.py --apply` with the certificate's SHA-1 and SHA-256,
which trusted it for code signing only, approved the runtime and supervisor, and rewrote the boot
definition with the `Standard` class. That run first exposed a setup defect: its lock lived in
`/private/var/run`, which stock macOS leaves group-writable, so its own ancestor check refused it.
The lock now lives in the tool's root-owned directory, with a regression test.

Before the owner left, a QUIC version-negotiation probe to the gateway's public address on the
home LAN (hairpin) and to the home computer's LAN address were both answered by Supgang.

## Off-network measurements

The laptop joined an outside network; the home computer's LAN address was unreachable.

- The same probe sent to the public address from outside was answered.
- Supgang reported an authenticated connection through the home public IPv4 forward within 3 s.
- SSH through `supgang connect solis ssh`, with strict existing host-key trust, reached the home
  computer, which reported the same artifact hash.
- Eight SSH masters, opened sequentially, were simultaneously live; a command ran through each.
  A command over an existing master took about 205 ms.
- 50 MiB uploaded at 9.3 MB/s and 50 MiB downloaded at 10.8 MB/s, each SHA-256 verified.

Thirty-two concurrent masters were verified only on the LAN. There, the home computer's sshd
closed connections before its banner after aborted probes: its per-source penalties have no
exempt list, and every tunnelled session arrives from loopback. An owner sshd change exempting
loopback and raising `MaxStartups` is pending.

## Limits

IPv6 from outside does not reach the home computer: the gateway's default inbound IPv6 filtering
refused it, and no pinhole was added. A change of the home public IPv4 while away breaks the
forward path until the mapped address is republished from home. Reconnection after a network
change can take up to about 80 seconds while the home side holds its stale connection; that
admission fix is tracked separately. Sleep and wake off-network, and a second outside network,
remain for the Labs travel profile.

## Addendum: laptop CLI after acceptance

Later on 13 October the laptop alone was updated to
`852e31d095e272da02a849243b98cb7c7def3c59c74e15b823e4d3dd36cb5005`. `supgang connect` now calls
`setsid` so an SSH ProxyCommand outlives the process group of the script that created an `ssh -f`
master; without it a job runner tearing down that group broke the master with "Broken pipe". The
wire protocol is unchanged and the home computer intentionally remains on `3f528aac…` while the
owner is away; the off-network check repeated afterwards (master survived its creator's group and
ran a command on the home computer through the tunnel). Both builds' slots are retained.
