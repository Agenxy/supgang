# Roaming reconnect: a stale path no longer blocks a new one

Date: 2026-10-15
Verdict: **passed in the simulator and on the owner's two computers; deployed**

## Defect

When the laptop left a network, the home computer kept the laptop's old connection registered
until QUIC's idle timeout. A new connection from the laptop's new network authenticated but was
refused by admission as a duplicate, so a roam could leave the pair apart for most of a minute.
Returning home had the opposite problem: the connection through the router forward kept working,
so nothing moved the pair back to the LAN.

## Correction

- **Liveness probe** (`service/liveness.rs`). When a peer authenticates a connection over a
  different path while another is registered, the registered one is sent a one-byte QUIC
  datagram. Any live peer acknowledges it at the transport layer; receivers ignore it as a
  non-rendezvous datagram, as every earlier release did. If no packet arrives within an
  RTT-scaled window (four RTTs, 0.5–2.5 s, two attempts), the old connection is invalidated
  and the new one admitted. A connection that cannot be probed is treated as live, so admission
  behaves as before.
- **On-link upgrade.** A connection over a directly attached network supersedes one that is not,
  even while the indirect one works. Both computers see the shared LAN as attached, so they agree
  which connection survives. The retry schedule keeps dialling on-link candidates of a peer
  connected off-link, and an active connection whose local network has left the computer is
  retired at once.

## Simulator evidence

The full gate passed (423 core tests). Bounds asserted by `service/tests/scenarios.rs`: roaming
to a hotel and returning home each reconnect within 15 s; a crashed peer within 90 s. The probe
judges a departed peer gone within 6 s (`connection/tests/liveness_cases.rs`).

## Physical evidence

Artifact `d0a7473c92ad217fdbbf5320ea274d7cb2d7bc76c5c974e9071923f612e04d9a` on the laptop and
the home computer. The previous builds were kept for rollback and were not needed.

On the home LAN:

- Home computer's signed record: eight candidates including the mapped forward.
- Tunnelled SSH, `supgang forward` to a test page, and a QUIC probe through the router forward
  all passed.
- A home service restart reconnected in 7 s; a laptop service restart in 15 s.

Roam, with a once-a-second watcher on the laptop:

| Event | Observed |
| --- | --- |
| Laptop moved to a phone hotspot | down at 10:59:26, connected through the router forward at 10:59:33 (7 s) |
| Over the hotspot | tunnelled SSH and `supgang forward` passed |
| Laptop back on home Wi-Fi | moved from the forward to the LAN path with no observed outage |

The watcher measured from the moment the laptop marked the old connection down; the exact
Wi-Fi switch time was not captured, so the switch-to-reconnect time may be slightly longer.
