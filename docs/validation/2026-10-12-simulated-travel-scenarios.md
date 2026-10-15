# Simulated travel scenarios: what the home gateway decides

Date: 2026-10-12
Layer: 1, in-process simulation ([ADR 0002](../architecture/0002-network-test-lab.md)).
Verdict: **the owner's trip depends on one gateway fact the simulation cannot supply**

This is evidence about the production service against declared gateway models. It is not WAN
acceptance and says nothing about how the owner's actual gateway behaves; the
[runbook](2026-10-06-service-tunnel-wan-runbook.md) still governs that.

## Scenarios

Each scenario pairs the home computer and the laptop on a simulated home network, starts the
production service on both, then moves the laptop. A pass requires an authenticated connection on
the stated path in both directions and 64 KiB carried intact through `supgang connect`, or, for a
refusal, no connection reported for 25 seconds and the refusing gateway identified by its drop
counter. The home gateway is modeled on RFC 4787's recommended behaviour (endpoint-independent
mapping, address-and-port-dependent filtering, port preservation, hairpinning).

| Laptop network | Home router configuration | Outcome |
| --- | --- | --- |
| Home LAN | none | Connected on the LAN; tunnel bytes intact |
| IPv4-only hotel, symmetric NAT | UDP 44330 forward plus published mapped address | Connected to the forward; tunnel intact; back on the LAN after returning |
| IPv4-only hotel, symmetric NAT | mapped address published, no forward | Refused at the home gateway (`NoMapping`), no false connection |
| Phone hotspot, CGNAT IPv4 and stateful IPv6 | inbound IPv6 admitted (Reflexive ACL off) | Connected over IPv6; tunnel intact |
| Phone hotspot | IPv6 default deny (Reflexive ACL on), no forward | Refused at the home firewall (`Firewall`), no false connection |
| Phone hotspot | IPv6 default deny with a UDP 44330 pinhole | Connected over IPv6; tunnel intact |
| IPv4-only hotel with forward, home computer restarts | forward | Reconnected through the forward |

The suite ran green four consecutive times after the corrections below, in 76–87 seconds each.

## Defects found

**A connection over a LAN the computer had left stayed live.** After the laptop moved, its service
kept reporting the connection made to the home computer's private LAN address and suppressed
redialing until QUIC's 45-second idle timeout. Route compatibility asked only whether the remote
address was routable, and a private address is routable through any default route. A connection
now records the directly attached network its remote was on when it was made, and is retired when
that network disappears from this computer. Paths through a router or VPN were never on-link and
are unaffected. The laptop now retires the stale path within one five-second interface refresh.

**The home side holds its stale connection and rejects the laptop's new one.** The home computer's
interfaces do not change, so it keeps its connection until the idle timeout. When node-identifier
order ranks that connection preferred, admission rejects the laptop's fresh, fully authenticated
connection as a duplicate. Reconnection after roaming therefore takes up to about 80 seconds in
roughly half of runs. Scenario bounds state this current behaviour; a fix needs a symmetric
replacement rule and is tracked separately.

Two model errors were corrected before any conclusion was drawn: a forward was inbound-only
(real gateways answer from the forwarded port), and the pairing fixture read the clock before
initialization. Calibration tests now pin both.

## What this means for the trip

Without a router change, the laptop reaches home only over IPv6, and only if the home gateway
admits unsolicited inbound IPv6. Public reports say the AT&T BGW320 drops it by default through
its Reflexive ACL; the successful 2026-09-17 external IPv6 session suggests this gateway may differ.
That single setting, readable in the gateway's Firewall Advanced page with the access code, decides
whether the phone-hotspot path works. The UDP 44330 forward makes IPv4-only networks work
regardless. Neither path survives a change of the home public IPv4 or IPv6 prefix while away.
