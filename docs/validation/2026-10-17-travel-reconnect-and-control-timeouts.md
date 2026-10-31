# Travel: misleading control errors, and a stale path a same-subnet hotel could keep

Date: 2026-10-17
Verdict: **link recovered by itself; three defects found and fixed in the simulator; installed on the laptop only**

## Reports

From France, on the first night of the trip, the laptop's `supgang status` and the MCP fleet tool
answered "local control socket operation failed", and `supgang connect solis ssh` answered "peer has
no authorized live connection or tunnel admission is full" for about two to three minutes after the
laptop joined the hotel network. The link then recovered without intervention: the laptop recorded a
successful route to the home computer through the router forward at 02:26:14 CEST, and SSH and
Screen Sharing through Supgang worked. Two days earlier, the owner's first `supgang forward` from the
laptop failed with the same control error.

## Findings

- **Load.** The laptop's load average was 924 at 02:29 and 481 a minute later, on 12 cores, from
  simulation, EDA and agent processes. The control client waited 2 s for the service's reply. The
  service runs on one thread, and at load 240 one control request was measured taking 5 s. A
  request that outwaits the client fails, and the failure was reported as a generic socket error
  that says nothing about what happened or what to do.
- **Ambiguous refusal.** "no authorized live connection or tunnel admission is full" joined
  unrelated causes. That night it meant the session to home was down while the laptop reconnected.
- **Same-subnet hotel.** The hotel's LAN is 192.168.1.0/24 with its gateway at .254, like home.
  This did not cause the outage, because the hotel issued the laptop a different address and the
  departed-LAN check (`active::retire_unroutable`) compares the local address. A simulator scenario
  showed the remaining case: a hotel that issues the laptop its own home address leaves every
  interface identical. The laptop then kept reporting the dead home-LAN session, and never dialled
  the forward, until QUIC's 45 s idle timeout.
- **Not established.** Why reconnection took two to three minutes. No connection history exists to
  read. The DHCP lease restarted at 02:28:08, so the Wi-Fi association may have dropped. A captive
  portal or load starvation are also possible. A bounded connection-event history is the next step.

## Corrections

- **Control waits.** Owner commands wait up to 10 s; health and readiness probes keep 2 s, because
  their callers retry. A timeout is now `ControlError::Unresponsive`: "the local Supgang service did
  not answer within N s; this computer may be heavily loaded. Retry, or run `supgang service
  status`". Tunnel setup and the tunnel CLI commands keep that advice instead of a generic failure.
- **Refusals.** A refused tunnel names its cause and its remedy: revoked; not connected right now
  (Supgang keeps reconnecting); session authorization lapsed; every tunnel this computer allows in
  use; every tunnel allowed to this peer in use (with `supgang tunnel-limits`).
- **Silent paths.** Keepalives are now every 5 s instead of 15, which also refreshes short UDP
  mappings in hotel and carrier gateways. A connection that has heard nothing for 12 s is probed
  (`service::liveness`), retired only if the probe confirms it is gone, and an immediate redial
  follows. A connection that is slow but still answers is kept.

## Follow-up, not yet installed

- **Connection history.** Each computer keeps its last 32 connections made and ended, with the
  time, the peer's fingerprint, the path's kind (private or Internet, IPv4 or IPv6) and the reason
  it ended, never an address. `supgang status` shows the last eight; `--json` shows all. The
  same-subnet hotel scenarios assert that the history shows the home LAN connection ending with a
  reason and the forward connection that followed.
- **Probation for a remote refresh.** A refresh to a newer release is staged as the supervisor's
  pending candidate, under health probation. When a peer was connected, it must also reconnect a
  peer within two minutes, or the refresh restores the previous release (`docs/security/secure-updates.md`).

## Evidence

- `control/tests.rs`: a service that accepts a request and never answers is reported as
  unresponsive within the bound.
- `scenarios.rs`: a hotel on the home subnet issues the laptop (a) a new address, (b) its own home
  address, and (c) the home computer's address. In each case the laptop reaches home through the
  forward within 25 s and the tunnel carries bytes. Case (b) failed before the silence check.
- `scenarios.rs`: a refused tunnel names the per-peer limit when that limit is full, and names
  "not connected right now" while the peer is down.

## Installation

The complete gate passed (429 core tests). With the owner's approval, relayed through Supply, artifact
`f3a344f6fca7…` (owner-signed) was installed on the laptop only, on 17 October from France. The
previous build, `d0a7473c92ad`, was kept for rollback. After `service refresh` the laptop
reconnected to the home computer through the router forward in 26 s, measured from the start of the
refresh. Tunnelled SSH and the running Screen Sharing forward then worked. The home computer stays on
`d0a7473c92ad` until the end-of-trip remote update, which waits for update probation (a failed
build must revert by itself).
