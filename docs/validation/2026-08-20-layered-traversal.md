# Layered traversal and user-owned anchor validation

Date: 2026-08-20

Status: local implementation accepted; physical separate-network fleet acceptance blocked on Home B deployment

## Scope

This milestone adds four recovery mechanisms without a hosted Supgang dependency:

1. tightly staggered racing of current and historically signed candidates;
2. hive-synchronized bilateral retry windows;
3. observed-socket introduction through an already authenticated member;
4. an explicit inbound-oriented user-owned anchor role.

The anchor exchanges signed Supgang control state and coordinates direct attempts. It is not a VPN,
general message relay, public discovery service, account system, or claim of guaranteed reachability.

## Repository evidence

`make check` passed on macOS with:

- format and all-target compile checks;
- all-feature Clippy with warnings denied;
- 123 core tests and the repository policy self-test;
- warning-free rustdoc;
- the typed repository policy gate.

Traversal-specific coverage includes canonical bounded datagrams, arbitrary input without panic,
real QUIC datagram delivery, symmetric forwarding of two directly observed sockets, recent
single-use recovery intent, fixed intent memory, hive-aligned retry boundaries, candidate-race
spacing, anchor neighbor ceilings, and preferred-path replacement of an outbound fallback.

The three-endpoint forwarding test is a transport-level loopback test. It proves that the selected
QUIC implementation carries the exact bounded messages and that an introducer forwards each client
only the other client's observed address. It does not simulate a consumer NAT or replace physical
wide-area acceptance.

## Installed-build evidence

`make install` replaced the prior local source installation with `supgang 0.2.0-alpha.8`. The
installed executable SHA-256 is:

```text
a0a6e97377c6800142665eca9561cf01354f68253ad33472ecc2bcb6074ac549
```

The native background service restarted through its bounded readiness check. From outside the
repository, `supgang status` reported the new recovery policy in plain language and JSON reported
`connection_recovery: automatic-multi-path` with `mode: device`.

A fresh temporary hive ran the installed binary in foreground anchor mode on a non-default port.
The owner-only control channel reported `service: running` and `mode: anchor`. After a termination
signal, the same installed command reported `service: stopped`. The temporary test identity was
moved to the operating-system trash after the check.

## Physical fleet gate

Laptop A is currently on a network outside the home LAN. Its installed alpha.8 service is running,
but the current gateway offers no automatic mapping and no Home B session is active. The home-LAN
Home B address is not routable from this network, so alpha.8 could not yet be installed on Home B.

This is a deployment blocker, not a passing WAN result. The required next run is:

1. return Laptop A to the home network;
2. deploy the exact alpha.8 artifact to Home B using only the authorized local account;
3. restart both installed services and prove a connected LAN baseline;
4. move Laptop A to an outside IPv4 network;
5. prove direct recovery through automatic mapping or peer-assisted traversal;
6. verify current signed address convergence and live connection status on both computers.

A two-member fleet with no reachable third member cannot exercise the new introduction path after
both direct edges disappear. A physical anchor acceptance therefore also requires a third
user-owned Supgang member with a reachable address. Hard NAT, blocked UDP, anchor loss, or two
isolated members changing to unknown addresses at the same time remain explicit non-guarantees.
