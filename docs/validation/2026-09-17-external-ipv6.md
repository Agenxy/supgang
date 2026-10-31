# External-network IPv6 validation

Date: 2026-09-17

Scope: two existing physical macOS Supgang peers, with the laptop on a different network from
the stationary peer. This is not IPv4-only, Linux, arbitrary-network, SSH, or update-activation
acceptance. No third Supgang peer, relay, hosted discovery service, or router change was introduced.

## Installed artifact and network

The laptop's normal installed CLI and running protected slot use the previously installed build:

`c1c3699cfcb28d65eb1369eb0d65dc2c24505a88d4e218987d10b1f28abda178`

The stationary device's matching artifact was verified in the preceding home-network validation;
its executable hash could not be independently reread during this run because WAN SSH timed out.

The laptop has a different IPv4 default gateway and an IPv6 default route through its current
physical network interface. The stationary peer's private address is classified as off-link.
The route to its public IPv6 address uses the outside network, not a local home-network path.
Strict mode reports zero public dependencies, and the directory contains exactly one remote peer.

## Fresh connection evidence

The initial status reported one connected peer, but this alone was not accepted as proof. The
laptop's Supgang service was restarted, preserving identity and configuration. Immediately after
restart it reported zero peers and no fresh peer observation. It subsequently reported one
authenticated peer and a new, short-lived public-address observation from that peer.

The peer listing also contains a newly created local observation of the stationary peer's public
IPv6 socket. This ephemeral observation was acquired after restarting the service; it was not a
persisted contact copied from the earlier home-network test. The preferred address is the fifth
public candidate in the signed contact, beyond the old fixed four-candidate cutoff. This is
consistent with the candidate-rotation fix helping this connection, not proof that it alone
explains every earlier failure.

The remote signed contact itself retains its earlier sequence because the stationary device has
not published a newer contact during this observation. It remains valid. Evidence of a new
exchange comes from the restarted session and fresh peer observations, not from falsely claiming
that a cached contact advanced its sequence.

The first observation collected 90 healthy status responses at one-second intervals. The first
connected sample was index 11; the remaining 79 samples all reported one connected peer. The
subsequent observation collected 120 healthy responses and 120 connected samples at one-second
intervals. It spans more than the configured 45-second QUIC idle timeout. This is sampled
connection stability, not a claim of lossless packet delivery or long-duration availability.

The ordinary peer command displays the stationary device as connected and prefers its public IPv6
address. Its inaccessible private address is not recommended from the outside network.

## Limits

- This is a successful new Supgang session over IPv6, not evidence of a working public IPv4 path.
- WAN SSH attempts to two authorized peer IPv6 candidates timed out. Supgang connectivity does
  not establish that an unrelated service such as SSH is reachable.
- Packet capture was unavailable because the account lacks capture permission and no cached
  administrator authorization was available. No password prompt, firewall change, or privilege
  change was requested. The evidence is authenticated application state and OS routing, not a
  complete packet-level traffic audit.
- Local update status reports `trusted: false` and no staged release. A peer software update was
  not attempted: the release trust authority must be provisioned through the owner-approved flow
  before an update-activation test can be claimed. Signature verification was not bypassed.
- The broader security-review and cross-platform acceptance gates remain separate. This test
  does not supply the previously blocked independent Opus review.

No production source changes or public release were made during this validation.
