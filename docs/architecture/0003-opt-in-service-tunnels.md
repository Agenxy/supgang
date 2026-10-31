# Opt-in authenticated service tunnels

Status: implemented for Dibs request 52763, 6 October 2026; installed physical LAN acceptance passed.
Separate-network acceptance remains open. See the [LAN acceptance record](../validation/2026-10-06-service-tunnel-lan-acceptance.md).

## Scope

Add `supgang connect PEER SERVICE` as a byte-only stdin/stdout transport suitable for SSH ProxyCommand.
The client uses the running owner's service and its existing authenticated QUIC session.
The server accepts only a named service explicitly configured by its local owner.
For the first acceptance case, `ssh` maps to IPv4 loopback TCP 22 on Solis.
The remote request cannot choose an IP, port, Unix socket, executable or next hop.
This extends the current address-plane product with optional application transport;
ordinary discovery and existing service advertisements do not enable forwarding.

SSH still verifies Solis's existing host key and authenticates `dr.marbles` end to end.
Supgang's member authentication does not replace either check.
No SOCKS proxy, shell execution, VPN, public discovery, third-party relay or automatic gateway change is added.
Router settings belong to the owner. Hole punching and an owner-operated relay remain separate work.

## Local authorization and configuration

Persist the exposure allowlist as a bounded owner-only document in protected Supgang state.
Use an explicit CLI to add/remove named loopback ports; advertise commands remain independent metadata.
Initially allow at most four service names, using the existing restricted 1..16 ASCII ServiceName type,
nonzero TCP ports and a fixed `127.0.0.1` target. Reject duplicate and unknown fields and unsafe file permissions.
Removing exposure must deny new streams and cancel existing streams before acknowledgement.
An exposure grants access to currently authenticated, unrevoked members of this hive;
document that trust scope prominently. A later per-member policy can narrow it without broadening targets.

The CLI resolves a unique name/tag/fingerprint through the existing local trusted directory.
A connection request contains the exact node identity and service name, never a peer address in arguments.
Reuse the private 0600 Unix control socket with same-user credential validation.
After a bounded request and success reply, transfer that local socket to a bounded stream worker.
Reject JSON mode for byte transport; stdout must contain only target bytes.
Failures use static address-free diagnostics on stderr and nonzero exit status.
No reconnect or stream replay after failure: repeating an SSH byte stream is unsafe.

## Wire and lifecycle

Use a new typed post-authentication bidirectional stream with a versioned bounded service-name preface.
Return a fixed bounded accept/refuse response before any application bytes.
Do not accept a service stream on a connection before complete membership and transport authentication.
The existing signed record capability parser rejects unknown bits; do not silently add a capability
that makes old clients reject ordinary contacts. Establish an explicit compatibility policy before publishing one.
Old runtimes may reject a new stream type; the CLI must report that safely rather than imply remote SSH failure.

Central SessionAuthorization covers membership expiry, received root revocation, connection replacement and shutdown.
Both inbound and outbound workers share it and cancel immediately when invalidated.
No worker survives loss of its authenticated session. Exposure removal has its own cancellation authority.
The peer actor must continue servicing gossip and revocation while streams transfer data.
Keep bounded worker sets and reject excess demand without allocating an unbounded queue.

Default implementation bounds: four concurrent streams per peer, sixteen total per runtime,
five-second service setup deadline, 16 KiB copy buffers per direction, and two hours without bytes in either direction.
The owner can configure 1..16 streams per peer, 1..128 total and 60..86400 idle seconds while the service is stopped.
There is no fixed active-session lifetime: authenticated session authority and membership expiry bound it.
Use backpressure and preserve independent half-close: stdin EOF closes only the outgoing half,
and remaining response bytes can still arrive. Do not buffer a whole file or log payloads.
Keep control/gossip receive budgets reserved within QUIC's fixed stream/window ceilings.
Idle behavior must permit interactive SSH but cannot leave admission occupied after session expiry.
QUIC reserves eighteen bidirectional stream slots and a fixed 2 MiB connection receive window:
at most sixteen application streams plus control/update capacity, with 64 KiB per-stream windows.
Changing exposure closes existing authenticated sessions before acknowledgement; reconnecting sessions use the new policy.

## Threat boundaries and rejection tests

An unauthenticated datagram or QUIC connection cannot trigger loopback TCP activity or durable state mutation.
A member can access only target-approved service names. Unknown/malformed names, caller-supplied targets,
oversized headers, excess concurrency and timeout must fail before target connection.
Protected local state rejects other users, symlinks, permissive files, oversized documents and unknown fields.
No hostname/DNS resolution occurs on the server. Fixed loopback prevents access to other LAN hosts.
Loopback exposure can still grant sensitive application access to every authorized hive member;
the owner must opt in explicitly and SSH's own authentication remains mandatory.

Test real QUIC paired runtimes and TCP echo/SSH-like fixtures: bidirectional bytes, half-close, backpressure,
unknown service, default-deny, malformed preface, concurrency limits, setup/transfer timeout,
revocation during transfer, membership expiry, removal during transfer and disconnect.
Also prove byte-only CLI output, unique peer selection, mixed-runtime refusal and local credential checks.

## Route reporting bug

Track as normal bug: family presence currently marks global IPv6 candidates route-compatible on a ULA-only laptop.
Use the OS's destination-specific route selection without sending a probe packet.
A safe native UDP socket bind/connect/local-address query can ask the kernel to select a route;
no datagram is sent, and this is route evidence, not observed peer reachability.
Keep a pure injected route-selection boundary for deterministic tests.
Reject no-route and reject/blackhole failures; retain valid explicit routes, on-link routes and default routes.
Cover ULA-only/no-default, missing family, explicit private route, on-link peer, default route, kernel failure,
and network-change invalidation. Do not equate the existence of a default route with a successful QUIC session.

## Address freshness and manual mapping

Current runtime re-enumerates automatic interfaces every five seconds and refreshes signed contacts
on interface change and at half the configured record lifetime (default lifetime six hours).
Authenticated gossip carries newer verified records over surviving connections.
Bounded historical authenticated/signed paths may recover an edge, but do not discover an unknown new prefix.
For a live session, a newly verified contact from the same authenticated device may extend authority
only when its transport key and generation match the original handshake. The contact must pass the
normal root, membership, revocation, sequence and expiry checks. Expired or revoked authority cannot
be revived; a changed transport key or generation requires a new handshake. Waiters share the renewed
expiry, so an actively used SSH session can survive successive six-hour contact refreshes.
If all edges fail and all remembered home addresses change, the laptop needs an owner-carried fresh signed contact
or a separately configured reachable owned anchor. History is no guarantee and expired authority is not extended.

Manual IPv4 forwarding must also publish the owner's declared public UDP endpoint in Solis's signed contact.
`supgang endpoint add-mapped --from-file /private/path/endpoint` accepts a public IPv4 UDP socket
from an owner-only file, then signs and gossips the change over the live LAN session.
`supgang doctor --peer solis` shows signed public endpoint presence and contact expiry without an address.
A gateway forward alone does not cause Supgang to learn its public IPv4 on the home LAN.
Use the existing owner-only endpoint configuration with a mapped candidate and carry its fresh signed contact
to the laptop before roaming. A dynamic public IPv4 change requires updating that configuration/contact.
Automatic PCP/NAT-PMP is optional and needs a positive live mapping result; support on this BGW is unverified.

## Owner router procedure

Supply reports live read-only evidence: HUMAX BGW320-500, software 6.35.8,
hardware 02001F00460050. Its menu contains Firewall, NAT/Gaming, Custom Services,
Packet Filter and Firewall Advanced. The actual configuration field labels require the owner's access code.
Confirm Solis's assigned addresses first.
Keep device access codes and public addresses private. Reserve Solis's LAN IPv4 allocation so the rule stays attached.
The required rule is only UDP external 44330 to Solis UDP 44330. Never forward TCP 22 for this tunnel.

For this gateway, use Firewall, NAT/Gaming, Custom Services: name `Supgang`,
Global Port Range `44330` through `44330`, Base Host Port `44330`, protocol UDP;
then assign the service to Solis in Needed by Device and save Hosted Applications.
The menu is observed; confirm the gated field labels before applying.
AT&T's current [BGW320 guide](https://www.att.com/device-support/article/31783/at%26t/bgw320/)
describes a different Networking, Port forwarding interface, so its field labels are not treated
as proof of the observed 6.35.8 firmware's configuration page.
If another router sits downstream, check the path and add only the matching narrow rule there if required.

For IPv6, request a narrow inbound allow rule for Solis's assigned global /128, UDP destination 44330.
Do not assume the `::c` address is permanently stable merely from its appearance.
IPv4 NAT/Gaming is not proof of an IPv6 pinhole. Exact IPv6 UI steps await model/firmware evidence;
do not disable the IPv6 firewall or grant an all-ports host exception to work around missing controls.
IPv4 forwarding can provide first WAN acceptance without waiting for IPv6 if the home IPv4 is reachable.
No authoritative source or positive local probe currently confirms BGW PCP/NAT-PMP support.
Plan manual forwarding; `--router-mapping` is not a promise that this gateway can perform it.

## Acceptance and estimates

Run focused tests then `cargo run --locked --package supgang-quality -- all` without weakening gates.
Install through `make install`, verify external command path, artifact hash/signing, help and JSON doctor.
Install the same release artifact on both physical peers before protocol acceptance.
On LAN, test SSH through a private owner SSH config with `ProxyCommand supgang connect solis ssh`,
the approved account and existing trusted HostKeyAlias, StrictHostKeyChecking yes and BatchMode yes.
Record authenticated peer identity and bounded success evidence, omitting addresses and keys from ordinary logs.

Then switch the laptop to phone tether, verify the home LAN is not the selected route,
and run `supgang --json resolve solis`, followed by SSH using that private config.
Resolution prints peer addresses intentionally; keep that output private.
A UDP port checker or `nc -u` is not an acceptance command; require actual authenticated QUIC plus SSH host/user auth.
Verify a bounded remote identity command and confirm it executed on the intended Solis host.
Repeat forced session disconnect/recovery and confirm no public TCP SSH rule was needed.
Router rule presence, LAN tests and passing CI do not count as WAN acceptance.

Planning estimate after this source inspection: one to two engineering days for the tunnel, route fix,
negative tests and complete local gate; reserve another session for same-artifact physical LAN validation.
After owner router changes, reserve one to two hours for tether verification and diagnostics if the signed home endpoint
is reachable. These are estimates, not a promised deadline; gateway/bootstrap failures can add work.
Do not mark request 52763 complete while physical WAN SSH acceptance remains unproved.
