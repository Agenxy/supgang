# Local command reliability, address preference, and connection agreement

Date: 2026-09-16

Scope: corrective development build; not a WAN, Linux, or release-security acceptance.

## Reproduced defects

The service raced an entire owner-control transaction against incoming QUIC acceptance. Network
activity could win after the local socket was accepted, cancelling a partially read command or
an in-progress response. A deterministic regression holds a partial owner request open, makes a
competing network event ready, and checks that the command still completes. It failed against the
old dispatch structure and passed after the fix.

Only acceptance is now raced. Once selected, the control transaction retains its existing bounded
read and write deadlines. Tests cover valid, malformed, and stalled requests, and preservation of
the competing network event. Ownership and socket validation are unchanged. A cancelled command
is a confirmed defect, but the historical transient control failure was not captured with enough
evidence to attribute every symptom to this one cause.

Status queries also caused unnecessary gossip because dispatch reported a state change regardless
of the operation. It now propagates the handler's actual change flag. Read and malformed-request
tests require no change; a revocation test requires gossip for the first mutation and not its replay.

Live home-network checks exposed a second defect: a public observation displaced an available
private address in the preferred result. Resolution now favors compatible local reports or signed
local addresses. Its regression failed before the correction and now covers home versus away
selection, disabled recommendations, and deduplication when a local address has both provenances.
Address preference remains a routing recommendation, not an independent proof of reachability.

A subsequent installation check failed its connection requirement even though both services
answered commands. Investigation reproduced an inconsistent connection ranking: an anchor could
consider a connection replaceable while its device peer considered that same connection preferred.
When competing connections arrived, each could close the other's choice. Ranking now depends only
on the authenticated identities and connection direction, so both ends agree. Anchor capacity
remains independently configured. The symmetry regression failed before the correction and passes
after it; existing admission and real-QUIC reverse-direction tests also pass. This establishes a
protocol defect, not proof that it caused every previously observed connection delay.

## Source checks

The complete `cargo run --locked --package supgang-quality -- all` gate passed after the final
source changes: repository policy, formatting, workspace checks, warnings-fatal Clippy, 220 core
tests, three ACL tests, one quality-policy test, and warnings-fatal documentation generation.

## Installation checks

Installed the final corrective build on both physical macOS peers using their existing owner
signing trust. Strict signature verification passed before remote activation. The normal CLI,
protected supervisor, and active runtime slot on each device have the same SHA-256:

`79053804fc336e5e21ec136ffe68358972f72406ef7362b7d6a8a8e5d61f485a`

Process inspection confirmed that both services actually execute that slot. Both refreshed without
an owner prompt and reconnected; laptop login startup and stationary-peer boot startup were
preserved. Commands were checked outside the repository. Both resolve results contain fresh peer
records, one preferred compatible local address, and a separately available public address.

After reconnection, each machine completed 120 consecutive status samples at one-second intervals:
120 healthy responses and 120 connected samples on each side. This spans multiple default retry
rounds, including the secondary recovery cadence. Sampling demonstrates the observed two-minute
LAN stability, not uninterrupted packet delivery or long-duration availability. The earlier build's
failed connection check is not counted as successful acceptance.

## Remaining acceptance

- The requested Claude Opus 5 review was attempted but did not run: the saved OAuth session had
  expired and could not be refreshed. Local checks do not replace that review.
- Both physical acceptance devices were on the same home network. No outside-network success is
  claimed. Automatic gateway mapping remained unavailable on the stationary peer.
- No router settings, membership, private keys, or startup roles were changed for these fixes.
- The no-helper, two-device WAN recovery work and real roaming acceptance remain incomplete.
- Physical Linux acceptance and production update-authority provisioning remain separate gates.

No release was published by this validation work.
