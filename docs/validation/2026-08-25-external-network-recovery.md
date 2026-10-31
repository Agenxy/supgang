# External-network reverse-recovery validation

Date: 2026-08-25  
Build: `0.2.0-alpha.9` corrective source  
Status: authenticated WAN path observed; persistent same-build acceptance pending

This run moved Laptop A to a network with no direct route to Home B's private address. It tested the
installed background service and a previously remembered mapped UDP endpoint. Machine names,
addresses, account names, and hive identifiers are intentionally omitted because this is a public
project record.

## Validation rubric

- [x] Laptop A used an external default gateway and had no direct home-LAN route.
- [x] The installed command and protected background-service executable were byte-identical.
- [x] A fresh daemon sent and received traffic through the remembered public UDP path.
- [x] Home B authenticated strongly enough to produce a peer-confirmed public observation for
  Laptop A; a saved address alone cannot produce that state.
- [ ] The authenticated peer remained active across multiple status samples.
- [ ] Both physical peers ran the same corrected artifact.

## Finding

Supgang deliberately gives one node-ID direction priority and lets the other direction probe once
per four retry rounds. The probing endpoint retained a successfully authenticated secondary-path
connection as a fallback. The receiving endpoint classified that same physical connection as
unusable because its local origin was inbound, then closed it. Live status therefore progressed
from no Internet evidence to a peer-confirmed public address while still reporting zero active
peers.

This was an availability defect, not an authentication bypass: certificate pinning, hive
membership, device proofs, and the authenticated public observation all completed before the
receiver's connection-selection policy closed the transport.

## Correction

Both endpoints now derive the same classification from node ordering and connection origin:

- the preferred direction is retained as preferred at both ends;
- the reverse direction is retained as fallback at both ends; and
- a later preferred connection replaces an existing fallback deterministically.

Two regressions cover the correction. One checks the classification from both endpoints. The other
creates a real two-ended QUIC connection in the reverse direction and verifies that both registries
retain it without either transport closing.

The complete repository gate passed after the correction: formatting, locked builds, Clippy with
warnings denied, 153 tests, documentation, and repository policy.

## Remaining proof gap

Laptop A now runs the corrected protected artifact. Home B still runs the earlier artifact and
continues to close the authenticated reverse-direction connection. Supgang intentionally has no
remote-execution or forced-update channel, so Home B cannot be safely upgraded through Supgang from
this external network. The next acceptance run must:

1. install the exact same corrected artifact on Home B through an authorized management path;
2. verify LAN authentication and identical artifact hashes;
3. move Laptop A back to an external network with no home route; and
4. require a persistent authenticated peer across several retry and reconciliation intervals.

This run validates the remembered public path and the authentication boundary. It does not yet
validate persistent same-build WAN recovery or zero-configuration gateway mapping.
