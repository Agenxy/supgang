# Supgang network lab on K7

This directory belongs only to Supgang's network tests. It is not a member of
K7's Forge/CI decks and does not reuse their running guests, storage, identities,
runner registration, or networks. It uses the existing K7 authority on the Mac;
it must not create a second daemon or restart that authority.

## Current implementation

`probe.spec7` is a small infrastructure probe, not a Supgang connectivity test.
It requests one disposable Linux guest on this Mac, capped at one CPU, 256 MiB
of RAM, and a 30-second workload lifetime. It inherits no environment variables,
mounts no host folders, publishes no services, forwards no SSH agent, and requests
no restart or persistent container. Its Debian ARM64 image is digest-pinned from
the official Debian container repository. Initial image acquisition can require
Internet access; the guest workload does not fetch anything. K7 must own image
acquisition and verification through its supported public API. Supgang must not
rewrite image references or operate K7's internal image store to make a run work.

The guest attempts to create private user, network, mount, and process namespaces,
then prints only the namespace's interface names/counters and user mapping. Failure
to create them must remain a failure. There are no Supgang processes or real hive
credentials in this probe. The outer K7 guest currently has ordinary NAT; do not
interpret `isolated: false`, VM isolation, or successful launch as proof of a
completed air-gapped lab. The namespace readback is an initial capability check,
not full route, egress, or failure-injection calibration.

Validate without starting a guest:

```text
k7 validate spec lab/k7/probe.spec7 --json
```

Run only through K7's public deck surface and preserve its terminal result. Never
use `--skip-preflight`, switch providers after a failure, or label a rejected job
as a passing test. A future runner must check the exact node identity, terminal
job result, workload exit code, namespace evidence, and cleanup, not merely the
outer CLI's exit status.

## Bring-up status

The first attempt on 2026-09-18 did **not** start a guest. It exposed two K7
contract defects and one missing capability:

- The CLI rejected canonical `isolation` and deck `placement` fields. A source
  repair in K7 now validates their nested fields rather than accepting arbitrary
  unknown data; local regression tests and changed-file gates pass. It is not
  yet merged or installed: [K7 PR #1542](https://github.com/kassettes/kassette/pull/1542).
- The installed Apple container provider rejects the pinned public OCI image
  reference. Its suggested `image.ensure` workflow is not exposed by the current
  CLI/agent manifest. Image preparation must be implemented in K7, not as a
  Supgang-specific loader, opaque label, or private-helper invocation. This is
  tracked at [K7 issue #947](https://github.com/kassettes/kassette/issues/947).
- The failed node appeared inside a `succeeded` job and the CLI returned zero.
  The source repair is [K7 PR #1546](https://github.com/kassettes/kassette/pull/1546):
  failed nodes fail the job, dependent nodes remain unstarted, and any running
  siblings remain visible for explicit cleanup. The repair also prevents a failed
  launch from activating deck panels/patches or recording a successful authored
  revision. Native runtime regressions and CLI failure-exit tests pass locally;
  full review, merge, installation, and public-API acceptance are still pending.
  A lab wrapper rejecting false success is not a substitute for this upstream fix.

The deck is a capability probe, not an accepted network-test environment. Do not
start Supgang peers until these source issues and packet-isolation checks pass.

## Next acceptance stages

The [architecture](../../docs/architecture/0002-network-test-lab.md) defines the
planned macOS and Linux lanes and their evidence boundaries. Real Supgang runs use
exactly two freshly paired test identities, never the owner's normal hive. The
macOS lane requires K7's private packet-attachment capability; Linux namespace
results do not stand in for it. Both lanes are on-demand and separate from all
other decks. The native macOS lane must declare its larger guest resource budget
explicitly rather than inherit the lightweight probe's budget.

No current probe result establishes outside-home connectivity, NAT behavior,
network-change recovery, or macOS guest acceptance.
