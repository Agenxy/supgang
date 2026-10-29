# ADR 0008: Scoped guest credentials for untrusted hosts

Status: Proposed. The owner decided the approval model on 28 Oct (below). K7's remaining
requirements are open with gpt-k7-3. No protocol or API in this ADR is implemented.

Date: 2026-10-28

## Direction and boundary

The owner's direction for K7, relayed on 28 Oct 2026 by K7's integrator (K7 epic
kassettes/kassette#2215, W5) and paraphrased by them:

- Untrusted hosts on other networks join K7's fleet so that build capacity scales for every
  Agenxy project.
- Each such host runs an isolated K7 instance and is cut off from the fleet except through
  authenticated, end-to-end encrypted tunnels.
- Supgang manages the security side: device identity, key custody, trust, enrolment and
  revocation.
- An untrusted host must not become a full hive member.

Membership today means "one of the owner's own computers":

- members exchange signed records and addresses;
- they gossip revocations;
- they deliver updates;
- an exposure admits every authenticated, unrevoked member (0003-opt-in-service-tunnels.md).

None of that may reach a host the owner does not control. This ADR adds a second principal, the
**guest**, with its own credential, its own admission path and nothing else.

What this ADR does not change:

- Membership, its enrolment and its trust scope.
- A guest can never be promoted to a member. Membership keeps its own in-person enrolment.
- K7 isolates the guest's workload in its own VM or kassette. K7's mutual TLS with its own pins
  runs unchanged inside the tunnel (ADR 0006, invariant 2). Supgang supplies identity,
  admission and transport only.
- No tool may require Supgang (agenxy-installation.md). K7's own enrolment path stays its
  default, and the Supgang guest path is opt-in.

## Threat model

Assume the guest host is hostile from the moment it is enrolled. Its operator can:

- read its key;
- copy the key elsewhere;
- run modified Supgang code;
- send anything over its tunnel.

A custody label from a guest therefore carries no weight, and is recorded as `untrusted`.
Every bound below must hold with the guest's key in an attacker's hands. Damage is limited to:

- the guest's own scope, on the named sponsor and services;
- until its expiry or revocation, whichever comes first;
- at the bounded rate and volume of its admission class.

## Authority: an issuer role and a configured policy

The owner, 28 Oct 2026, on how guests are approved:

> the point is that it shouldnt be blocked by my intervention, and supgang should provide the
> authority, the policies are config settings

So the owner approves no individual guest. Two layers make that bounded.

**The guest-issuer role.** The root grants it once, in person or through an ADR 0005
carried-device approval. It is a typed root operation in the same family as ADR 0005's
owner-action grants and ADR 0007's roles, and it shares their field order, `issuer_head`,
never-reused identity and monotonic revocation. It names:

- the `consumer_id`;
- one issuer key, held in hardware (package 8) on one sponsor member;
- the sponsors the issuer may name;
- ceilings: the services a guest may be given, the maximum guest lifetime, guests per day,
  concurrent guests per sponsor, and streams per guest;
- a lifetime of at most 366 days.

Revoking the issuer role, or its sponsor's membership, ends every guest it issued.

**The issuer policy.** These are owner configuration settings on the issuing sponsor
(`supgang config`). Each setting may only narrow the role's ceilings, never widen them. A
setting above its ceiling is refused when written and again when used. Changing a setting
needs no ceremony. It applies to new issuance at once, and lowering a ceiling also ends any
existing guest that the new ceiling would not have admitted.

**Issuance is automatic.** The consumer, here K7's coordinator on the sponsor, passes Supgang a
guest's request over the same-user local control socket. Supgang issues a guest grant if the
request is within policy and refuses it otherwise, with no prompt. Consequence, stated: any
same-user process on the issuing sponsor can obtain guest grants, but only within the policy:
only the configured services, for the configured lifetime, up to the daily count. The issuer
key's hardware custody means the power cannot be copied off the sponsor.

## The guest grant

A guest grant is signed by the issuer key under domain `supgang/guest-grant/v1`. It is not a
root step.

| Field | Meaning |
| --- | --- |
| `hive_id`, `grant_id` | Exact hive and a random, never-reused 16-byte identity. |
| `kind` | `guest`. |
| `issuer_role_id`, `issuer_serial` | The issuer role, and a serial that only ever increases per role, kept in the issuer's rollback-resistant ledger. |
| `consumer_id` | Exact product, for example `org.agenxy.k7`; no wildcard. |
| `guest_key` | The guest's public key, generated on the guest, with a possession proof over the fields above it. Custody is always `untrusted`. |
| `sponsors` | 1 to 4 exact member `NodeId`s that may admit this guest, all within the role. A guest reaches no other member. |
| `services` | Per sponsor, a sorted set of 1 to 4 exact service names the guest may open, plus the direction (below). |
| `not_before`, `not_after` | Lifetime, within policy. |

A sponsor admits a guest only under a grant whose issuer role is unrevoked on that sponsor's
own root chain, and only within the role's ceilings. The issuer can revoke a guest without the
owner; the consumer asks for this and the issuer signs it. A sponsor can also deny a guest at
once in its own local state. That local deny only narrows access and is never synchronised as
authority.

## Admission and what a guest sees

- **Sponsors only.** A guest dials only its sponsors. It learns a sponsor's endpoint from its
  enrolment bundle. This is the one address disclosure a guest receives, and the bundle says so.
  Guests never receive endpoint records, peer lists, rendezvous hints or revocation gossip.
  Sponsors never publish guest records to members.
- **A separate admission class.** Guest handshakes have their own per-source and global quotas,
  smaller than members' quotas and never shared with them. A flood of guests cannot crowd out
  members.
- **Typed stream allowlist.** On a guest connection the sponsor accepts only guest service
  streams for the granted names. It refuses all of the following:
  - Sync;
  - Update;
  - gossip;
  - record exchange;
  - session replacement proofs;
  - member Service streams.
- **Exposure is explicit.** A guest never matches a member exposure. A service is reachable by
  guests only if the sponsor's owner exposed it to guests of that consumer, for example
  `supgang expose k7-coord 7443 --guests org.agenxy.k7`. Default deny holds for every guest.
- **Authority ends together.** Authorization covers the grant's lifetime, issuer-role and guest revocation, local
  deny, exposure removal and session loss. Any one of these cancels the guest's streams at once,
  as `SessionAuthorization` already does for members.
- **Strict mode.** Admitting guests opens no public connection that the sponsor would not
  otherwise make.

## Enrolment

The flow mirrors member enrolment but stays separate from it:

1. The guest runs `supgang guest request`. It generates its own key and a recipient-bound
   request.
2. The consumer passes the request to the issuing sponsor, which issues the grant within policy.
3. The guest installs the resulting bundle.

Nobody needs to be present at any step. The owner's presence is spent once: on granting the
issuer role, and on setting the policy.

## Open decisions

gpt-k7-3 asked for these to stay open until K7's join path is audited. Each lists a
least-privilege candidate.

| Decision | Least-privilege candidate |
| --- | --- |
| Direction | The guest opens streams to the sponsor's granted services only. The sponsor sends work back over those guest-opened streams and opens none of its own to the guest. |
| Guest-to-guest reachability | None. Two guests never connect, even if sponsored by the same member and consumer. |
| Lifetime | 24 hours or less, renewed by a fresh grant, never by the guest itself. |
| Revocation bound | The lifetime is the outer bound. The issuer's revocation and a sponsor's local deny are immediate on that sponsor. For other sponsors, an issuer-signed guest status at most 1 hour old. The issuer can sign that status unattended, so it does not wait on the root. |
| Isolation | K7's decision: VM or kassette. Supgang needs only the boundary at which the tunnel ends: a sponsor-side loopback service, and on the guest a socket reachable only by the isolated K7 instance. |
| Policy defaults | These are configuration settings (decided above). Shipped defaults: 8 guests per day, 24-hour lifetime, 4 streams per guest, 32 concurrent guests per sponsor. Each can be narrowed. |

## Acceptance before anything is advertised

- A guest on a different network, with nobody at the sponsor, enrols, opens a granted service
  and runs a K7 job through it.
- The same guest is refused each of the following:
  - a member service;
  - a service granted to another consumer;
  - another member;
  - another guest;
  - Sync, Update, gossip and record streams;
  - any request after expiry, revocation or local deny. Streams that are already open are
    cancelled.
- A member exposure is unreachable to guests. A guest exposure is reachable only by the named
  consumer's guests.
- A guest flood at the quota leaves member handshakes and sessions unaffected.
- A guest never receives the address of any computer other than its sponsors. This is checked
  on the wire and in its state directory.
- Logs and `doctor` output contain no guest or member address (AGENTS.md).

Adversarial vectors to ship as tests, one each:

- a cross-hive grant;
- a reused `grant_id`;
- a guest grant from a revoked or expired issuer role;
- a guest grant above a role ceiling, or above the configured policy;
- the daily count exceeded;
- an issuer serial replayed or rolled back;
- a policy setting written above its ceiling;
- possession bound to another grant;
- a guest key presented as a member key, and the reverse;
- a guest opening a forbidden stream type;
- a guest naming a service not in its grant;
- a guest asking a non-sponsor to admit it;
- a promotion attempt through member enrolment with the guest key;
- a revoked guest reconnecting;
- a credential replayed from a second source address while the first session is live.

## Consequences

- K7 gains a way to add hostile build capacity without widening what any member trusts.
- Supgang gains a second principal type. Every new stream type and authority check must from
  now on state how it treats guests, and the default is refusal.
- The admission path is new code reachable before full authentication, and it is reachable by
  key holders the owner does not control. It gets the same bounded-input and fuzz coverage as
  the member handshake.
