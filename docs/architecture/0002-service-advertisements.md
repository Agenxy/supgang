# ADR 0002: Signed service advertisements

Status: accepted, implemented

Date: 2026-09-13

## Decision

A member may advertise, in its own endpoint record, a bounded list of local
services other Agenxy software on the same computer offers: a short service
name, the TCP or UDP port it listens on, and a 32-byte pin of the TLS key that
service presents. The list is device-signed with the rest of the record, is
published and reconciled exactly as candidates are, and is returned by
`supgang peers`, `supgang resolve`, and the MCP `resolve` tool beside the
addresses.

Supgang does not connect to, proxy, or verify those services. It carries a
signed statement, made by the computer that runs them, of where they are and
what key they hold. A consumer that dials a peer's address on an advertised
port and finds the advertised key has exactly the assurance Supgang gives about
the peer's own transport: the hive root authorised this device, and this device
signed this claim.

## Why

Dibs, the Agenxy coordination board, is the first consumer. A Dibs hub on a
member serves HTTPS with a certificate it generates. A second machine joining
that hub today copies a secret by hand and then pins the hub's certificate by
hand, comparing a fingerprint read from one screen against another. Supgang
already answers where the hub is (docs/architecture/0001, `resolve`) and who
it is (the node id); the one thing it does not answer is what key the hub's own
service presents, so the pinning ceremony survives as the last manual step of
joining a fleet.

The alternative, Dibs keeping its own trust exchange, is what Agenxy decided
against on 2026-09-13: the projects use each other as dependencies and
specialise rather than each growing a copy of the others' work. Identity and
addresses are Supgang's; a service's key pin is a fact about that identity's
computer and belongs in the same signed register.

## What changes

- `EndpointRecord` gains `services: Vec<ServiceAdvert>` under a new protocol
  version and signature domain (`supgang/endpoint-record/v3\0`), the way v2
  added `display_name`. v1 and v2 records keep verifying under their own
  domains; a v3 decoder reads all three, and a v2 decoder rejects v3 as an
  unsupported version, which is the existing downgrade boundary. A member
  that advertises nothing keeps signing v2 records, so upgrading Supgang
  changes nothing a member that has not upgraded can see. A member that
  advertises signs v3, which a member that has not upgraded rejects whole,
  addresses included: advertising is the step that requires the fleet to
  have upgraded, and `advertise` says so.
- `ServiceAdvert { name: ServiceName, port: u16, key_pin: [u8; 32] }`.
  `ServiceName` is 1 to 16 bytes of lowercase ASCII letters, digits and
  hyphens, not starting with a hyphen. At most 4 advertisements per record,
  strictly sorted by name, no duplicates. Encoded as a fixed 3-element CBOR
  array each; 4 of them add at most 4 × (1 + 17 + 3 + 34) = 220 bytes to a
  record whose budget is 3 584, which the existing bound absorbs.
- The advertisements live in the owner-only profile beside the display name
  (`profile.json`, bounded to 1 024 bytes rather than 256, the pin written as
  hex) and are read into the record the way the name is: by the service when it
  starts, and by `publish` when it signs a contact. A change advances the
  endpoint sequence on the next signing and needs no re-enrolment. As with
  `name set`, the verbs refuse while the service is running, because a profile
  that says one thing while the fleet is told another is the drift both verbs
  exist to prevent; a live control request to re-sign is a later refinement.
- What a record claims beyond identity and time, its candidates, capabilities
  and services, is one value, `EndpointClaims`, so signing takes a claim and
  not a growing list of arguments.
- CLI: `supgang advertise NAME PORT --key-pin HEX` adds or replaces one
  advertisement, `supgang unadvertise NAME` removes one (both answer
  `supgang.services/v1`), `supgang peers` and `supgang resolve` print
  `services` per peer in both text (`runs dibs on port 4777`) and JSON
  (`supgang.peers/v6`, `supgang.resolve/v5`, each row `{name, port,
  key_pin}` with the pin as 64 hex digits), and the MCP `resolve` and `fleet`
  tools return the same field. Both verbs are owner-only local operations with
  the same authentication as `name`.
- Merge is unchanged: services are part of the signed record and win or lose
  with it by generation and sequence.

## Invariants and threats

- A service advertisement is a claim by the device that signed it, bounded in
  count and size, never an observation. It confers no authorisation: a
  consumer decides for itself whether to dial, and Supgang's own transport pin
  (`transport_key_id`) is untouched.
- No advertisement carries an address: the peer's addresses are the record's
  candidates, and a service is reachable on those, on its port. An
  advertisement naming a different address would be a way to point a consumer
  at a third party under a member's signature.
- Unknown service names are carried and printed; nothing in Supgang acts on a
  name. Consumers match names they know.
- A revoked device's advertisements go with its record.
- No secret or key material is in an advertisement: a pin is the hash of a
  public key. Which hash of which bytes is the consumer's convention to state;
  Supgang carries 32 bytes. Dibs pins the SHA-256 of its board CA's
  SubjectPublicKeyInfo, the RFC 7469 form.

## Consequences

A Dibs hub tells its operator, through `dibs doctor` and `dibs fingerprint`,
the exact `supgang advertise dibs <port> --key-pin <pin>` for the key it
serves, and a joining machine reads the pin from `supgang resolve` and checks
the certificate it is offered against it, so `dibs mcp-config --board <peer>`
becomes the whole join and a mismatch is a refusal rather than a fingerprint a
person did not compare. Other Agenxy services on a member can do the same with
their own names.
