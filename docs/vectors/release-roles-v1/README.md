# Release-role provider vectors

**DRAFT - NOT FROZEN.** `manifest.json` lists SHA-256 and the expected acceptance or
refusal for each file. The bundle joins ADR 0007 release and code-signing role grants,
their root-signed steps, ADR 0005 shared status, a carried-device owner assertion,
and carried and unattended release statements. It replaces the earlier
statement-only draft vectors.

The 121-file manifest includes two aggregate pre-parse length refusals: 16,385
bytes for a statement and 262,145 bytes for an authority bundle. ADR 0007
labels these necessarily multi-fault because every otherwise valid nested
record stays below the aggregate ceiling. Verifiers reject them on length
before decoding their contents.

The records use public disposable test scalars. The normal certificate uses a
code-signing key distinct from the release key. Its reviewed public DER is
pinned because ECDSA certificate signatures can vary on reissuance. A separate
pinned 4,096-byte certificate exercises the size edge. A `hardware`
custody label in these records is **not** a physical hardware proof. The example
consumer is `org.agenxy.Remap`, whose preview version is
`0.3.0-preview.4` (`[0, 3, 0, ["preview", 4]]`). The example default install
channel is `stable`; the unattended role is restricted to `preview`.

From the repository root, regenerate deliberately with:

```sh
cargo test --locked --package supgang-core generate_release_role_vectors -- --ignored
```

The normal suite checks every listed hash, parses accepted `.cbor` records as
one complete item with an independent structural reader, verifies the signatures
and bindings, and checks the named encoding and policy refusals. The carried
`release-request.bin` is the exact canonical content bytes; the assertion signs
their domain-separated request hash. `artifact.bin` supplies bytes for the
artifact-digest check. A consumer must independently
verify the pinned root chain and status, its own opt-in and default channels,
persisted version high-water, the complete owner assertion and signing-host nonce, and the
actual artifact bytes. This provider bundle establishes none of those runtime
or physical acceptance claims.

Contextual refusal pairs use the pinned values in `manifest.json`: the
`refuse-fewer-than-threshold-grant.cbor` pairs with
`refuse-fewer-than-threshold-statement.cbor`, which carries one signature for
the active three-signer role; the `refuse-reused-role-id-step` follows
the six accepted steps and repeats the release role ID; and
`refuse-stale-status.cbor` is checked at `verification_time` with a 600-second
maximum age. The stale-issuer step has a valid root signature over canonical
CBOR but is refused because its payload names a different predecessor.
The assertion-at-statement-expiry vector uses the separately root-issued
owner grant and is checked at the manifest verification time, where both the
statement and owner grant are otherwise live.
