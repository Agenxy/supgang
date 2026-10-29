# Release-role provider vectors

**DRAFT - NOT FROZEN.** `manifest.json` lists SHA-256 and the expected acceptance or
refusal for each file. The bundle joins ADR 0007 release and code-signing role grants,
their root-signed steps, ADR 0005 shared status, a carried-device owner assertion,
and carried and unattended release statements. It replaces the earlier
statement-only draft vectors.

The records use public disposable test scalars. The certificate is a pinned
public fixture; regenerating the other files reuses that DER file. A `hardware`
custody label in these records is **not** a physical hardware proof. The example
consumer is `org.agenxy.Remap`, whose preview version is
`0.3.0-preview.4` (`[0, 3, 0, ["preview", 4]]`). The example default install
channel is `stable`; the unattended role is restricted to `preview`.

From the repository root, regenerate deliberately with:

```sh
cargo test --locked --package supgang-core generate_release_role_vectors -- --ignored
```

The normal suite checks every listed hash, parses each `.cbor` record as one
complete item with an independent structural reader, verifies the signatures
and bindings, and checks the named refusals. A consumer must independently
verify the pinned root chain and status, its own opt-in and default channels,
persisted version high-water, the complete owner assertion and nonce, and the
actual artifact bytes. This provider bundle establishes none of those runtime
or physical acceptance claims.
