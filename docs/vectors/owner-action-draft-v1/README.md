# Draft owner-action wire vectors

**DRAFT - NOT FROZEN.** These bytes illustrate the current proposed grant,
status-policy, status, challenge, and assertion codecs. `manifest.json` records
each file's SHA-256 for local integrity checks; the hashes are not a stable
consumer pin. Remap must not vendor them as frozen conformance fixtures yet.

The root and P-256 signing scalars used to regenerate these records are fixed,
public test inputs. No production key or address appears here. `request.bin` is
opaque provider-level input, **not** a canonical Remap resolver or lifecycle
request. The `accept` expectations apply only to the Supgang envelope and
binding checks at the manifest's verification time. Remap must still apply its
own canonical request, preview, release-authenticity, high-water, and effect
checks. The negative records demonstrate wrong-case consumer identity, changed
request digest, invalid status signature, and wrong budget.

From the repository root, regenerate with:

```sh
cargo test --locked --package supgang-core generate_owner_action_vectors -- --ignored
```

The normal test suite checks every listed byte count and SHA-256 against the
manifest. The release-statement wire format and its vectors belong to a
separate stacked branch. Owner approval of the renewal limits, a durable
current-head issuer and ledgers, independent consumer verification, and
physical acceptance remain required before any vector set can be frozen.
