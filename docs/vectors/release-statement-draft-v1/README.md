# Draft release-statement wire vectors

**DRAFT - NOT FROZEN.** These bytes illustrate ADR 0007's current proposed
content and signed-statement layout. `manifest.json` records each file's size
and SHA-256 for local integrity checks. The hashes are not stable consumer pins.

The role and carried-device signing scalars used to regenerate these records
are fixed public test inputs. The valid statement has two role signatures and
an ADR 0005 assertion bound to its statement digest. The negative records
cover a bad role signature, changed statement digest, a valid carried signature
bound to a different digest, and an uppercase channel.

The vectors exercise only the statement codec, role-signature checks, and
partial assertion binding. They do **not** contain or prove a root role grant,
current status, challenge, target, nonce spend, artifact bytes, native package
signature, version high-water mark, or physical custody. A consumer must check
all of those separately before accepting any release.

Regenerate from the repository root with:

```sh
cargo test --locked --package supgang-core generate_release_statement_vectors -- --ignored
```

The normal test suite checks every manifest-listed byte count and SHA-256,
then verifies the valid and negative vectors. Do not vendor these files as
frozen conformance fixtures until the owner has settled ADR 0005 and ADR 0007,
the role grant codec and independent consumer verifier exist, and the physical
acceptance gates have passed.
