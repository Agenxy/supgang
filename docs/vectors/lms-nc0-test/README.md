# Public LMS test vectors

These are deterministic **public TEST data only**, never product or tapeout keys or signatures.
They were supplied by Agenxy procurement for the Supgang LMS cross-check (Dibs request
486565, source packet stage1-485433/public-TEST-LMS). The supplier extracted each 32-byte
message as SHA-256 of a generated test NC0 package's v2 header and payload, and each
9,164-byte signature as that package's suffix. This extraction did not sign again or
recompute the public roots. The original generator SHA-256 recorded by the supplier is
`9ac2c40604f14bbaa4982175493f5e434e665279606b293192c7de95d756227c`.

`TEST-LMS-vectors.json` SHA-256:
`fba4405192284d62c8ef9fffd6753551b4b64ae7658a7bba10291d3fa8faa50f`.
The manifest names all 22 public binary fixtures and records their individual hashes.
The primary and recovery public-key SHA-256 values are respectively
`ed7c8940fd4032e096021e21cfc2ec86365e7db67a6c6e509a3907d0d96442d4` and
`5edbd2d510e5523dce92f9a5b19791817f7ab0bac53f7363d4f3b92ffd29f322`.

The Rust regression test runs Supgang's fixed H20/W1 verifier on all ten raw
message/signature pairs. Acceptance requires its computed candidate root to equal the
fixed public key's bytes 24..56. The expected result is eight acceptances and two
rejections. The separate C host-package harness remains an independent acceptance item.
