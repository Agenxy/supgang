# Supgang Secure Enclave helper

This optional SwiftPM executable uses CryptoKit's sealed-blob API. It never
stores a keychain item and needs no entitlement, provisioning profile or
developer account. `SecAccessControl` describes the key's access policy;
using that type does not put the key in the keychain.

Build Supgang with Cargo first, then explicitly build and place the helper:

```text
uv run --offline --script platforms/macos/build.py --beside target/debug/supgang
```

For an installed binary, pass its absolute path after `--beside`. The
destination is always named `supgang-secure-enclave`. Build products and
caches stay under `target/supgang-macos`. The manifest uses Swift 6 language
mode and treats compiler warnings as errors. Release builds omit debug
information, like Supgang's stripped release binary. A machine without Swift
can still build and test the Rust workspace; a missing sibling is reported
as `HelperMissing`. The build tool reports `ToolchainMissing` separately.

There is one request per process, supplied on stdin and terminated by LF and
EOF. The helper takes no arguments. Every response is one ASCII line and LF.
The wire limit is 16384 bytes, and a sealed payload is at most 4096 bytes.
These are protocol lines, not shell commands:

```text
supgang/custody/v1 probe
supgang/custody/v1 generate --presence
supgang/custody/v1 generate --no-presence
supgang/custody/v1 public --sealed <blob-hex>
supgang/custody/v1 sign --sealed <blob-hex> <32-byte-digest-hex>
```

Success responses start with `supgang/custody/v1 ok` followed by:

| Operation | Body |
| --- | --- |
| probe | `probe supgang-secure-enclave ready` or `probe supgang-secure-enclave no-hardware` |
| generate | `generate <blob-hex> <compressed-public-key-hex>` |
| public | `public <compressed-public-key-hex>` |
| sign | `sign <raw-signature-hex>` |

Errors start with `supgang/custody/v1 error`, then `no-hardware`,
`owner-declined-presence`, `protocol`, or `refused <signed-integer>`.
Native error descriptions never cross the pipe. Rust also distinguishes
missing executable, process refusal, malformed response, busy and timeout.
The helper's protocol response uses a successful process exit even for
typed errors; a failing process status is a separate helper refusal.

Hex is lowercase and even-length. Public keys are 33-byte compressed SEC1;
signatures are 64-byte raw `r || s`. Rust, exclusively, normalizes `s` to the
low half before constructing a `DeviceSignature`, then verifies the returned
signature against the restored public key and the requested message. The
Swift digest overload signs the supplied SHA-256 digest without hashing it
again. Presence keys use `[.privateKeyUsage, .userPresence]` with a fresh
authentication context and no Touch ID reuse interval.

Rust enforces the deadline, kills and reaps a hanging child, and accepts only
one in-flight helper operation. The standalone helper expects its pipe caller
to enforce that deadline. It performs no networking or persistent writes.

The two ignored Rust tests require this helper beside the **test executable**
under `target/debug/deps`, not just beside `target/debug/supgang`. Build that
test executable with `cargo test --locked -p supgang-core --lib --no-run`, pass
its path to the build tool, then run the exact ignored test. The presence
variant also requires the owner at the Mac:

```text
cargo test --locked -p supgang-core device_key::secure_enclave::tests::real_helper_restores_and_signs -- --ignored --exact
cargo test --locked -p supgang-core device_key::secure_enclave::tests::real_helper_requires_presence -- --ignored --exact
```

Framing and refusal checks can run without hardware and create no keys:

```text
uv run --offline --script platforms/macos/test_protocol.py --helper target/debug/supgang-secure-enclave
```

The helper is a custody primitive. It does not show or authorize a typed
authority transaction. ADR 0003 records that remaining policy requirement;
it must be met before live authority integration. Existing service-copy and
update-slot installers carry only Supgang today. They do not distribute this
optional sibling automatically; those contexts report `HelperMissing` until
the helper is installed beside the executable they actually run.
