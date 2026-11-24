# supgang-netwatch 0.20.2 (vendored from netwatch 0.20.2)

The source files in this directory are the published `netwatch-0.20.2.crate`
archive (excluding Cargo's generated packaging metadata `.cargo_vcs_info.json`,
`Cargo.lock`, and `Cargo.toml.orig`), republished under the Supgang-owned
package name `supgang-netwatch` with upstream `MIT OR Apache-2.0` licensing
and attribution preserved.

Manifest diff from published `netwatch-0.20.2.crate`:

```diff
-name = "netwatch"
+name = "supgang-netwatch"
 version = "0.20.2"
+publish = ["crates-io"]

-[target.'cfg(target_os = "windows")'.dependencies.chrono]
-version = "0.4.23"
-
 [target.'cfg(target_os = "windows")'.dependencies.wmi]
 version = "0.18"
+default-features = false
```

The default `wmi` feature and transitive `chrono` entry pull in `chrono`, which
is unmaintained under RUSTSEC-2026-0543. `netwatch` uses `WMIConnection` and
`FilterValue`; it does not use `chrono` or WMI date/time conversion. Publishing
this copy directly as `supgang-netwatch` (depended on by `supgang-portmapper`
via package rename) avoids `[patch.crates-io]`, which Cargo does not carry into
published crates.

`netwatch` 0.20.2 already uses `netlink-packet-core` 0.9.0, which removes the
archived `paste` dependency (RUSTSEC-2024-0436) without vendoring netlink
crates.

- Upstream package: `netwatch` `0.20.2`
- Published archive SHA-256: `2acf7a1ca9205d7c1fc9a1595193a8cbaa7537b4a07dca93c6ae3de7c8d0e597`
- Upstream commit recorded by the archive: `334793cfdaf3487db0c721b9312179a8ae3b0dcb`
- `LICENSE-APACHE` from that commit SHA-256: `7986218ec4ea89de3511a843ae27fea2584a525036c220ff7b26589179f07888`
- `LICENSE-MIT` from that commit SHA-256: `33616ec4c88b6e00de66e6c06f1a55d80bb32a9d7939f3aa83d28e673a1adcae`

The published crate omits the two license files referenced by its README. They
are included here from the recorded upstream commit. The repository policy gate
verifies the archive hash, every archived source file, the exact manifest diff,
and both license files offline from the local Cargo registry cache. If absent,
fetch and verify the exact archive with:

```text
mkdir -p "${CARGO_HOME:-$HOME/.cargo}/registry/cache/index.crates.io-1949cf8c6b5b557f"
curl --fail --location --show-error --silent \
  https://static.crates.io/crates/netwatch/netwatch-0.20.2.crate \
  --output "${CARGO_HOME:-$HOME/.cargo}/registry/cache/index.crates.io-1949cf8c6b5b557f/netwatch-0.20.2.crate"
printf '%s  %s\n' \
  2acf7a1ca9205d7c1fc9a1595193a8cbaa7537b4a07dca93c6ae3de7c8d0e597 \
  "${CARGO_HOME:-$HOME/.cargo}/registry/cache/index.crates.io-1949cf8c6b5b557f/netwatch-0.20.2.crate" | shasum -a 256 -c -
```
