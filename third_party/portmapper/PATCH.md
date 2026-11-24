# supgang-portmapper 0.20.2 (vendored from portmapper 0.20.2)

The source files in this directory are the published `portmapper-0.20.2.crate`
archive (excluding Cargo's generated packaging metadata `.cargo_vcs_info.json`,
`Cargo.lock`, and `Cargo.toml.orig`), republished under the Supgang-owned
package name `supgang-portmapper` with upstream `MIT OR Apache-2.0` licensing
and attribution preserved.

Manifest diff from published `portmapper-0.20.2.crate`:

```diff
-name = "portmapper"
+name = "supgang-portmapper"
 version = "0.20.2"
+publish = ["crates-io"]

 [dependencies.netwatch]
-version = "0.20.2"
+package = "supgang-netwatch"
+version = "=0.20.2"
+path = "../netwatch"
```

Cargo does not carry workspace `[patch.crates-io]` overrides into crates
published to crates.io. Because `supgang-core` reaches `netwatch` through
`portmapper`, republishing `portmapper` as `supgang-portmapper` depending
directly on `supgang-netwatch` removes `[patch.crates-io]` completely and
ensures packaged crates resolve cleanly across every supported target without
pulling upstream `netwatch` or `chrono`.

- Upstream package: `portmapper` `0.20.2`
- Published archive SHA-256: `d36ce759df600731dd2511cd2d640bd551086b2f7b68bceb9bbcfd8c7ff86053`
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
  https://static.crates.io/crates/portmapper/portmapper-0.20.2.crate \
  --output "${CARGO_HOME:-$HOME/.cargo}/registry/cache/index.crates.io-1949cf8c6b5b557f/portmapper-0.20.2.crate"
printf '%s  %s\n' \
  d36ce759df600731dd2511cd2d640bd551086b2f7b68bceb9bbcfd8c7ff86053 \
  "${CARGO_HOME:-$HOME/.cargo}/registry/cache/index.crates.io-1949cf8c6b5b557f/portmapper-0.20.2.crate" | shasum -a 256 -c -
```
