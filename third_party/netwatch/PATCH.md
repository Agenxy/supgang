# netwatch 0.19.1 source patch

The source files in this directory are the published `netwatch-0.19.1.crate`
archive, with one manifest change:

```diff
 [target.'cfg(target_os = "windows")'.dependencies.wmi]
 version = "0.18"
+default-features = false
```

The default `wmi` feature pulls in `chrono`, which is unmaintained under
RUSTSEC-2026-0543. netwatch uses `WMIConnection` and `FilterValue`; it does not
use WMI date/time conversion. Remove this local patch when an upstream netwatch
release disables `wmi` default features and passes the full Supgang gate.

- Published archive SHA-256: `4d9cbe01741347ef750d743d6690603f5eed8341e679fb51c8e629337aa11976`
- Upstream commit recorded by the archive: `051ab8761006d7f2155e34a49f6bb881b582d5ab`
- `LICENSE-APACHE` from that commit SHA-256: `7986218ec4ea89de3511a843ae27fea2584a525036c220ff7b26589179f07888`
- `LICENSE-MIT` from that commit SHA-256: `33616ec4c88b6e00de66e6c06f1a55d80bb32a9d7939f3aa83d28e673a1adcae`

The published crate omits the two license files referenced by its README.
They are included here from the recorded upstream commit. The repository
policy gate verifies the archive hash, every archived file, the single manifest
change, and the two added license files. It reads a local Cargo registry cache
archive and makes no network request. If absent, fetch the exact archive with:

```sh
mkdir -p "${CARGO_HOME:-$HOME/.cargo}/registry/cache/index.crates.io-1949cf8c6b5b557f"
curl --fail --location --show-error --silent \
  https://static.crates.io/crates/netwatch/netwatch-0.19.1.crate \
  --output "${CARGO_HOME:-$HOME/.cargo}/registry/cache/index.crates.io-1949cf8c6b5b557f/netwatch-0.19.1.crate"
printf '%s  %s\n' \
  4d9cbe01741347ef750d743d6690603f5eed8341e679fb51c8e629337aa11976 \
  "${CARGO_HOME:-$HOME/.cargo}/registry/cache/index.crates.io-1949cf8c6b5b557f/netwatch-0.19.1.crate" | shasum -a 256 -c -
```

Cargo omits the registry checksum from `Cargo.lock` when the path patch replaces
the registry package. This archive hash is the checksum from the unpatched
`Cargo.lock` on `main` at `04000f70aa92d50829d48736ddfba01bb958b510`.

The patch applies to source-built Supgang binaries in this workspace. Cargo
does not include a workspace path patch in the crates it packages for
crates.io: package verification currently resolves registry netwatch 0.19.3,
which still enables WMI's default `chrono` feature on Windows. A public crate
release must be blocked until its rehearsed package dependencies are checked
for all targets and an upstream or distribution fix removes that path.
