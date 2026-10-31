# Shared Cargo cache maintenance

`make check`, `make test`, and `make install` select a Cargo output directory under
`~/.cache/agenxy/cargo-targets/supgang`. The directory name includes the actual pinned compiler binary,
host target, profile, and relevant compiler flags. Compatible Supgang worktrees can share compiled
dependencies. A separately selected `CARGO_TARGET_DIR` is respected. The wrapper may use an
already-installed sccache 0.18.0; it does not install a cache server or change a global selector.
Rust 1.98.1 in the cross-project proposal remains a candidate, not a Supgang pin change.

The local `make check` gate prints one `quality-cache` hit or miss for every stage and workspace
package. It hashes source content, `Cargo.lock`, selected tools, the compiler binary, and build
environment, then reuses a passing result for at most 24 hours. Changed package inputs rerun that
package and its local dependents; common inputs rerun all packages. Repository policy always runs.
CI and release validation set `SUPGANG_QUALITY_CACHE=off` to execute every stage. A cached local
pass is not installed-artifact, physical-peer, or release proof.

`make cache-sweep` is a dry run. `uv run --offline --script tools/cache_sweep.py --apply` deletes
up to two complete, idle, lock-protected lanes whose last wrapper use was at least 30 days ago.
The sweep is bounded to 200,000 entries and 200 GiB and refuses symlinks or special files. An
active build holds a shared lock, which prevents its lane from being selected. The sweep does not
touch a repository's `target/` directory or installed binaries.

[`org.agenxy.supgang-cache-sweep.plist.example`](../../platforms/macos/org.agenxy.supgang-cache-sweep.plist.example)
is a weekly macOS schedule template. Its two absolute paths must be filled with the selected `uv`
executable and this repository's sweep script. Installing or enabling that schedule is a separate
owner action; the repository does not install or activate it.
