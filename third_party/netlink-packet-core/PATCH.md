This is netlink-packet-core 0.8.2, redistributed under its MIT licence.
Supgang vendors it because the upstream 0.8 series depends on the archived
`paste` procedural macro (RUSTSEC-2024-0436). The only source change is the
Cargo dependency alias `paste = { package = "pastey", version = "=0.2.3" }`;
the `paste!` macro and public re-export retain their names. The upstream
package source is available at https://crates.io/crates/netlink-packet-core/0.8.2.

- Published archive SHA-256: `b897d7bd4f0af82e68d40d0344cf37e97f9c97ddf74a098de3e4da05e96ca395`
- `LICENSE-MIT` is included unchanged from that archive.

The repository quality gate verifies the pinned archive hash, every archived
file, and exactly the two manifest dependency edits. It requires the archive
in the local Cargo registry cache and makes no network request. CI fetches
and hashes that archive before running the gate. Public crate packaging must
still be checked because path patches are not carried into packaged crates.
