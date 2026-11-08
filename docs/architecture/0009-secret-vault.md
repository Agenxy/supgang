# ADR 0009: A secret vault sealed to each Mac's Secure Enclave

Status: Accepted. The owner asked for it on 6 Nov 2026 and approved building it on 8 Nov. Slice 1
(below) is implemented; later slices are not.

Date: 2026-11-08

## Problem

The owner keeps tokens in iCloud Keychain. Agents and Agenxy tools that need them trigger a
keychain prompt each time, because macOS binds an item's access list to the code signature of the
program that created it. Agents run as interpreters and rebuilt binaries, so every one of them
looks new to macOS. The owner's direction: Supgang should hold these tokens, so that agents and
the appropriate tools have them without asking him.

## Decision

Supgang keeps a per-computer vault, `vault.cbor`, in its protected state directory.

- **Key.** One P-256 key-agreement key, created in the Secure Enclave by the existing
  `supgang-secure-enclave` helper, using CryptoKit's sealed-blob API.
  - No keychain item, entitlement or developer account is involved.
  - `AfterFirstUnlockThisDeviceOnly`, with no presence requirement, so a granted secret is
    readable without a prompt and the key never syncs.
  - Only the helper's restore record is stored, and only this Mac's enclave can use it.
- **Sealing.** Each secret is encrypted as follows:
  1. A fresh ephemeral P-256 key, made in Rust, is combined with the vault key by ECDH.
  2. HKDF-SHA-256 derives the secret's key from that shared secret. It is salted with the
     ephemeral and vault public keys, and its info is `supgang/vault-entry/v1\0` followed by
     the name.
  3. ChaCha20-Poly1305 encrypts the secret. The associated data is the domain, the name, NUL,
     the ephemeral key, the storage time (big-endian) and the note, so an edit to any of them
     fails.

  Adding a secret needs only the public key. Reading one needs the enclave. A ciphertext moved
  to another name, a flipped byte, a non-canonical file or trailing data all fail closed.
- **Use without disclosure.** `supgang vault run --env GH_TOKEN=github -- gh …` replaces itself
  with the program, carrying the secret in its environment. The secret never enters argv, a URL,
  terminal output or Supgang's output. `vault get` exists for programs that read a pipe, and
  refuses a terminal.
- **Import.**
  - `vault add NAME` reads stdin, and only one trailing line ending is removed. At a terminal it
    reads raw bytes with echo, line editing and terminal signals off, and restores them on every
    exit. Canonical mode would cut a pasted line at about 1 KiB. Ctrl-C or Ctrl-D cancels and
    Backspace edits.
  - `--from-keychain SERVICE [--account A]` copies one login-keychain password through
    `/usr/bin/security`. The owner approves that copy once, within two minutes, or the lookup is
    killed. After that, agents ask Supgang instead of the keychain.
- **Record.** Every add, replace, removal, read and refused read is appended to the owner-only
  `vault-audit.log`. Each line holds the time, operation, name and the consuming program's file
  name, never a value.
  - A read is recorded before the secret is released. If that record fails, nothing is released.
  - Changes are recorded after they are saved.
  - Appends and truncation hold `vault-audit.lock`.
  - At 256 KiB the log keeps the newest half.
- **Bounds.**
  - At most 128 secrets of 1 to 8,192 bytes each.
  - Names match `[a-z0-9][a-z0-9._-]{0,63}`. Notes are at most 200 bytes of printable text.
  - At most 16 `--env` secrets per program.
  - One flock-held writer at a time. Each helper call has a deadline.
- **No fallback.** A Mac without the helper or the hardware gets a refusal that says so. Other
  platforms are refused. No file-held key is substituted.

## The boundary, stated plainly

Any program running as the owner's macOS user can ask the vault for any secret. The control
socket, the state directory and the enclave key all admit exactly that user, and an agent is
indistinguishable from the owner's own shell at that layer. The vault therefore:

- removes the prompts;
- keeps secrets off disk in clear, out of iCloud and off every other computer;
- keeps them out of transcripts and logs, by preferring `run` over printing;
- records every use.

It does **not** stop one of the owner's programs from reading a secret another was meant to
have. An agent misled by text it read could ask for a token. The defence is to keep anything
that moves money, unlocks recovery or controls identity out of the vault. Slice 4 below is the
one that adds a real boundary between programs.

## Later slices (not built)

1. **Scoped use.**
   - A git credential helper that answers only for the host bound to a secret.
   - Per-secret host binding.
   - Hash-chained audit entries, with the head carried in this computer's signed record.
2. **Fleet sealing.**
   - Publish each member's vault public key in its device-signed record.
   - `vault share NAME --with PEER` seals a copy to that peer's enclave key and carries it in
     hive sync.
   - A revoked member's copies are refused at the next sync, and the owner rotates the token.
   - No iCloud and no server.
3. **Presence-held secrets.** A second agreement key with `userPresence` for secrets the owner
   wants to approve each time with Touch ID.
4. **Program identity.** Once ADR 0007 gives Supgang a stable Developer ID signature:
   - the vault key moves into a keychain access group that only the signed Supgang can use;
   - reads go through the running service;
   - the service grants a secret per consumer, checking the caller's code signature from the
     socket's audit token.

   Callers without a stable signature, such as interpreters, keep only owner-scoped grants, and
   the grant says so.

## Consequences

- `make install` now builds the helper and installs it beside `supgang`, signing it when
  `MACOS_CODESIGN_IDENTITY` is given. A bare `cargo install` has no helper, so `vault` reports
  that the helper is missing.
- The service needs no change. The vault is a local command, so no restart, protocol change or
  fleet rollout is involved.
- New dependencies are RustCrypto's `hkdf` 0.13 and `chacha20poly1305` 0.11 (MIT or Apache-2.0),
  plus `p256`'s `ecdh` feature and `rustix`'s `termios` feature for hidden input.
