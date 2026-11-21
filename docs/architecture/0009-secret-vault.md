# ADR 0009: A secret vault sealed to each Mac's Secure Enclave

Status: Accepted. The owner asked for it on 6 Nov 2026 and approved building it on 8 Nov. Slice 1
(below), the Ed25519 signing addendum, and the SSH-agent addendum are implemented; later slices are
not.

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

## Addendum: non-exportable Ed25519 signing entries (16 Nov 2026)

`vault keygen --signing ed25519 NAME` requires terminal stdin and generates a random 32-byte seed
in process. The seed is sealed in the same vault; the public key is returned as 64 lowercase hex
characters. The fingerprint is lowercase SHA-256 hex of the raw 32-byte public key, with no prefix.
Keygen never overwrites an entry. `vault list` shows the kind and fingerprint. `vault public-key`
returns the public key and fingerprint. `vault get` and `vault run` refuse signing entries.

The vault document's canonical CBOR version 2 adds an entry kind and, for signing entries, the
public key. Version 1 secrets remain readable and retain their version 1 encryption binding when
the document is upgraded. A signing entry's kind and public key are additionally authenticated
by the encryption associated data. Before returning a signature, Supgang writes the read audit,
opens the seed, verifies its derived public key against the stored public key, signs, and zeroizes
the opened seed and signing key. An audit failure returns no signature.

`sign NAME --context CONTEXT --sha256 DIGEST` accepts a 1–64 byte ASCII context from
`[a-z0-9._-]` and exactly 32 digest bytes encoded as 64 hex characters. It signs
`b"supgang-sign/v1\0" || context || b"\0" || digest32` with Ed25519. The JSON schema is
`supgang.signature/v1`; signatures and public keys are raw bytes encoded as lowercase hex.
Independent verification needs no Supgang instance. The
[sign-v1 vector](../vectors/sign-v1/agenxy-launcher-install.json) includes the exact public test
artifact bytes and their digest. The fixed seed is used only by tests; production keys come from
OS randomness.

The Secure Enclave supports the vault's P-256 agreement key, not an Ed25519 signing key. Ed25519
seeds are therefore sealed at rest and briefly used in process memory. Until program identity
enforcement is implemented, any process running as this macOS user can ask Supgang to sign.

## Addendum: SSH-only Ed25519 keys and local agent (18 Nov 2026)

`vault keygen --ssh ed25519 NAME` requires terminal stdin and generates a separate, random
32-byte seed. The vault stores it as kind `ssh-ed25519`. Its kind and public key are authenticated
in the encryption associated data, so changing a stored kind to `secret` or
`signing-ed25519`, including with canonical version-1 or version-2 CBOR, cannot expose or
repurpose the seed. Conversely, an existing `signing-ed25519` entry cannot serve an SSH-agent
request. `vault get`, `vault run`, and `sign` refuse SSH entries.

`vault ssh-public-key NAME` returns the OpenSSH `ssh-ed25519` public line with comment
`NAME@supgang`, plus its `SHA256:` fingerprint. The fingerprint is unpadded standard Base64
of SHA-256 over the full SSH public-key blob, matching `ssh-keygen -lf`. The JSON schema is
`supgang.ssh-public-key/v1`.

Remote `vault keygen --ssh ed25519 --remote MEMBER NAME` uses a current authenticated member
session and creates the SSH key in the target member's vault. It refuses the root-authority
computer, verifies the requester against the target's durable current peer contact and
revocation state, and applies the existing remote-key creation nonce, audit, and rate caps.
Vault format v5 binds the requester member ID to a remote SSH entry as authenticated metadata;
local SSH keys have no creator marker. The creator is visible in `vault list` and
`ssh-public-key --json`. Remote creation does not start an SSH agent or grant signing use.

`ssh-agent --socket PATH --key NAME` serves only the named SSH-kind entries. The socket must be
in an existing owner-only directory; Supgang creates it mode `0600` and verifies the connecting
process has the same user ID. It answers OpenSSH identity-list (11) and plain Ed25519 sign (13)
requests. For sign, it requires the exact selected public-key blob, a well-formed message, and
flags zero. All other request types, malformed payloads, and unsupported flags receive failure
(5); the agent has no key-add, remove, or forwarding operation. OpenSSH clients must also use
`ForwardAgent=no` to avoid forwarding their local agent socket.

The request body is capped at 256 KiB before allocation. At most 16 keys and 8 simultaneous
connections are admitted, with 256 requests per connection, at most 32 per second per connection,
a 5-second frame deadline, and a 120-second connection lifetime. Each sign uses the vault read
audit with purpose `ssh-sign` before opening the seed; an audit failure releases no signature.
The seed is zeroized after the sign. Vault reads and signs run as bounded blocking work,
so a slow Secure Enclave call does not stall other clients or shutdown. Shutdown gives lingering
blocking calls at most one second before the process exits. Agent requests and errors do not log
key material, message bytes, or the socket path.

The boundary is still the local user account: any process running as the owner can ask for a
signature while the agent is running. `authorized_keys restrict` limits the remote account's
SSH features; `restrict,pty` restores a PTY when an interactive shell is needed. A private
socket and `ForwardAgent=no` limit accidental exposure. These controls do not authenticate
individual local programs.

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
