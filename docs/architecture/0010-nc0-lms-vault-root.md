# NC0 LMS vault root

Status: implementation contract, 18 November 2026. Supgang owns the signing
key and package signer; Agenxy Labs owns the independent stage-1 verifier and
the eventual chip acceptance. This document is a design and test plan, not
evidence of a manufactured or booted device.

## Scope and wire contract

The only public LMS kind is RFC 8554 `LMS_SHA256_M32_H20` (type 8) with
`LMOTS_SHA256_N32_W1` (type 1). Its 56-byte public key is
`u32be(8) || u32be(1) || I[16] || T[1][32]`. Export exactly those bytes and
their lowercase SHA-256. A signature is exactly 9164 bytes:
`u32be(q) || u32be(1) || C[32] || y[265][32] || u32be(8) || path[20][32]`.
Reject other public parameter sets. Internal parameterized code may exist only
to check RFC test vectors. Generate a random 32-byte SEED and 16-byte I;
encrypt both to a new per-root Secure Enclave P-256 agreement public key whose
private agreement requires owner presence on every use. The Secure Enclave
protects the agreement key; it does not itself execute LMS. Never export
SEED or I through `vault get` or `vault run`.

The key is single-purpose: NC0 format-2 application packages. The signer
accepts a bounded 64-byte header followed by the exact payload, checks every
field, and signs `msg = SHA256(header || payload)`. It does not accept a bare
digest or arbitrary message. The 16 header words are little-endian u32:
magic `0x0400006f`, format `2`, scheme `3`, header length `64`, total length
`64 + payload length + 9164`, nonzero payload length, flags with only bit 0
permitted, signature length `9164`, helper offset/field/length all zero,
security version in word 11, and words 12–15 zero. The signature follows the
payload directly. RFC 8554 computes
`Q = SHA256(I || u32be(q) || 0x8181 || C || msg)`; there is no additional
prehash or application domain tag. Stage 1, not ROM, verifies the LMS signature
against a pinned root. ROM checks stage 1 against its fixed SHA-256 digest.

## Key generation and state

Key generation requires the owner at a TTY. Derive leaf keys from SEED and I
as RFC 8554 Appendix A specifies. Compute T[1] by streaming treehash with
O(H) nodes; never allocate the full tree. The H20/W1 operation is expensive;
show progress and measure wall time in the installed acceptance run. Vault
format v3 adds the LMS kind, its 56-byte public key, and `next_q` under
authenticated encryption. Existing v1/v2 documents remain readable and are
upgraded canonically on mutation without changing their entry authentication.

### Presence from root creation (vault v6)

Every new LMS root gets a distinct agreement key with
`[.privateKeyUsage, .userPresence]`,
`AfterFirstUnlockThisDeviceOnly`, and an LAContext with reuse duration zero.
Creation uses its public half and ephemeral ECDH, so it does not request
presence. The existing unattended vault agreement remains unchanged for
other secrets. In v6, the LMS SEED and I exist only in the separate presence
wrap. The ordinary vault ciphertext holds a one-byte state marker; its AAD
binds q, public root and the digest of the complete presence wrap. The
presence ciphertext AAD binds the root, entry name, note, time, presence
public key and ephemeral key, but excludes q so advancing q cannot rewrap
the seed. A changed or removed wrap cannot authenticate as the original
state. The vault format upgrade is one-way; v1-v5 LMS entries remain readable
for public-key and q inspection, but signing them is refused. They cannot be
rewrapped into product roots because a prior plaintext copy cannot be ruled
out. `lms-keygen` has no flag to omit presence.

After command confirmation, `lms-sign` must complete the presence-gated
agreement and decrypt SEED/I while holding the vault lock, before either q
record changes. A declined or unavailable presence prompt returns without a
signature or output file and without changing the vault q or journal q. The
existing journal-before-vault reservation order follows a successful unwrap.
The helper allows up to 60 seconds for the owner prompt, so the vault lock can
be held for that entire interval. Other vault changes wait for it; they do not
start another LMS reservation.
The owner prompt names the LMS key, the q being reserved, and the first 16
hex digits of the validated package SHA-256. This reason text is supplied by
the caller, not attested by the Secure Enclave; any same-user process can
trigger a prompt with its own text.
`preview`, public-key reads, and journal agreement checks use only the
ordinary vault agreement and do not prompt. The owner prompt approves use
of the Secure Enclave private key; it does not attest that the requesting
process is a human-owned console. A headless or agent-pty refusal is an
installed acceptance observation, not a portable platform guarantee.

An independent owner-only append-only reservation journal is bound to the
public-key hash. Its initial durable record says `next_q=0`. Both the sealed
vault entry and the journal must be readable and have the same `next_q` before
signing. Missing, malformed, truncated, reordered, or disagreeing state
refuses signing. Neither source silently repairs the other. The vault lock
serializes all key state changes; journal creation and append sync the file
and parent directory. Atomic vault replacement syncs the replacement and
parent directory. Exclude only the LMS journal from Time Machine backups and
verify the flag after each append; preserve normal vault backup behavior for
other secrets. Restoring a vault backup without its journal leaves the journal
missing, so signing refuses. Backup exclusion is a precaution, not a rollback
proof: APFS clones and snapshots do not honor it.

If key generation fails before the vault entry is committed, its new q=0
journal is removed and the directory synced; cleanup failure is reported.
After a crash, a retry may replace only one valid, single-record q=0 orphan
when no vault entry of that name exists, and the replacement is audited. If
the vault entry did commit before the error, retain its journal and refuse a
new key under that name. Any non-pristine orphan refuses.

Signing requires a TTY and explicit confirmation showing key name, next q,
remaining signatures, and the package digest. Exactly one external check is
required: `--first-signature`, allowed only when both records have never
reserved a q, or `--after-q N`, where N is the highest q in the caller's
independent release log. Refuse when `next_q <= N`. After confirmation and
while holding the lock, recheck all state and external constraints. Append
and sync `next_q=q+1` to the journal first; reseal/save/sync the vault's
`next_q=q+1` second; only then compute or release the signature. A failed
computation burns q. Every successful result carries q. Refuse when
`q >= 2^20`.
Before releasing the signature, verify it against the fixed public root and
package digest. Verification failure burns q and returns an error.

The command surface is `vault lms-keygen NAME`, `vault public-key NAME`
(also `vault lms-public-key NAME`), `vault lms-sign NAME --package
UNSIGNED --output SIGNED --first-signature` or `--after-q N`, and
`vault lms-advance NAME --to-q N --after-q M`. The signing output is the
validated header and payload followed directly by the signature; output
creation never overwrites an existing file. If output creation or verification
fails after q is reserved, that q remains burned. The caller must add each
successfully released q to its independent log before signing again.

An owner-present TTY `advance` command is the only recovery path for a
readable mismatch. It takes a target `next_q` strictly greater than the
highest readable local record and strictly greater than `--after-q N`; it
advances journal then sealed state with the same durability ordering. It
never decreases either record. An unreadable record or uncertain key identity
requires retiring this key and generating a new root. The public key and
journal are retained as retirement evidence; no reset or implicit reuse.

**A coordinated rollback of all local state, together with a missing or
rolled-back external release log, can replay q. Supgang cannot detect that.**
Owner custody of the independent release log is part of the operational
boundary. A hardware monotonic counter is outside this slice.

## Offline product-root escrow ceremony

NC0 product roots use `supgang lms-keygen --escrow-only NAME --to PATH --to
PATH --generate-passphrase` at an owner terminal on a network-off laptop. Run
the command separately for each root, with a different passphrase each time.
The command rejects a peer or state-directory argument and never opens the
vault, service, or network. Before generation, it reads the local IPv4 and
IPv6 routing table and refuses while a default route exists. The explicit
`--i-confirm-offline` override is for tests only and prints a warning. It
requires two to four distinct new files. Each file is an independently
randomized standard age v1 scrypt ciphertext with work factor `2^20`, `r=8`,
and `p=1`; decryption accepts only work factors `2^18` through `2^22`.

`--generate-passphrase` draws seven words from the embedded, hash-pinned EFF
large wordlist using bounded unbiased rejection sampling from the OS CSPRNG.
It shows the passphrase once on the terminal and requires the owner to type it
back before any file is written, then requests ANSI screen and scrollback
clearing. Terminals and capture software may retain earlier output. Without
that flag, the owner enters a manual passphrase of at least seven words totaling
24 bytes, or 40 bytes, then confirms it. Passphrases are at most 256 bytes, read with terminal
echo and line editing disabled, and entered again to verify every written
file. They are never accepted in argv or environment.

Keygen draws a random SEED32, I16, and LM-OTS randomizer, computes the H20/W1
root and its q=0 authentication path in one streaming pass, then signs
`SHA256("supgang/nc0-lms-known-answer/v1\0" || name || public_key)` at q=0.
That message is only a known answer; it is not an NC0 package. Supgang checks
the signature against the new root before any write. The versioned escrow
record contains LMS type 8, LM-OTS type 1, I, SEED, public key, name,
`next_q=1`, q=0 marked as used for the known answer, and the signature. The
public output schema is `supgang.nc0-lms-public-key/v1`; human and JSON
output include the public root fingerprint, known-answer signature SHA-256,
and the SHA-256 of each verified escrow file for the owner record.

The plaintext record exists only in zeroizing process memory. The ceremony
disables process core dumps before generating SEED/I. It creates no temporary
file and writes only ciphertext with owner-only permissions, exclusive
creation, file sync, and parent-directory sync. It reopens each path,
decrypts with the separately entered passphrase, authenticates the known
answer, and independently recomputes T[1] from that file's SEED/I. A failure
names the path and withholds the success receipt. Ordinary OS swap or
forensic recovery of process memory is outside this software guarantee; the
owner's network-off, protected laptop remains part of the ceremony boundary.

`supgang lms-escrow-verify NAME --from PATH` verifies an existing escrow file
without generating a root or opening the vault, service, or network. It reads
one hidden passphrase, authenticates the age header and payload, checks the
record name and q=0 known answer, and independently recomputes the H20/W1
root from that file's SEED/I. Its public receipt uses
`supgang.nc0-lms-escrow-verify/v1` and includes the public key, fingerprint,
known-answer signature SHA-256, `next_q=1`, and the encrypted file SHA-256.
It never prints the decrypted record or seed. Since it is read-only, it has no
offline routing-table guard; core dumps remain disabled during verification.

## Failure and acceptance matrix

| Stop point | Expected result |
| --- | --- |
| Before confirmation or reservation | No signature and no q consumed |
| After journal append, before vault save | Mismatch; signing refuses; owner may advance forward |
| After vault save, before signature release | Both records at q+1; q burned; future sign may continue |
| During signature or output | q remains burned; never retry the same q |
| Stale or rolled-back one local record | Mismatch; signing refuses |
| Both local records rolled back; release log intact | `--after-q` refuses replay |
| Both local records and release log rolled back | Undetectable; stated limitation |
| q reaches 2^20 or state cannot be read | Refuse signing |

Tests must cover canonical v1/v2/v3 reads, AAD tampering, key export refusal,
bounded input, every crash window, stale/rolled-back records, concurrent
signers, exhaustion, and forward-only recovery. Check the independent RFC
8554 Appendix F vectors. For package acceptance, generate a public test
package, sign it with Supgang, verify the result with Labs' C `nt0_lms.h`,
and show a flipped byte is rejected. Do not copy the GPL Labs verifier into
this Apache-2.0 repository. Run focused tests, the complete local quality
gate, then install an isolated release artifact and exercise key generation
through a pty from an owner-only directory under `~/.cache`. Local and hosted
checks, installed behavior, stage-1 integration, and physical boot are
reported separately.
