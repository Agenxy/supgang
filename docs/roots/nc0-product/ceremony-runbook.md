# NC0 product-root share ceremony: owner runbook

This runbook creates the two NC0 product LMS roots, `nc0-product-primary` and
`nc0-product-recovery`, on the owner's laptop while it is offline. The design is
in [ADR 0010](../../architecture/0010-nc0-lms-vault-root.md).

## What the ceremony makes

Each root comes from its own random 256-bit master secret. The command splits
each master into three SLIP-39 shares, any two of which rebuild it. It then
encrypts the shares onto three media, A, B and C:

| Medium | Holds | Unlocked by |
|---|---|---|
| A | stick A: one share of each root (2 files) | passphrase sheet A |
| B | stick B: one share of each root (2 files) | passphrase sheet B |
| C | stick C, then cloud copies: one share of each root (2 files) | passphrase sheet C |

That's three passphrases and six files. A share counts only when its file and
its passphrase sheet are together. One share alone reveals nothing about the
root, and any two shares rebuild it.

No device keeps the masters. The command erases them from memory, then rebuilds
each root from every pair of media (A+B, A+C, B+C) and checks that the public
key is identical every time. The rebuild never signs.

Only the owner runs this ceremony, and only at the laptop's own keyboard. No
agent, remote session or screen-sharing tool may be connected.

## Before you start

You need:

- 3 new USB sticks, labelled `A`, `B` and `C`;
- 3 sheets of paper, labelled `PASSPHRASE A`, `PASSPHRASE B` and `PASSPHRASE C`,
  and a pen;
- a phone camera, used only for photographing **public** values in step 7;
- the expected `supgang` binary SHA-256 and code-signing team. Supply sends these
  separately, for the release built from the merged ceremony commit.

Allow 30 minutes. Each root takes about a minute of computation.

## 1. Go offline and reboot

1. Unplug Ethernet. Turn Wi-Fi off from the menu bar, and turn Bluetooth off.
2. Restart the laptop and log in.
3. Do not turn Wi-Fi back on until step 9.

## 2. Make sure no agent is running

Open Terminal and run:

```bash
ps -axo pid,comm | grep -iE 'claude|codex|antigravity|gemini|node|dibs|supgang' | grep -v grep
```

The output must be empty. If it isn't, quit the listed applications and run it
again. Also quit any screen-recording, clipboard-history or remote-desktop tool.

## 3. Verify the binary

```bash
shasum -a 256 "$(command -v supgang)"
```

```bash
codesign --verify --strict --verbose=2 "$(command -v supgang)"
```

The hash must match the value Supply sent, character for character, and
`codesign` must report the expected team. If either differs, stop and report
it. Do not continue.

## 4. Run the ceremony

Insert sticks `A`, `B` and `C`. Each one appears under `/Volumes/`. Run:

```bash
supgang lms-share-ceremony --medium-a /Volumes/A --medium-b /Volumes/B --medium-c /Volumes/C
```

- If it reports that a default route is present, the network is still on.
  Return to step 1. Never use `--i-confirm-offline`, which exists only for tests.
- It prints passphrase A **once**, as seven words. Write them on the
  `PASSPHRASE A` sheet, then type them back at the hidden prompt. The screen
  then clears. Passphrases B and C follow the same way, each on its own sheet.
- The command then writes the six files, asks for each passphrase again, and
  rebuilds both roots from every pair of media. Type each passphrase from its
  sheet. A mistyped entry is checked at once and asked again, up to three
  times.
- It finishes by printing, for each root, the public key, fingerprint,
  known-answer SHA-256 and `next_q`, plus a SHA-256 for each of the six files.
  Leave this on screen for step 7.

If any step fails, stop and report the exact message. Never rerun the ceremony
on sticks that already hold share files. If the files were written but a later
check failed, the message says so: run step 5a for each pair instead, and
report the result.

## 5. B+C recovery drill and negative checks

### 5a. Recovery drill: must SUCCEED

This drill rebuilds each root from stick B and stick C alone, the same pair
that recovers the roots if Site 1 is ever lost. It never signs.

```bash
supgang lms-share-verify primary --share /Volumes/B/nc0-product-primary.share.age --share /Volumes/C/nc0-product-primary.share.age
```

```bash
supgang lms-share-verify recovery --share /Volumes/B/nc0-product-recovery.share.age --share /Volumes/C/nc0-product-recovery.share.age
```

Type passphrases B and C from their sheets. Each command must succeed and print
the same public key and fingerprint as step 4 for that root.

### 5b. Negative checks: each must FAIL

Run these against `nc0-product-primary`:

1. Repeat the 5a primary command, but type a deliberately wrong passphrase for
   B. It must fail.
2. **Single share.** Give the same file twice (`--share` B, `--share` B). One
   share is below the threshold, so it must fail to rebuild.
3. **Altered file.** Make a copy with one byte changed, then verify using the
   copy. It must fail:

   ```bash
   cp /Volumes/B/nc0-product-primary.share.age ~/Desktop/flipped.age && printf 'X' | dd of="$HOME/Desktop/flipped.age" bs=1 seek=400 conv=notrunc
   ```

   ```bash
   supgang lms-share-verify primary --share ~/Desktop/flipped.age --share /Volumes/C/nc0-product-primary.share.age
   ```

   Then delete the copy with `rm -P ~/Desktop/flipped.age`.

## 6. Which tool is primary

The Rust tool is primary only if, by Fri 27 Nov 09:00, an independent hands-on
check has rerun the official SLIP-39 vectors, the two-way cross-check against
the pinned Python 0.3.0, and the KDF known answers and must-fails. If that
check is missed, the pinned Python CLI is primary for the ceremony
automatically, and Supply sends its sheet. Supply confirms which tool is primary
before you start.

## 7. Photograph the public values

For each root, photograph the terminal lines that show:

- the public key (hex);
- the fingerprint;
- the known-answer SHA-256;
- `next_q`;
- every file SHA-256 line.

These values are public. **Never photograph a passphrase sheet.**

## 8. Close and reboot

Close the Terminal window, eject every stick and restart the laptop. The reboot
discards any terminal scrollback or memory that might still hold a passphrase.

## 9. Cloud copies of medium C

After the reboot, turn the network back on. Insert stick `C`. Copy both
`.share.age` files from it into a folder in iCloud Drive, then copy the same two
files into Proton Drive. Copy them exactly; do not open, rename or compress
them.

Check that each cloud copy's SHA-256 matches the step 7 photograph:

```bash
shasum -a 256 ~/Library/Mobile\ Documents/com~apple~CloudDocs/<folder>/*.share.age
```

Once both cloud copies match, erase stick `C` with Disk Utility. Erase it, never
store it. Paper C is the only physical part of medium C. Without the sheet, a
cloud copy is useless to anyone.

## 10. Custody

| Place | Holds |
|---|---|
| Site 1 | stick A and sheet A |
| Site 2 | stick B and sheet B |
| P | sheet C |
| Cloud (iCloud and Proton) | the two C files |

Never type, photograph, message or store a passphrase on any device.

### What this layout survives

Run `tools/custody_table.py` to regenerate this table:

| Places | Theft: usable shares | Loss: shares left |
|---|---|---|
| Site 1 | 1 (A) | 2 (B, C) |
| Site 2 | 1 (B) | 2 (A, C) |
| P | 0 | 2 (A, B) |
| Cloud | 0 | 2 (A, B) |
| Site 1 + Site 2 | 2 (A, B) | 1 (C) |
| Site 1 + P | 1 (A) | 1 (B) |
| Site 1 + Cloud | 1 (A) | 1 (B) |
| Site 2 + P | 1 (B) | 1 (A) |
| Site 2 + Cloud | 1 (B) | 1 (A) |
| P + Cloud | 1 (C) | 2 (A, B) |
| Site 1 + Site 2 + P | 2 (A, B) | 0 |
| Site 1 + Site 2 + Cloud | 2 (A, B) | 0 |
| Site 1 + P + Cloud | 2 (A, C) | 1 (B) |
| Site 2 + P + Cloud | 2 (B, C) | 1 (A) |
| Site 1 + Site 2 + P + Cloud | 3 (A, B, C) | 0 |

The roots survive any ONE place lost or stolen. Losing any two places other
than P + Cloud is fatal, which is inherent to 2-of-3. If one place is lost,
re-run the share ceremony from the two surviving media, promptly, before a
second loss.

Send the step 7 photographs to the lead through Supply. The lead checks them
against the hashes of the cloud copies, then files the public record in this
directory.

## Signing is a separate step

This ceremony never signs anything except each root's q=0 known-answer
signature. Before the first product signature, the signer must meet the
following, as set out in ADR 0010:

- signing is refused without a signing log held in at least two copies;
- after any restore, signing resumes at the next unused 2^16 block above the
  highest logged q;
- q is never restored from a share;
- q at or above 2^20 is refused.
