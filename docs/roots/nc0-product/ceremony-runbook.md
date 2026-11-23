# NC0 product-root escrow ceremony: owner runbook

This runbook generates the two NC0 product LMS roots, `nc0-product-primary` and
`nc0-product-recovery`, on the owner's laptop while it is offline. The command
contract is in [ADR 0010](../../architecture/0010-nc0-lms-vault-root.md#offline-product-root-escrow-ceremony).

The roots are held in **escrow only**. Each root exists solely as
passphrase-encrypted age files plus the passphrase on paper. No device holds
it in a vault, and nothing about it is non-exportable. Anyone holding one
escrow file together with that root's passphrase can sign as that root.

Only the owner runs this ceremony, and only at the laptop's own keyboard. No
agent, remote session, or screen-sharing tool may be connected.

## Before you start

You need:

- 4 new USB sticks, labelled `P1`, `P2`, `R1`, `R2`;
- 2 sheets of paper labelled `PRIMARY PASSPHRASE` and `RECOVERY PASSPHRASE`, and a pen;
- a phone camera, used only for photographing **public** values in step 7;
- the expected `supgang` binary SHA-256 and code-signing team, which Supply sends
  you separately for the release built from the merged ceremony commit.

Allow 20 minutes. Each root takes about 40 seconds of computation.

## 1. Go offline and reboot

1. Unplug Ethernet. Turn Wi-Fi off from the menu bar, and turn Bluetooth off.
2. Restart the laptop. Log in.
3. Do not turn Wi-Fi back on until step 9.

## 2. Make sure no agent is running

Open Terminal. Run:

```bash
ps -axo pid,comm | grep -iE 'claude|codex|node|dibs|supgang' | grep -v grep
```

The output must be empty. If it is not, quit the listed applications and run it
again. Also quit any screen-recording, clipboard-history, or remote-desktop tool.

## 3. Verify the binary

```bash
shasum -a 256 "$(command -v supgang)"
```

```bash
codesign --verify --strict --verbose=2 "$(command -v supgang)"
```

The hash must match the value Supply sent, character for character, and
`codesign` must report the expected team. If either one differs, stop and
report it. Do not continue.

## 4. Generate the primary root

Insert sticks `P1` and `P2`. Each one appears under `/Volumes/`. Run:

```bash
supgang lms-keygen --escrow-only nc0-product-primary --to /Volumes/P1/nc0-product-primary.age --to /Volumes/P2/nc0-product-primary.age --generate-passphrase
```

- If it reports that a default route is present, the network is still on. Return
  to step 1. Never use `--i-confirm-offline`, which exists only for tests.
- It prints seven words **once**. Write them on the `PRIMARY PASSPHRASE`
  sheet, then type them back at the hidden prompt. The screen then clears.
- At the final prompt, type the passphrase from the paper again. This
  re-reads and verifies both files.
- Leave the terminal output on screen for step 7.

## 5. Generate the recovery root

Eject `P1` and `P2`. Insert `R1` and `R2`. Run:

```bash
supgang lms-keygen --escrow-only nc0-product-recovery --to /Volumes/R1/nc0-product-recovery.age --to /Volumes/R2/nc0-product-recovery.age --generate-passphrase
```

Write the new seven words on the `RECOVERY PASSPHRASE` sheet. The two roots
must never share a passphrase.

## 6. Must-fail checks

For one primary file and one recovery file, confirm that verification rejects
bad input:

```bash
supgang lms-escrow-verify nc0-product-primary --from /Volumes/P1/nc0-product-primary.age
```

1. Enter a deliberately wrong passphrase. The command must fail.
2. Enter the correct passphrase. It must succeed and print the same fingerprint
   as step 4.
3. Make a copy with one byte changed, then verify the copy. It must fail:

   ```bash
   cp /Volumes/P1/nc0-product-primary.age ~/Desktop/flipped.age && printf 'X' | dd of="$HOME/Desktop/flipped.age" bs=1 seek=400 conv=notrunc
   ```

   ```bash
   supgang lms-escrow-verify nc0-product-primary --from ~/Desktop/flipped.age
   ```

   Then delete the copy with `rm -P ~/Desktop/flipped.age`.

Repeat 1 and 2 with `nc0-product-recovery` on `R1`.

## 7. Photograph the public values

For each root, photograph the terminal lines that show:

- the public key (hex);
- the fingerprint;
- the known-answer signature SHA-256;
- `Next q: 1`;
- each `Escrow file SHA-256` line.

These values are public. **Never photograph the passphrase sheets.**

## 8. Close and reboot

Close the Terminal window, eject every stick, and restart the laptop. The
reboot discards any terminal scrollback or memory that might still hold a
passphrase.

## 9. Cloud copies

After the reboot, turn the network back on. Copy `nc0-product-primary.age` from
`P1` and `nc0-product-recovery.age` from `R1` into a folder in iCloud Drive,
then copy the same two files into Proton Drive. Copy the files exactly; do not
open, rename, or compress them.

## 10. Custody

- Store `P1` and `P2` in two different places, and `R1` and `R2` likewise.
- Store each passphrase sheet apart from every stick of its own root.
- Store the two passphrase sheets apart from each other.
- Never type, photograph, message, or store a passphrase on any device.

Send the step 7 photographs to the lead through Supply. The lead checks them
against the hashes the cloud copies produce, then files the public record in
this directory.
