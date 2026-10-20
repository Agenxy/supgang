# Runbook: updating the home computer remotely, 22–24 October

Status: planned. Run only with the owner's explicit approval for this update, given at the time.

## What changes

The home computer moves from `0.2.0-alpha.10` (`d0a7473c92ad…`) to `0.2.0-alpha.11`
(`e9e6f1525bc58a2463c759c5ad74cb2c29e66aeca3cf4e7d189d98c8b4a7160c`), the build the laptop has
run since 20 October. That build has already been installed, under probation, on the laptop. The
update brings:

- BBR congestion control, so downloads from home stop collapsing on lossy networks;
- 5 s keepalives and the silence probe;
- path statistics and connection history;
- update probation and `supgang update revert`;
- the clearer control and refusal errors.

The update changes the home computer's payload only. Its supervisor, LaunchDaemon, sshd, the
router forward and the K7 pin are untouched, and no administrator password is needed.

## Why a failure cannot strand the owner

1. `service refresh` stages the newer release as the supervisor's pending candidate. The running
   supervisor (`d0a7473c92ad`) judges it with its 30 s health probation. A candidate that does not
   start, or stops answering, is abandoned for the known-good release within about 40 s.
2. A candidate that is healthy but cannot reconnect the laptop within 2 min is reverted by the
   refresh process itself, on a local timer, and the service restarts on the known-good release.
3. The outcome is recorded and shown by `supgang update status` on the home computer.

The laptop rehearsal on 20 October took 35 s from refresh to commit, with the peer back after
32 s.

What this does not cover: a candidate that passes both checks and fails later. Then run
`~/.local/bin/supgang update revert` on the home computer through any session that still works. If no session
works, wait for the owner's return.

## Preconditions

- The laptop is connected to the home computer, and `supgang peers --json` shows low loss.
- No tunnel transfer is in flight. Notify Labs, K7 and Supply on Dibs first.
- The owner has approved this update at the time.
- `scratchpad/alpha11/bin/supgang` on the laptop has the hash above and is signed by
  `Supgang Owner Codesign`.

## Steps, from the laptop

```bash
export P='ProxyCommand=supgang connect solis ssh'
scp -o "$P" ~/.local/bin/supgang solis:.local/bin/.supgang.new
ssh -o "$P" solis 'shasum -a 256 ~/.local/bin/.supgang.new; codesign -dv --verbose=2 ~/.local/bin/.supgang.new 2>&1 | grep Authority'
```

Stop unless the hash is `e9e6f152…` and the authority is `Supgang Owner Codesign`.

```bash
ssh -o "$P" solis 'mv -f ~/.local/bin/.supgang.new ~/.local/bin/supgang && nohup ~/.local/bin/supgang --json service refresh > ~/.local/share/supgang/refresh-alpha11.log 2>&1 < /dev/null &'
```

The SSH session ends when the payload restarts, because it rides the connection being replaced.
The refresh continues in its own session. Wait three minutes, then:

```bash
ssh -o "$P" solis '~/.local/bin/supgang update status; cat ~/.local/share/supgang/refresh-alpha11.log; ~/.local/bin/supgang --json status | grep -o "running_version[^,]*"'
supgang --json peers
```

Expected result: "Last probation refresh to 0.2.0-alpha.11: committed", and running version
`0.2.0-alpha.11`.

## If something goes wrong

| Seen from the laptop | Meaning | Action |
| --- | --- | --- |
| Back within 3 min, status "committed" | Success | Record and notify |
| Back within 3 min, "reverted-unhealthy" or "reverted-no-peer" | Known-good restored | Read the log, keep alpha.10, report |
| Not back after 5 min | Unexpected | Wait 5 more minutes; the revert restarts once more |
| Not back after 15 min | Both safeguards failed | Stop. Report to the owner. Nothing more can be done remotely |
