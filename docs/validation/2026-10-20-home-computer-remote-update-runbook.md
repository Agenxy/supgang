# Runbook: updating the home computer remotely

Status: planned. Run only with the owner's explicit approval for this update, given at the time.

## What changes

The home computer moves from `0.2.0-alpha.10` (`d0a7473c92ad…`) to `0.2.0-alpha.13`
(`afe18ad392d4d5602334daf164fb476bacd6f1270f02f04b7f3ee7620405b4c7`, commit `d0e4d08`). The laptop
has run this build since 20 October, installed under probation, and both automatic reverts were
proven with it (below). The
update brings:

- BBR congestion control, so downloads from home stop collapsing on lossy networks;
- 5 s keepalives and the silence probe;
- path statistics and connection history;
- update probation, `supgang update revert`, a revert target that is never a failed build, and
  candidate judgement that survives a timed-out restart wait;
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

Proven on the laptop on 20 October with alpha.13 and deliberately failing probe builds, each
logging its own life:

- Install: committed in 34 s with the peer back.
- Unhealthy candidate: it refused to start, and the supervisor restored the previous release in
  5 s.
- Candidate that never reconnects: committed at 10:39:30Z after 30 s of health probation,
  reverted by the refresh's local timer at 10:41:30Z, restart requested at 10:41:31Z, peer back
  at 10:42:02Z.
- Owner hand revert: 3 s.

In every case `supgang update revert` was left pointing at a release that had worked.

What this does not cover: a candidate that passes both checks and fails later. Then run
`~/.local/bin/supgang update revert` on the home computer through any session that still works. If no session
works, wait for the owner's return.

## Preconditions

- The laptop is connected to the home computer, and `supgang peers --json` shows low loss.
- No tunnel transfer is in flight. Notify Labs, K7 and Supply on Dibs first.
- The owner has approved this update at the time.
- `~/.local/bin/supgang` on the laptop has the hash above and is signed by
  `Supgang Owner Codesign`.

## Steps, from the laptop

```bash
export P='ProxyCommand=supgang connect solis ssh'
scp -o "$P" ~/.local/bin/supgang solis:.local/bin/.supgang.new
ssh -o "$P" solis 'shasum -a 256 ~/.local/bin/.supgang.new; codesign -dv --verbose=2 ~/.local/bin/.supgang.new 2>&1 | grep Authority'
```

Stop unless the hash is `afe18ad3…` and the authority is `Supgang Owner Codesign`.

```bash
ssh -o "$P" solis 'mv -f ~/.local/bin/.supgang.new ~/.local/bin/supgang && nohup ~/.local/bin/supgang --json service refresh > ~/.local/share/supgang/refresh-alpha13.log 2>&1 < /dev/null &'
```

The SSH session ends when the payload restarts, because it rides the connection being replaced.
The refresh continues in its own session. Wait three minutes, then:

```bash
ssh -o "$P" solis '~/.local/bin/supgang update status; cat ~/.local/share/supgang/refresh-alpha13.log; ~/.local/bin/supgang --json status | grep -o "running_version[^,]*"'
supgang --json peers
```

Expected result: "Last probation refresh to 0.2.0-alpha.13: committed", and running version
`0.2.0-alpha.13`. The log lists each stage with a Unix timestamp.

## If something goes wrong

| Seen from the laptop | Meaning | Action |
| --- | --- | --- |
| Back within 3 min, status "committed" | Success | Record and notify |
| Back within 3 min, "reverted-unhealthy" or "reverted-no-peer" | Known-good restored | Read the log, keep alpha.10, report |
| Not back after 5 min | Unexpected | Wait 5 more minutes; the revert restarts once more |
| Not back after 15 min | Both safeguards failed | Stop. Report to the owner. Nothing more can be done remotely |
