# Trip readiness, 9 to 12 November: reconnect waits, limits, and a hotspot check

Date: 2026-11-09
Verdict: **WAN not yet re-proved on alpha.17; two defects fixed in source; the outside check below
is for the owner to run**

## Starting state

Both Macs run `0.2.0-alpha.17`. Both have tunnel limits of 40 per peer, 64 total and a 24-hour
idle deadline. Solis exposes `ssh`, `screensharing` and `remaptest`. The laptop reaches Solis on
the LAN. Solis's signed record carries the mapped IPv4 forward, and that forward matches the
home's public IPv4.

Physical WAN acceptance (13 October) used artifact `3f528aac`. Later outside evidence, from 15 and
17 October, used `d0a7473c` and `f3a344f6`. No outside evidence exists for alpha.17, and sleep and
wake off the home network has never been tested.

## Defects

- **`connect` failed during a reconnect.** A path change replaces the QUIC connection rather than
  migrating it, so every tunnel stream ends and its client must redial. The service reconnects in
  7 to 26 s. Until then, `connect` refused at once with "the peer is not connected right now".
  - An SSH started in that window failed.
  - The supervised SSH forward (`KeepAlive`, `ThrottleInterval` 30) failed and waited 30 s
    before each further try.

  Paris saw one manual recovery of a shared SSH master. `connect` now retries once a second while
  the refusal is one the service resolves itself: the peer is not connected, or its session
  authorization lapsed. It prints one line to stderr. Any other refusal returns at once.
  - Setup is bounded as a whole: 45 s (QUIC's idle timeout) from the start of `connect` to the
    first application byte, including resolving the name.
  - Each wait for the local service is cut to the time left, so a late retry cannot overrun. A
    caller with its own budget, such as an SSH `ConnectTimeout`, still applies it on top.
  - The bound says nothing about sleep and wake. Step 6 of the check below tests that.
- **A bare `tunnel-limits` reset limits.** Its flags had defaults, so running the command without
  arguments saved 4 per peer, 16 total and two hours. It did that once today on the laptop, and the
  previous values were restored a minute later. The command now shows the limits when given no
  flags, and each flag changes only its own limit.

The fix is in the client only. It needs no service restart and no protocol change, and it applies
to the computer that runs `connect`: the laptop.

## Not changed

- **Solis's sshd needs no change.** Notes from 12 and 13 October blamed resets on `MaxStartups`
  and on `PerSourcePenalties`, which has no exemption list, because every tunnelled session reaches
  sshd from loopback. Neither setting can act here.
  - macOS 27 runs sshd from launchd in inetd mode (`com.openssh.sshd`, `Wait` false). Each
    connection gets its own `sshd -i`, and no daemon listens.
  - Both settings exist only in a listening sshd's accept loop.
  - The cap visible on that socket is launchd's `Instances` of 42, a little above the 40-per-peer
    tunnel limit.
- **The gateway's IPv6 filter.** On 13 October the gateway refused unsolicited inbound IPv6. From
  the home LAN, Solis's public IPv6 addresses are on-link, so a TCP 22 answer seen from home does
  not show WAN exposure. Step 4 of the check below tests it from outside.

## Outside check, about four minutes

Run on the laptop with home Wi-Fi off and a phone hotspot on. Paste the outputs, which hold no
addresses.

1. Reconnect. Repeat until `solis` shows as connected; note the seconds taken.

   ```
   supgang peers
   ```

2. Tunnelled SSH.

   ```
   ssh -o 'ProxyCommand=supgang connect solis ssh' -o HostKeyAlias=192.168.1.191 -o ControlMaster=no -o ControlPath=none -o BatchMode=yes solis 'hostname; uptime'
   ```

3. Which path was used.

   ```
   supgang --json status | python3 -c 'import json,sys; [print(e["event"], e["path"], e["reason"]) for e in json.load(sys.stdin)["recent_connections"][-4:]]'
   ```

4. Nothing but Supgang open from outside. Expect no `OPEN`. On an IPv4-only hotspot, the IPv6 lines
   report unreachable, which is inconclusive.

   ```
   supgang --json resolve solis | python3 -c '
   import json, socket, sys
   for i, c in enumerate(c for c in json.load(sys.stdin)["candidates"] if c["kind"] in ("direct", "mapped")):
       host = c["address"].rsplit(":", 1)[0].strip("[]")
       s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET); s.settimeout(5)
       try: s.connect((host, 22)); r = "OPEN"
       except socket.timeout: r = "filtered (timeout)"
       except OSError as e: r = "closed or unreachable (%s)" % e.strerror
       finally: s.close()
       print(c["kind"], i, "tcp/22:", r)'
   ```

5. The supervised forward survived.

   ```
   launchctl print gui/$(id -u)/org.agenxy.dibs.solis-forward | grep -E '^\s*(state|runs|last exit code)'
   ```

6. Sleep and wake. Close the lid for one minute, open it, then repeat steps 1, 2 and 5.

## Evidence

- `control/tests.rs`: tunnel setup against a service that never answers gives up at its caller's
  deadline (300 ms), not after the 10 s setup timeout.
- `cli_tunnel/tests.rs`:
  - `connect` waits through both retryable refusals and announces once.
  - It returns any other refusal after one attempt.
  - It stops at its bound.
  - A `tunnel-limits` with no flags keeps raised limits, and one flag changes only its own limit.
- The complete local gate; its result is recorded in the pull request.
