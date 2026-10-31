# Tunnel throughput collapsed on a lossy hotel network

Date: 2026-10-20
Verdict: **cause reproduced in the simulator and fixed; installed on the laptop; the home computer follows at the end-of-trip update**

## Report

Labs agents on the travelling laptop measured a bounded pull from the home computer through an
SSH master tunnelled by Supgang at about 33.7 kB/s, with SSH channel round trips of 0.74 to
1.02 s and some 5 s timeouts.

## Measurements from the laptop, France, 09:41–09:47 CEST

| Path | Result |
| --- | --- |
| Fresh tunnelled `ssh … head -c 4MiB /dev/zero` | 3.3 MB in 90 s, about 37 kB/s |
| Fresh tunnelled `ssh … true` | 1.9 to 4.2 s |
| TCP download from Ashburn, same network (95 ms connect) | 13.5 MB/s |
| TCP download from Cloudflare Paris | 22 MB/s |
| Scheduler wake-up delay, load average 100–275 | 1 ms median and maximum |

Wi-Fi was strong (802.11ax, −36 dBm). CPU starvation was ruled out at the time of measurement.
The 32 KiB steps the agents saw are SSH's channel packet size. Supgang's copy paths are
asynchronous with 16 KiB buffers, and QUIC allows 1 MiB per stream and 8 MiB per connection, so
neither is a 33 kB/s limit.

## Cause

Supgang's QUIC transport used quinn's default loss-based congestion control (Cubic). Hotel and
café networks commonly drop a few percent of UDP. Cubic reads each drop as congestion and, at an
ocean's round trip, holds its window near the minimum. In the simulator, 1 MiB each way at 150 ms
through the home forward:

| Random loss, each way | Cubic | BBR |
| --- | --- | --- |
| 0% | 311 kB/s | 629 kB/s |
| 2% | 35 kB/s | 459 kB/s |
| 5% | 17 kB/s | 451 kB/s |
| 10% | 11 kB/s | 372 kB/s |

The 2% row reproduces the field measurement. The simulator applies loss to every datagram,
acknowledgements included, so it is a model of a lossy network rather than of this hotel's exact
policy.

## Correction

- The transport uses model-based congestion control (quinn's BBR), which estimates the path's
  bandwidth rather than backing off on every loss.
- `service/tests/lossy_path.rs` is a gated regression test: 1 MiB each way at 150 ms with 2% loss
  must complete within 10 s. With BBR it takes about 2.3 s. With Cubic restored, it failed at 31 s.
- `supgang peers --json` now reports each connection's round-trip time, congestion window,
  congestion events, packets sent and lost, current MTU and detected MTU black holes, without
  addresses. A slow tunnel can then be attributed to loss or to the transport directly. The
  transatlantic scenario asserts that the reported round trip matches its modelled path.

The complete gate passed (434 core tests).

## Limits and next evidence

- Congestion control governs only what each side sends. Pulls from the home computer improve
  only once it runs this build; a laptop install improves pushes to it.
- BBR does not yield to competing traffic as Cubic does. On a shared hotel network, Supgang will
  hold its share more firmly. That is acceptable for an owner's tunnel. It remains a property to
  watch if an anchor later carries many owners' traffic.
- Physical confirmation: compare tunnelled throughput from the same network before and after the
  laptop install, using the path statistics to read the loss rate.

## Laptop installation, 2026-10-20

With the owner's approval, relayed through Supply, `0.2.0-alpha.11`
(`e9e6f1525bc58a2463c759c5ad74cb2c29e66aeca3cf4e7d189d98c8b4a7160c`, owner-signed) was installed on
the laptop through the new probation refresh, as a dress rehearsal for the home computer's update.
The candidate started at 11:10:01 CEST and passed the supervisor's health probation. The home
computer, still on `d0a7473c92ad`, reconnected at 11:10:33, and the refresh committed by itself
after 35 s. A tunnelled `ssh true` then took 1.54 s.

By then the network had stopped losing packets: the path statistics showed 0 lost of 4,128 sent,
a 157–160 ms round trip and a 1452-byte MTU. A 1 MiB transfer, including the SSH handshake, ran
at about 550 kB/s each way both before and after the install. That is the expected result
without loss. The simulator's comparison stands as the evidence for the lossy case, and the
next lossy period will show it in the field, readable from the path statistics.

Afterwards the Labs agents re-established their one SSH master and repeated their bounded pull:
4 MiB from the home computer in 1.23 s, about 3.4 MB/s (first byte at 0.43 s). That compares
with about 34 kB/s in the morning. The path statistics showed no loss (0 lost while the sent count
rose from 4,909 to 6,429) and a 159–167 ms round trip. Because the home computer still sends with
Cubic and the path was lossless, this shows the network recovering, not BBR at work. BBR's effect
on pulls awaits the home computer's update and a lossy period.
