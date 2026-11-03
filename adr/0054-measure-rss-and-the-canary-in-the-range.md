# 0054 — Measure rss_mib and the canary in the range

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-03
- Decided-by: alex (2026-11-03: the loads, the queue and peak bounds, CanaryEvery 29 s); claude/opus-5.5 the rest
- Agent: claude/opus-5.5
- Closes the decisions of issue #199; amends the methods of `rss_mib` (ADR 0007) and `canary_interval_s` (ADR 0017).

## Context

`rss_mib` (256 MiB, ADR 0040) and `canary_interval_s` (30 s) had no range trial. Two loads the acceptance named
cannot run: rate-burst's 10000 records/s at 64 KiB is 640 MB/s, and a DIAG run measured Laurel at one core for about
4 MB/s of 2 MB records, so 50 execs/s of them only measures a backlog; at 2 execs/s auditd's dispatcher overflowed
(KVM, dec2a4b, GitHub run 41567155763). The range's collector holds an 8 MiB queue
(ADR 0039, point 2), the shipped one 64 MiB; 1 s VmRSS samples can miss a peak between them; a recorder killed by
its MemoryMax is restarted by systemd, which read as INVALID and was rerun. A canary sent every 30 s puts a gap over
30 s on any late writer tick.

## Decision

1. `rss_mib` is decided by three trials: 1000 execs/s for 600 s (cpu-1000's load), the ptrace burst of 10000/s for
   10 s with its small records (rate-burst's), and 1 exec/s of 2 MB argv for 30 s, below the dispatcher's overflow.
2. A run's peak is the larger of the largest 1 s VmRSS sum and the summed VmHWM of the recorder's processes at the
   end (each trial boots a fresh VM), plus `collector.QueueBytes` less the collector's own `-queue-bytes`, read
   from its argv, in KiB. A peak over 256 MiB is a MISS; a queue not read is INVALID.
3. An OOM event of a recorder unit, from its cgroup's `memory.events` (`oom`, `oom_kill`) or systemd's OOM message,
   which outlives the restart, is a MISS. A MISS outranks every INVALID of the run.
4. A load not delivered, shown by auditd's overflow flag or a loss or stats record of the collector or the store,
   or not covered, the first sample after the load's start or a gap over 2 s during it, is INVALID.
5. The collector sends its canary every 29 s (`CanaryEvery`), a second inside 30 s. A frozen stage passes only with
   its first canary within 30 s of the freeze, UNKNOWN no earlier than that canary's deadline less a second (28 s)
   and within 61 s of it, health UNKNOWN from then to SIGCONT and OK within 40 s after; the quiet phase must be OK
   throughout, after a floor that showed healthy. Only an audited create of `c-<n>` counts as a canary.

## Alternatives considered

- Run RSS trials with the shipped queue (a drop-in and a restart, or a second image): the correction bounds it
  from above without another unit file in the range.
- 64 KiB records at 10000/s, or 2 MB ones at 50/s or 2/s: a stage drops or backs them up, so no run is whole.
- Sample faster than 1 s: costs CPU under the load it measures; VmHWM bounds what falls between samples.
- A restart as a MISS: it has causes other than memory; it stays INVALID unless an OOM event shows.

## Consequences

- An RSS PASS is an upper bound: VmHWM sums peaks that need not coincide, and the correction assumes a full queue.
- An UNKNOWN before the first frozen canary's deadline needs a probe missed outside the injection: a MISS.
- The OOM message is trusted to carry the unit's name; `memory.events` covers a unit systemd did not restart.
- Revert: a pull request removing this file and restoring the two methods in `acceptance/0.toml`.
