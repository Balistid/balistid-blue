# 0054 — Measure rss_mib and the canary in the range

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-03
- Decided-by: jvc0n (2026-11-03: the 1000 execs/s and burst loads, the queue and peak rules, CanaryEvery 29 s);
  claude/opus-5.5 rss-large's 1 exec/s from his intent, "the rate Laurel holds", after 2/s overflowed (run 41567155763),
  confirmed by his approval of this pull request, and the rest
- Agent: claude/opus-5.5
- Closes the decisions of issue #199; amends the methods of `rss_mib` (ADR 0007) and `canary_interval_s` (ADR 0017).

## Context

`rss_mib` (256 MiB, ADR 0040) and `canary_interval_s` (30 s) had no range trial. Two loads the acceptance named
cannot run: rate-burst's 10000 records/s at 64 KiB is 640 MB/s, and a DIAG run measured Laurel at one core for about
4 MB/s of 2 MB records, so 50 execs/s of them only measures a backlog; at 2 execs/s auditd's dispatcher overflowed
(KVM, dec2a4b, GitHub run 41567155763). An 8 MiB queue in the range lost about 15000 records of rss-burst at the
queue (run 41585851808), the shipped one holds 64 MiB; 1 s VmRSS samples can miss a peak between them; a recorder
killed by its MemoryMax is restarted by systemd, which read as INVALID and was rerun. A canary sent every 30 s puts a
gap over 30 s on any late writer tick.

## Decision

1. `rss_mib` is decided by three trials: 1000 execs/s for 600 s (cpu-1000's load), the ptrace burst of 10000/s for
   10 s with its small records (rate-burst's), and 1 exec/s of 2 MB argv for 30 s, below the dispatcher's overflow.
2. A run's peak is the larger of the largest 1 s VmRSS sum and the summed VmHWM of the recorder's processes at the
   end (each trial boots a fresh VM). A peak over 256 MiB is a MISS. The collector runs the shipped queue,
   `collector.QueueBytes`, read from its argv: another, or one not read, is INVALID (ADR 0039, point 2).
3. An OOM event of a recorder unit, from its cgroup's `memory.events` (`oom`, `oom_kill`) or systemd's OOM message,
   which outlives the restart, is a MISS. A MISS outranks every INVALID of the run. The control `rss-oom-control` sets
   the ledger's MemoryMax to 1 MiB at runtime under 1000 execs/s for 30 s and stops it after the load (each restart
   is an audited exec); the ledger is not sampled. It gives MISS only by the ledger's OOM messages whose journal time
   is after the proven injection, none at or before it, with the other units' run whole; anything less is INVALID.
4. A load not delivered, shown by auditd's overflow flag, a loss record of the store or a collector's lost record
   from the load's start to the store read, or not covered, the first sample after the load's start or a gap over
   2 s during it, is INVALID. The drain waits for auditd's plugin queue too, as the kernel's backlog empties first.
5. The collector sends its canary every 29 s (`CanaryEvery`), a second inside 30 s. A frozen stage passes only with
   its first canary within 30 s of the freeze, UNKNOWN no earlier than that canary's deadline less a second (28 s)
   and within 61 s of it, health UNKNOWN from then to SIGCONT and OK within 40 s after; the quiet phase must be OK
   throughout, after a floor that showed healthy. Only an audited create of `c-<n>` counts as a canary.

## Alternatives considered

- A smaller queue with `collector.QueueBytes` less its bytes added to the peak: it dropped part of rss-burst's
  load, and the Go heap can hold up to twice the queue (GOGC 100), so the sum bounds nothing.
- 64 KiB records at 10000/s, or 2 MB ones at 50/s or 2/s: a stage drops or backs them up, so no run is whole.
- Sample faster than 1 s: costs CPU under the load it measures; VmHWM bounds what falls between samples.
- A restart as a MISS: it has causes other than memory; it stays INVALID unless an OOM event shows.

## Consequences

- VmHWM sums peaks that need not coincide, an upper bound. The queue's bytes are measured with the rest, below the
  collector's 192 MiB soft limit.
- rss-large at 1/s drives Laurel at half its ~4 MB/s, below the collector's worst case: 2/s measured about 126 MB
  (67b19f2) against 122-124 MB at 1/s. An overflow stays INVALID: dropped records leave the load that reached the
  recorder unknown, and no count of the load's records after the dispatcher shows how much it was.
- An UNKNOWN before the first frozen canary's deadline needs a probe missed outside the injection: a MISS.
- The OOM message is trusted to carry the unit's name; `memory.events` covers a unit systemd did not restart.
- Revert: a pull request removing this file and restoring the two methods in `acceptance/0.toml`.
