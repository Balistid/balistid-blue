# 0069 — Decide anchor gaps and truncation alarms in the range

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-08
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-08)
- Agent: claude/opus-5.5
- Carries out ADR 0052 points 3, 5 and 6 for issue #213.

## Context

ADR 0052 sends `anchor_interval_s` (1 s between batch entries while recording) and `truncation_alarm_per_hour`
(more than 10 truncated records in an hour alert) to the range; no trial decides either. The rate trials report
counts only, and the record trial stores one truncated record. 2 MB records at 2 execs/s overflowed auditd's
dispatcher (ADR 0054), and the acceptance file gives the truncation alarm no latency of its own.

## Decision

1. `anchor_interval_s` gets its own row, `anchor-sustained`, and method `anchor`: rate-sustained's load (2000
   execs/s for 600 s, two runs) and facts, then a checkpoint later the largest gap between consecutive batch
   entries' stamps in the ledger's log from the load's start to its end, both ends counted as for the canary, and
   how many batches fell in it. PASS at most 1000 ms, MISS above or with no batch over the whole load. INVALID: a gap
   not measured, stamps out of order, gaps that do not cover the load, or a rate run that is not a PASS.
2. The control `anchor-control-stall` must MISS: 100 execs/s for 30 s, a record in every tick of the ledger, with
   the ledger stopped by SIGSTOP for 2 s in the middle and proven stopped, then SIGCONT; an unproven stop fails the run.
   Its MISS shows that the judge can MISS on a stalled ledger.
3. `truncation_alarm_per_hour` gets method `truncation` and two rows of two runs: `truncation-11` and
   `truncation-10`. With the watcher started through the sink, the guest runs 11 or 10 execs of 17 arguments of
   125000 B under a 32 MiB stack: all but the last one every 5 s, below the rate that overflowed, the last 80 s after
   the one before, so an alert the others raised has reached the sink, and waits 80 s after the last. 11 passes
   with exactly one `truncated` post within 65 s of the 11th exec and none before it; 10 with none.
4. A truncation run is INVALID with execs off that schedule by over a second, a sink read over an hour after the
   first exec, another count of execs or of the ledger's truncated entries than N, one before the first exec, any
   other loss entry, a kernel or dispatcher loss, no start at the sink before the first exec, a sink read before the
   window ended, or a watcher not shown to have verified the last truncated entry. A refused push, a watcher that
   restarted or is not running before its verification is a MISS; the sink and restarts are read after it.
5. The 65 s are `loss_alarm_s`'s bound (ADR 0036, point 4), as both reach the sink by the same watcher step. The
   hour's window is not shortened; its expiry stays a Go test (`TestTruncationAlarm11vs10`), untested in the range.
6. The two metrics' `method` texts in `acceptance/0.toml` name these trials; no number changes.

## Alternatives considered

- The gap as two more facts of rate-sustained: the rate judge's closed facts would change for every rate run, and
  a load that misses would also have to decide a gap.
- The control at rate-sustained's load: 14 min for a MISS on a stalled ledger that 30 s at 100/s gives as well, and the
  stall stays under the collector's 5 s write deadline to the ledger at either load.
- Truncated records at 1/s: rss-large's rate, which held for 30 s; 5 s keeps the dispatcher idle between them.
- A shorter truncation window in the range: a range-only limit would decide a number the host does not run.

## Consequences

- The table grows by four rows; `rangerun.Metrics()` lists both metrics. T13 and T20 name the trials.
- A batch stamp is the ledger's wall clock (T22): a clock step during a run can hide or invent a gap.
- The 1 h run of the method becomes L12's 24 h run (#210); the hour's expiry rests on the Go test.
- Revert: a pull request removing this file, the four rows and their methods, and restoring the two method texts.
