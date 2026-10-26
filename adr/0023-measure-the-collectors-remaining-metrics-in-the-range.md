# 0023 — Measure the collector's remaining floor-0 metrics in the range

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-26
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

With the collector in the image (ADR 0022), six metrics of `acceptance/0.toml` still have no trial that decides them:
crash_loss_ms (only the writer controls of ADR 0018, which never count), record_max_kib, refusal_summary_s, ready_s,
systemd_exposure and cpu_cores. Their methods name what to measure, not how the guest sees it: the store says when a
collector run restarted only through `store.Open`'s recovery record; the collector reads one connection at a time
to EOF, writes stats every 60 s on a 250 ms tick and none at stop; a refusal summary lacked cause and rule version.

## Decision

1. A trial's method follows from its failure, load and metric (`rangejob.Trial.Method`); the guest runs and the host
   judges by it, a trial without one is INVALID. Rows that repeat a trial past MaxTrials are named `<trial>-<n>`.
2. crash_loss_ms: `kill-collector-1..7` and `reset-collector-1..7` (3 runs each) exec numbered events at sustained_rate.
   The fail mark carries H (ADR 0018) and S, the highest seq the collector journaled as committed before the failure,
   read live in boot 1 (never from a journal after the reset). The guest fails the run itself, before any mark, when a
   whole 10 s window before the failure held less than the rate or the last commit line is over 750 ms old. A kill is
   SIGKILL through a pidfd taken before the load, its mark once the process is gone; the store is read once a collector
   of another pid commits. MISS: a number up to H not stored, the recovery record's `last` below S (Open reused an
   acknowledged seq), or the seqs read without a gap ending below S. INVALID: no or two recovery records (a kill right
   after a seal leaves none), its seq not last+1. H counts from the exec, so auditd's and Laurel's latency is charged to
   the collector: a lagging pipeline is a MISS, never a hidden loss.
3. record_max_kib: execs with 131 072 B (1024 arguments), 2 000 000 B and, with a 32 MiB stack limit, 6 000 000 B of
   argv; a child with Laurel's uid connects, the guest sends Laurel SIGHUP (its re-exec ends the old connection, so the
   collector reads the child's three malformed lines at once; they count as a Laurel restart), and the store is read
   after the next stats record. MISS unless both smaller execs are stored whole, the large one truncated with its
   first argument in the head and its last in the tail, the three lines stored exactly (the long one by head, tail,
   length and SHA-256), no loss record, and the stats count every truncated and malformed record before them.
4. refusal_summary_s: root and a uid in `_laurel`'s group each connect 100 times a second for 150 s; under 99 % of
   that or more than planned is INVALID; a flooder stops on time. MISS unless every connection is counted once, each
   summary has its socket, its run's rule version and one cause `uid`, is stored at most 60 s plus two collector ticks
   (500 ms: the minute's tick and the flush's) after its first refusal (in acceptance/0.toml), one summary per minute
   and at most two more, and no health record but refused, stats, health and lag appears during the flood.
5. ready_s: from kernel start (realtime minus `/proc/uptime`) to the store's `Received` of the first health record
   OK, after 31 s of uptime, kernel start bounded early; none or over 30 s is a MISS. systemd_exposure: `systemd-analyze
   security` of every Balistid Blue service but the range's own and auditstat, with their range drop-ins. cpu_cores:
   CPU of the collector's and auditd's cgroups (auditd with Laurel) from before 600 s at 1000 execs a second until the
   audit backlog is empty and commits stop for 3 s, over 600 s; a rate not held, steal over 1 %, a restarted unit or a
   lost record is INVALID. What Laurel holds unsent at that moment is not counted (residual).

## Alternatives considered

- S from the journal after a reset: journald does not fsync INFO, a stale S weakens the test. The guest judging nothing:
  the host cannot see the load's windows after a reset. A collector change to write stats at stop for record_max_kib:
  a product change for a test. Strict 60 s for refusals: the ticks alone give false MISS. cpu_cores of the collector
  alone: hides the sensor's cost on the host.

## Consequences

- Amends ADR 0018 points 1, 3 and 4, ADR 0019 point 3 (S of a collector is its commit line) and refusal_summary_s's
  method (the tick); no number changes. About 70 runs a commit. A 2-vCPU VM does not hold 2000/s (C1), so crash
  trials are INVALID until the sustained_rate decision. T2, T18, T20, T24 and T26 are measured here.
- Tests: judges by closed facts, mutations of the crash judge killed (no S, no H, any recovery count); guest flows of a
  kill and a reset with a fake collector; KVM once per trial before C3.
