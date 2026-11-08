# 0070 — Wait the collector's first 15 s for auditstat's first report

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-08
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-08)
- Agent: claude/opus-5.5
- Closes issue #279; amends ADR 0059 point 3.

## Context

ADR 0059 point 3 made health reason 8 `audit-stale` at once until the collector has read auditstat's first report,
so that an OK never says nothing of the loaded rules (R6). At boot the collector starts before auditd, without
default dependencies, and stores its first canary once audit-rules.service has loaded the canary's watch, while
balistid-auditstat starts with multi-user.target. Between the two the collector logs 8, which the Pi alerts at once:
a false page at a boot whenever the watcher already follows the log. ba1e366 put 8 at once and replaced the test of
the old 15 s grace with `TestNothingReadIsStale`. The range control `loss-control-none` then gave a MISS on
2026-11-06 and 5 MISS and 2 PASS on 2026-11-08, each an unknown alert 13.5 to 16.8 s after the watcher's start;
`loss-auditd-crash` run 42290375401 was INVALID with "an UNKNOWN logged before 8" the injection.

Nothing orders auditstat after audit-rules.service either: a first report taken while augenrules loads the rules
shows a part of them, reason 11 at once if the canary, whose watch loads early, is stored before the next poll.

## Decision

1. With no report read yet, health is `UNKNOWN starting` (reason 1) while the collector is under 15 s old
   (`auditFresh`, ADR 0038 point 4's grace for 8 and 10), and 8 from 15 s on. It is never OK without a report.
2. Starting is named where 8 was, only where health would otherwise be OK; the order 9, 11, 10, 8 stays.
3. balistid-auditstat starts after audit-rules.service, so its first report shows the rules the boot loaded.
4. `balistid status` says starting lasts until the first canary is stored and auditstat's report is read.

## Alternatives considered

- Start auditstat before the collector can store a canary: `Type=exec` says nothing of its first report, and a
  report before audit-rules.service shows no rules, 11 at once; ordering only narrows the race.
- auditstat as `Type=notify` after its first report, with the collector after it: the collector starts before
  auditd and must not wait for a unit that needs the loaded rules.
- A grace for 8 on the Pi: the Pi cannot tell a boot's 8 from a stopped auditstat's.
- Keep 8 at once: every boot whose watcher follows the log pages.

## Consequences

- R6 holds: a report that does not come alerts as 8 at 15 s of the collector's monotonic clock; were 8 never
  logged, the Pi's watchdog alerts on a starting that lasts 60 s (ADR 0031 point 3). An auditstat that reports
  later than 15 s after the collector starts still pages, as before ba1e366.
- A collector restarted while auditstat runs reads the report in its first tick and logs no starting for it.
- The rules trials keep their 10 s from the first stored canary to `rules-differ`; their judge accepts starting.
- Revert: a pull request removing this file, the starting case, the hint, the unit's `After=` and their tests.
