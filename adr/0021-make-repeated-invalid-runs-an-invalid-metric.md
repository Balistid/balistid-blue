# 0021 — Make repeated INVALID runs an INVALID metric

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-13
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0018 point 6 lets INVALID runs that outnumber a metric's trials make a MISS. Review of the acceptance slot showed
what that costs. The tick runs QEMU at idle CPU priority, so ordinary load on the host, an agent's included, raises
guest steal over 1 %, and each such run is INVALID. Three of them would make a MISS that stands for the commit. T36
accepts that agents delay acceptance or make it INVALID, never that they fail a commit. A control that cannot measure
would likewise fail its metric, which ADR 0019 point 2 rules out.

## Decision

1. INVALID runs never make a MISS. A trial whose INVALID runs exceed its Count is no longer scheduled for the commit.
   If it may decide its metric, or is one of its controls, the metric's verdict is INVALID: it could not be measured.
2. A metric's verdict is MISS once a run that may decide it missed; else INVALID as in point 1; else PASS when every
   run that may decide it passed and every control gave its verdict; else it is still open. A MISS is never replaced.
3. Runs the host stopped (memory watch, a process the runner could not start: pipe or exec) or the runner's stop
   cut short are not recorded and run again. Baseline runs decide nothing, their INVALID runs included. Each batch
   logs every metric's verdict.

## Consequences

- Amends ADR 0018 point 6. T36 stands as written: agents and host load can delay acceptance or make it INVALID.
- A start that fails inside the sandbox wrappers (bwrap or QEMU exiting before the guest) is not told apart from a
  run that failed: it counts as INVALID and can make the metric INVALID, never a MISS. Accepted under T36.
- An INVALID metric holds until the next commit restarts the suite; it says to look at the host, not the collector.
