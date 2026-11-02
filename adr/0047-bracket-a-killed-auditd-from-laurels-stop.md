# 0047 — Bracket a killed auditd from Laurel's stop

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-02
- Decided-by: alex
- Agent: claude/opus-5.5
- Amends ADR 0039 points 3 and 5

## Context

ADR 0039 point 5 brackets the four auditd crash trials from the SIGKILL to auditd's exit. With Laurel stopped,
auditd's plugin queue drops the flood's events before the kill (overflow_action = SYSLOG, audisp queue), so the
loss begins up to the flood's length earlier than that bracket: an alert at 65 s from the kill can be over 65 s
from the first dropped event, which the judge would pass (review of #193). The kill alone also does not prove
that the queue overflowed: the execs can finish while auditd has not yet read their records.

## Decision

1. The crash bracket runs from just before the guest stops Laurel, the earliest moment the plugin queue can drop
   an event, to auditd's exit seen through its pidfd. `first_unknown` counts from the same moment in the ledger's
   clock (point 3), so an UNKNOWN from before the stop is "before N" and leaves the alert unattributed.
2. The overflow is proven before the kill: auditd's own journal line "queue to plugins is full" after a cursor
   taken before the stop (unit, executable and uid set by journald), within 3.5 s of the fresh state write; then
   a whole read of the state file still "no" in that generation, before auditd's next write. Without both, or with
   auditd already gone before the signal, the run is INVALID.

## Alternatives considered

- The journal line's timestamp as the bracket's start: wall clock from syslog, T22; the stop's uptime is the
  guest's own clock and can only widen the bracket.
- `auditctl -s` backlog near 0 before the kill: shows auditd read the records, not that its queue dropped them.

## Consequences

- A wider bracket makes a run INVALID sooner, never a false PASS; the measured delays (0.8 to 2.6 s from the kill
  on GitHub's KVM) leave the 65 s window wide open.
- Residual: the ledger's reason 10 covers both "auditd down" and "restarted", so the trial cannot require the new
  pid's UNKNOWN specifically; the guest requires a new active MainPID instead.
