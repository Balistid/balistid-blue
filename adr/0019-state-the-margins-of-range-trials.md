# 0019 — State the margins of range trials

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-12
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0018 point 4 asks for the rate "held in every 10 s window" and names controls that must miss or pass, without
saying how a window treats a number that lands a few milliseconds late or how a control's verdict is stored. On an
idle host a sleep that overruns by a scheduler tick put the last number of a window past its end, and a strict
reading gave a false MISS in 8 of 10 burst runs (review of #100, 11.10.); a MISS stands for the commit. A failure
trial can also lose numbers because the host stalled the guest's storage, not because the file system lost data
that was synced.

## Decision

1. A generated number is timed when the call that made it returns. It counts in the 10 s window it was due in if
   it returned at most 100 ms after that window ends, else in the window it returned in, and in none if it returned
   more than 100 ms after the schedule ends, where the generator stops. 100 ms is at most 1 % of a window.
2. A control is judged like any trial of its metric and must give the verdict the trial table expects of it (PASS
   or MISS). Its result is labelled `control` and never counts for the metric; a control that does not give its
   verdict means the measurement is broken, not that the metric failed.
3. A failure trial's fail mark carries S, the highest number its measured writer had written before its last
   fsync returned. A control that must pass with a syncing writer is INVALID when S is below H and every number up
   to S survived: the premise "synced through H" did not hold. A number up to S lost is a MISS.

## Alternatives considered

- The strict window: false MISS from scheduler jitter alone. A wider grace: hides a real shortfall. Storing a
  control's result as its metric's: a working drop control would fail the metric.

## Consequences

- Amends ADR 0018 points 3 and 4. `acceptance/0.toml` states the 100 ms in the `sustained_rate` method, which
  `burst_rate` inherits; no number changes.
- Tests: a number returning exactly 100 ms late counts, 1 ms more does not; a control drop gives MISS; a sync
  control with S below H and nothing up to S lost is INVALID.
