# 0057 — Judge steal per second, only against a MISS

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-03
- Decided-by: alex (2026-11-03: steal decides only a MISS, per-second windows); claude/opus-5.5 the rest
- Agent: claude/opus-5.5
- Amends ADR 0018 point 4 (guest steal), ADR 0023 point 5 (cpu_cores) and the steal note of ADR 0024.

## Context

Rate and CPU trials made a run INVALID when guest steal exceeded 1 % of the ticks summed over the load, and for rate
trials over a part of the drain. A sum dilutes: one second at 2 % hides in 600 clean ones, and splitting the drain
into parts only moved the seam (#228, #229: three review rounds, each fix opening the next path). Steal can only make
a run worse: records lost, a rate not held, more CPU µs; never fewer losses or less CPU (ADR 0024: contention the
guard misses ends as MISS, not PASS). Yet the guard also voided PASSes, so on GitHub's runners rate-burst,
rate-sustained and cpu-1000 were INVALID on steal alone (#229, #233).

## Decision

1. The guest reads `/proc/stat`'s cpu line just before the load and every second until its store read ends (rate)
   or the drain is over (CPU), and once more at the end. It reports `steal_windows`: for each span between two reads,
   `ms:total:steal` (wall ms on the monotonic clock, all CPUs' ticks, steal ticks), comma-separated. The sums
   `cpu_ticks`, `steal_ticks` and the drain's parts are gone.
2. The judge reads every span. A span with more than 1 % of its ticks stolen, one of 1 s or more without ticks, or
   one over 2 s (seconds not measured) means host steal may have caused a MISS: the run's MISS becomes INVALID. A
   PASS stands.
3. A series not of that form, a span with more steal than ticks, over 4096 spans or covering less than the load's
   seconds is INVALID whatever the verdict.

## Alternatives considered

- Sums over the load and drain parts: dilute (Context).
- Steal against PASS as well: throws away a run that held its metric under harder conditions, and keeps the GitHub
  trials INVALID.
- The guest reporting only its worst second: the judge would trust the guest's choice instead of reading the seconds.

## Consequences

- One stolen second makes a MISS INVALID; three INVALID runs still make a MISS that stands (ADR 0021).
- A guest can turn a MISS into INVALID with false spans, as it could with false sums; it cannot make a PASS.
- 1 % of a second on 4 vCPUs is 4 ticks; noisy hosts give more INVALID MISSes, never more PASSes.
- Revert: a pull request removing this file and restoring the sums in the guest, the judge and `acceptance/0.toml`.
