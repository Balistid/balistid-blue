# 0057 — Judge steal per second

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-03
- Decided-by: alex (2026-11-03: per-second windows, no sums; steal voids PASS and MISS alike); claude/opus-5.5 the rest
- Agent: claude/opus-5.5
- Amends ADR 0018 point 4 (guest steal), ADR 0023 point 5 (cpu_cores) and the steal note of ADR 0024.

## Context

Rate and CPU trials made a run INVALID when guest steal exceeded 1 % of the ticks summed over the load, and for rate
trials over a part of the drain. A sum dilutes: one second at 2 % hides in 600 clean ones, and splitting the drain
into parts only moved the seam (#228, #229: three review rounds, each fix opening the next path). Voiding only a MISS
was weighed and refused: the suite reruns INVALID runs (ADR 0021) and decides on the PASSes that follow, so a
collector that loses records in some runs would pass more often the more the host steals, and a load on the host,
which runs QEMU at idle priority, could choose them.

## Decision

1. The guest reads `/proc/stat`'s cpu line just before the load and every second until its store read ends (rate)
   or the drain is over (CPU), and once more at the end. It reports `steal_windows`: for each span between two reads,
   `ms:total:steal` (wall ms on the monotonic clock taken before the read, all CPUs' ticks, steal ticks),
   comma-separated. The sums `cpu_ticks`, `steal_ticks` and the drain's parts are gone.
2. The judge reads every span. A span with more than 1 % of its ticks stolen, one of 1 s or more without ticks, or
   one over 2 s (seconds not measured) makes the run INVALID, whatever it would have given. Its reason names the first
   such span and how many there were; the worst span's share is kept as the measure `steal_worst_ppm`.
3. A series not of that form, a span with more steal than ticks, over 4096 spans or covering less than the load's
   seconds is INVALID.

## Alternatives considered

- Sums over the load and drain parts: dilute (Context).
- Steal voiding only a MISS: biases the suite toward PASS through its reruns (Context).
- The guest reporting only its worst second: the judge would trust the guest's choice instead of reading the seconds.

## Consequences

- On a noisy host more runs are INVALID; a trial with more INVALID runs than its Count makes its metric INVALID,
  never a MISS (ADR 0021). GitHub's runners steal in the first second of a load, so rate trials stay INVALID there.
- The limit is per span between reads, 1 to 2 s, over all vCPUs: 8 stolen ticks split across two spans, or one vCPU
  stolen at 4 %, stay under it. A guest can void a run with false spans, as it could with false sums.
- Stalls that are not steal (a stopped QEMU, host page faults) show only as a span over 2 s or not at all.
- Revert: a pull request removing this file and restoring the sums in the guest, the judge and `acceptance/0.toml`.
