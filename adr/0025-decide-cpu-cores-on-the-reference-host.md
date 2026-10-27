# 0025 — Decide cpu_cores on the reference host

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-27
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

cpu_cores (`acceptance/0.toml`, max 0.5 cores of all Balistid Blue processes at 1000 records/s) is measured in the
range by cpu-1000 (ADR 0023, point 5). Its number follows the guest's CPUs, not only the recorder: on the same code
the collector's CPU in rate-burst rose by 38 % from 2 to 4 vCPUs, and cpu-1000 gave 0.468 on 2 vCPUs and 0.637 on 4
(auditd with Laurel about 0.42 on both, ADR 0024). The metric's unit is stated for the reference host (32 cores,
`[meta]`), which no vCPU count models. ADR 0024 left cpu-1000 a MISS that blocks the host install; the host install
(9.5) waits for every metric the range measures, so a range MISS of a number the range cannot measure blocks it for
good, and measuring it on the host needs the install first.

## Decision

1. cpu_cores is decided on the reference host after the install, as `healthy_ok` is (ADR 0018): 1000 numbered
   execs a second for 600 s, and the CPU of the recorder's units (the collector's, and auditd's with Laurel, ADR 0023
   point 5) over that time divided by it. A rate not held, a lost record or a restarted unit is INVALID and repeats.
   Who runs the load and computes the binding result is decided in 9.5, as for healthy_ok: a result at the
   maintainer's uid is advisory (T33). The limit 0.5 is unchanged.
2. In the range cpu-1000 is a trend: it runs, is judged and keeps its measures (collector and auditd CPU) like
   any trial, but never decides cpu_cores, never makes it MISS or INVALID, and its MISS does not stand for the
   commit. A rise between two commits is read from two results; no code compares them.
3. The host install's condition "every metric the range measures passes" does not include cpu_cores: it is a metric
   of the reference host, like healthy_ok, loss_per_day and the other seven-day metrics.
4. A MISS on the reference host means floor 0 is not done and the next floor does not start. The running install
   is not taken down for its CPU: the record is worth more than the budget. The fix (a CPU quota or GOMAXPROCS in
   the units, or a new limit through an ADR) is measured again on the host, and cpu-1000 shows its trend first.

## Alternatives considered

- Bound the recorder's threads now: tunes the product to a VM that is not the host, before the host's number exists.
- Change the limit: R3, and there is no number from the host to change it to.
- Keep cpu-1000 deciding cpu_cores: blocks the install on a number of the VM's CPUs, or waits for itself.
- A range VM with the reference host's 32 vCPUs: ADR 0024 rejected it; it is still a VM on a shared host.

## Consequences

- Amends ADR 0023 point 5 (cpu_cores is measured, not decided, in the range) and ADR 0024 point 2 (the decision).
  `acceptance/0.toml` cpu_cores gets this method; its number does not change. T20 names this ADR.
- Risk: auditd with Laurel alone used about 0.42 cores in the range, and the number rose with the CPUs, so a MISS
  on the reference host is likely. That is a reason to measure there before tuning, not to call the range's number
  the host's.
- Code: `rangejob.Trial.Trend`, set on cpu-1000; the runner's suite never decides a metric by a trend and lists only
  the metrics the table decides. Tests: a trend MISS and INVALIDs leave cpu_cores open and keep running.
