# 0046 — Budget stress CPU at one core, typical CPU at a twentieth

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-02
- Decided-by: alex (approves this pull request; drafted by the agent on his delegation, 2026-11-02)
- Agent: claude/opus-5.5
- Amends ADR 0040 point 4 (the CPU bar) and its consequence that CPU decides before more Pi work

## Context

ADR 0040 put both stress and typical CPU at 0.5 cores. `cpu_cores` runs 1000 execs a second for 600 s, a heavy
parallel build. No host measurement exists yet (ADR 0025: it runs after the install). The range VM (4 vCPUs) on
the reference host gave 0.63-0.70 for the collector and auditd with Laurel, auditd with Laurel alone 0.39-0.46; the
host adds every other floor-0 unit (auditstat, ledger, relay, litewitness, balistid-pi) and more CPUs, which raised
the VM's figure 36 % from 2 to 4.
So the next step under 0.5 was an own audit netlink reader (weeks). On GitHub's KVM (exp commit 3da7f84 with a CPU
profiler on, one run each) the cost follows the rate: 0.046 cores at 50 a second, 0.133 at 200, 0.725 at 1000.

## Decision

1. `cpu_cores` (1000 execs a second) at most 1.0 core: a product choice, about 3 % of the reference host's 32
   cores for a heavy build, not headroom measured on it. ADR 0025 refused a new limit without a host number; this
   one is set before it, and the host's first measurement over 1.0 reopens point 3 instead of taking units down.
2. `cpu_cores_typical` (mean over each day of normal use) at most 0.05 cores: the bar a user sees.
3. The data source stays auditd with Laurel for floor 0 (ADR 0004). An own netlink reader is reopened only if
   `cpu_cores_typical` misses on the host, or `cpu_cores` passes 1.0 there.

## Alternatives considered

- A lower stress rate (200 a second) at 0.5: it passes, but stops measuring the heavy build that exists.
- The own netlink reader now: weeks of a new sensor (R9) for a stress bound, before any host number.
- Keep 0.5 for both: blocks the install on a number auditd alone nearly fills in the VM.

## Consequences

- This is a weakening of the stress bound: a flood of execs (T20) may cost up to one core before `cpu_cores`
  misses. T20's controls are the caps and summaries, not the CPU bound; its row names the metric, not the number.
- The 0.05 typical bar is inferred from one run at 50 a second (0.046) and the scaling, not from a real day; the
  seven days on the host decide it, and a miss reopens point 3. Laptop-class machines may run closer to it.
- The range's cpu-1000 trend now reads green up to 1.0: a regression shows in its result line, not as red.
- Floor 0 no longer waits on a sensor rewrite; the collector's cheap fixes (about 30 % of its CPU) are margin.
- `acceptance/0.toml`: `cpu_cores` max 1.0, `cpu_cores_typical` max 0.05; methods unchanged.
