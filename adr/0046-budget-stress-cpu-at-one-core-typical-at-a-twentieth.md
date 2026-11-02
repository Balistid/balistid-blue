# 0046 — Budget stress CPU at one core, typical CPU at a twentieth

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-02
- Decided-by: claude/opus-5.5 (delegated by alex, 2026-11-02)
- Agent: claude/opus-5.5
- Amends ADR 0040 point 4 (the CPU bar) and its consequence that CPU decides before more Pi work

## Context

ADR 0040 put both stress and typical CPU at 0.5 cores. `cpu_cores` runs 1000 execs a second for 600 s, a heavy
parallel build; there the floor costs 0.63-0.70 cores on the reference host (32 cores) and auditd with Laurel alone
0.39-0.46, so no recorder on auditd fits, and the next step would be an own audit netlink reader (weeks). On
GitHub's KVM (2026-11-02, one run each, exp branch) the cost follows the rate: 0.046 cores at 50 a second, 0.133 at
200, 0.725 at 1000; the collector adds about 0.008 at rest and 0.24 ms per record. The claim the product makes to a
user is "light on a normal machine", which `cpu_cores_typical` measures over seven days on the host.

## Decision

1. `cpu_cores` (1000 execs a second) at most 1.0 core: about 3 % of the reference host, with room over 0.70.
2. `cpu_cores_typical` (mean over each day of normal use) at most 0.05 cores: the bar a user sees.
3. The data source stays auditd with Laurel for floor 0 (ADR 0004). An own netlink reader is reopened only if
   `cpu_cores_typical` misses on the host, or `cpu_cores` passes 1.0.

## Alternatives considered

- A lower stress rate (200 a second) at 0.5: it would pass, but stops measuring the heavy build that exists.
- The own netlink reader now: weeks of a new sensor (R9) for a stress number no user reads.
- Keep 0.5 for both: blocks the install on a number that auditd alone nearly fills.

## Consequences

- Floor 0 no longer waits on a sensor rewrite; the collector's cheap fixes (stat cache, one prepared insert, the
  id without a full Unmarshal, about 30 % of its CPU) are optional margin, in their own pull request.
- The 0.05 typical bar is inferred from the scaling, not measured on a real day yet: the seven days on the host
  decide it, and a miss there reopens point 3.
- `acceptance/0.toml`: `cpu_cores` max 1.0, `cpu_cores_typical` max 0.05; methods unchanged.
