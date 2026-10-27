# 0024 — Boot the range VM with four vCPUs

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-27
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

The range VM has had 2 vCPUs (`-smp 2` in `qemuArgv`) since it was built; no ADR chose the number. On them the
generator and the recorder together saturate the CPUs: rate-sustained generated 889 009 of 1 200 000 execs (14 173
in the slowest 10 s, want 20 000), and the crash trials of ADR 0023 were INVALID because the rate was not held
before the failure. The judge cannot tell a slow generator from a recorder that holds it back.

One run on 4 vCPUs (c9fdf5e: #135 on `main` with only `-smp 4`): selftest PASS; rate-sustained PASS (1 200 000
stored, 0 missing, window minimum 20 000); rate-burst PASS twice; kill-collector-1 and reset-collector-1 PASS;
cpu-1000 MISS at 0.637 cores. cpu-1000 had passed at 0.468 on 2 vCPUs (ac77232, older collector code): auditd with
Laurel 251 s of CPU instead of 191 s, the collector 132 s instead of 90 s, for the same 600 000 execs. On the same
code (#135 on 2 vCPUs, its identical tree on 4) the collector's CPU in rate-burst rose from 3.45-3.53 s to
4.74-4.94 s (+38 %): the vCPU count alone moves cpu_cores. One run each, a sample, not a spread.

## Decision

1. Every range run (self-test, trials and agent jobs) boots with 4 vCPUs, the smallest count tried that holds the
   trials' load; the memory stays 2048 MiB. 4 is not a model of the reference host, which has more CPUs.
2. cpu_cores keeps its limit and its method (ADR 0023, point 5). Its number depends on the guest's CPUs, so a range
   value says nothing about the reference host until that is decided: whether to bound the recorder's threads
   (GOMAXPROCS or a CPU quota in the units), to measure cpu_cores on the reference host, or to change the limit.
   That is an ADR of its own; until then cpu-1000 is a MISS that blocks the host install like any other.
3. A change of the VM's CPUs changes measured numbers, so it needs an ADR and a KVM run of the suite.

## Alternatives considered

- Stay on 2 vCPUs: generator and recorder share 2 CPUs, so sustained_rate and every crash trial stay undecided.
- The reference host's CPU count: other machines measure differently, and a trial does not need that many.
- Lower rates in the trials: changes acceptance numbers to fit the range (R3).
- Stay on 2 vCPUs for cpu-1000 only: picks the vCPU count by the verdict it gives.

## Consequences

- Amends ADR 0023's consequence that a 2-vCPU VM does not hold 2000/s; the crash trials can now decide.
- The steal limit (1 %) is a share of all vCPU time, idle included, so on 4 vCPUs it allows about twice the steal
  per busy CPU; measured steal is 0.07 %, and contention it misses ends as MISS, not PASS. Kept, watched in the suite.
- Numbers measured on 2 vCPUs (ready_s 7.2 s, refusal_summary_s's 2 ms margin) are measured again on 4.
- `TestQemuArgv` pins `-smp 4`. Before C3 the full suite runs once in KVM on 4 vCPUs from `main`.
