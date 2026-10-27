# 0024 — Boot the range VM with four vCPUs

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-27
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

The range VM has had 2 vCPUs (`-smp 2` in `qemuArgv`) since it was built; no ADR chose the number. On them the
guest cannot make the load the trials ask for: rate-sustained generated 889 009 of 1 200 000 execs (14 173 in the
slowest 10 s, want 20 000), and the crash trials of ADR 0023 were INVALID because the rate was not held before the
failure. Those verdicts measured the range, not the recorder; the sustained_rate question waited for a 4 vCPU run.

That run (2026-10-27, `main` with only `-smp 4`): selftest PASS; rate-sustained PASS (1 200 000 stored, 0 missing,
window minimum 20 000); rate-burst PASS twice; kill-collector-1 and reset-collector-1 PASS; cpu-1000 MISS at 0.637
cores. On 2 vCPUs cpu-1000 had passed at 0.468: for the same 600 000 execs auditd used 251 s of CPU instead of 191 s
and the collector 131 s instead of 90 s. One run each, so the numbers are a sample, not a spread.

## Decision

1. The range VM boots with 4 vCPUs for the selftest and every trial; the memory stays 2048 MiB.
2. cpu_cores keeps its limit and its method (ADR 0023, point 5). Its MISS on 4 vCPUs is a finding about the
   recorder, open in STATUS: whether the limit, auditd's own cost (about 0.42 cores alone at 1000 execs a second)
   or the method has to change is decided on the suite's numbers, by an ADR of its own.
3. A change of the VM's CPUs changes measured numbers, so it needs an ADR and a KVM run of the suite.

## Alternatives considered

- Stay on 2 vCPUs: the generator, not the recorder, decides sustained_rate and every crash trial.
- vCPUs from the host's count: the same commit would measure differently on another machine, and the reference
  host has more CPUs than a trial needs.
- Lower rates in the trials: changes acceptance numbers to fit the range (R3), and hides the load the host sees.
- Stay on 2 vCPUs for cpu-1000 only: picks the vCPU count by the verdict it gives.

## Consequences

- Amends ADR 0023's consequence that a 2-vCPU VM does not hold 2000/s; the crash trials can now decide.
- cpu_cores MISSes until its own decision, so the host install (9.5) waits for it as for every metric.
- `TestQemuArgv` pins `-smp 4`. Before C3 the full suite runs once in KVM on 4 vCPUs from `main`.
