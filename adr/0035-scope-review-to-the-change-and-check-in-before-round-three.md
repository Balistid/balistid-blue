# 0035 — Scope review to the change's goal; the maintainer decides before a third full round

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-30
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

200 complete Codex reviews in 83 checkpoints (2026-09-30 to 10-30, all repositories) give CRIT and HIGH findings
per review of 2.0 in round 1, 1.3 in round 2, 1.1 in round 3 and 1.0 from round 4 (median 0 from round 3 on);
about three in four of the late ones were acted on with a fix, so a cap on rounds would drop findings that mattered,
as ADR 0033 found. Rounds 2 and later cost 51 % of the Codex window. The share of findings that the previous fix
introduced rises from 4 % in round 1 to 36 % in round 2 and 40-47 % from round 3. The long chains were checkpoints
whose brief asked how an attacker gets past each gate with no bound: on 2026-10-30 a root install helper took
three full rounds against "an agent at the maintainer's uid wants root", which no code can hold while that agent
writes the script the maintainer runs; only the maintainer's reading holds it. Data and scripts are kept outside
the repository (the maintainer's proposals directory, review-rules-20261030).

## Decision

1. The reviewer's threat and criteria name the change's goal: what it must hold, against whom, within which
   threat rows and ADRs. A boundary a person holds (the maintainer reads a script or a diff and confirms) is
   stated as an assumption, not offered as a target; whether that person is shown exactly what runs stays in
   scope, and a missing threat row is still a finding (ADR 0033 point 6). The default brief becomes "what should
   not exist here, and how would you get past each gate this change adds or touches, within its goal".
2. Every fix of a finding carries its own test, and before the fix range goes back the author checks what new
   path the fix opens: a file or directory, a mode or owner, an error branch, a race, a signal.
3. Before a third full round on one checkpoint (reply rounds do not count), the author gives the maintainer the
   open findings with how many the fixes introduced, how many reach beyond the change's goal and how many are CRIT
   or HIGH inside it; the maintainer decides to go on, redesign, or accept the rest as residuals.

## Alternatives considered

- A cap of two full rounds: late rounds still find real defects (above); ADR 0033 rejected a cap for this reason.
- More review per fix (a full round for every fix): rounds 2+ already cost half the window.
- No change: the unbounded brief and fix-introduced defects cost the most rounds of 2026-10-30.

## Consequences

- Amends ADR 0033 point 5 and §5 (the maintainer decides before a third full round), and the default brief in
  CLAUDE.md and AGENTS.md. Outside this repository CODE_POLICY §12 carries the same three rules.
- Measured as ADR 0033: full rounds per checkpoint and the INTRODUCED-BY-FIX share over the next three checkpoints.
