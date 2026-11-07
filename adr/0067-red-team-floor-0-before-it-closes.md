# 0067 — Red-team floor 0 before it closes

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-07
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-07: a red-team pass at the floor-0 checkpoint, decided in session)
- Agent: claude/opus-5.5
- Amends ADR 0055 point 1 for floor 0.

## Context

ADR 0055 closes a floor with a security audit and a deletion pass: both read the code. Floor 0's promise is about
behaviour under attack: every event is recorded or its loss counted, and tampering with the record is detectable
(ADR 0040, 0060, 0061). No pass yet attacks the installed recorder to show that. ADR 0064 puts the install and seven
days on the maintainer's host first, so the attack can run against the real configuration.

## Decision

1. Floor 0 closes after a third pass on the same commit as the other two: a red-team pass whose only goal is to leave
   the record without a trace, run after the seven days of ADR 0064.
2. Two attackers, both only inside the isolated range (ADR 0009, no network out, never another host): Atomic Red Team
   tests for indicator removal and impaired defenses, pinned and reviewed (#212), and one AI agent told to cover its
   tracks as root and as an unprivileged uid, against the techniques of ADR 0061 and T3, T4, T8 and T25, and to
   rewrite history the witness cosigned (T12).
3. The pass succeeds when every attempt leaves a record or a counted loss, or is refused where the threat model says
   so; each attempt that does neither is a finding, fixed or decided before the floor closes like an audit finding.
   The pass writes what it tried and what it found into the floor's `STATUS.md` entry and an issue per finding.

## Alternatives considered

- Atomic Red Team alone: its tests are known in advance; an agent told to cover its tracks tries what no list holds.
- An attack on the maintainer's host: a mistake there harms the evidence it tests; the range keeps the attacker caged.

## Consequences

- Floor 0's close needs the range image of the installed commit and a reviewed attack set. It is Balistid Red's
  first task, scoped to floor 0's promise, not to detection (floor 1).
