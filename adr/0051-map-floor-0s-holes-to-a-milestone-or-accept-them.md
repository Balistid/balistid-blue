# 0051 — Map floor 0's holes to a milestone or accept them

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-03
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-02)
- Agent: claude/opus-5.5

## Context

`THREAT_MODEL.md` has 28 rows marked `partial` or `gap`. The maintainer set the critical path on 2026-11-02: the
product must install, and each hole either blocks that or does not. The issues of the residual triage (#196-#213)
carry no milestone, and no file says which holes 9.5 closes and which floor 0 keeps for good. ADR 0014 and 0049
keep the threat model one table with a byte cap, so the map lives here, not in its rows.

## Decision

1. Each hole closes at one milestone, or is accepted for floor 0: it stays `partial` or `gap`, the ADRs named below
   are its acceptance, and only a new ADR reopens it. A row named in two lines below has two parts.

   | Closes at | Rows (issue or ADR) |
   |---|---|
   | 9.5 | T8's x32 ABI (#197), T9's signed manifests (#196); in part T4's alarm delivery (#204), T11's local mode (#203), T25's dead Laurel (#198) |
   | L12 | T12 (#210), T14's quiet cap (#210), T16 on the real Pi (#210), T21's Pi side and IPv6 (#210), T27's dead-man (#209) |
   | floor 1 | T6 with the normalizer (#205), T8's interpreters, mmap exec, envp and truncated argv (#211), T32 (#212) |
   | accepted | T2 (#207, 0027), T3 (0004), T4's kernel overflow (0038), T10 (#170, 0013, 0016), T11's host CLI (0048), T13 and T15 (0040 point 3), T14 beyond the cap, T16 and T18 (0026, 0031, 0038), T19 (0027, 0029, 0030), T21's flush by A2 (0032), T22 (0029), T23 (0004), T25 (0016, 0022), T27's channel holder (0034), T28 (0017, 0030), T29 (0003), T31 (0009, 0011), T33 (0009, 0018), T34 (0010), T36 (0011, 0022, #123), T37 (0028) |

2. T6 closes in the checkpoint that ships the normalizer: without it no derived database exists. If the normalizer
   moves into 9.5, #205 moves with it.
3. Milestones on the issues: 9.5 for #196-#204, #213 and #219; L12 for #209 and #210; floor 1 for #205, #211 and
   #212. `residual` marks only an accepted limit. #206, #207 and #208 close, fixed by #216, #217 and #218.
4. A pull request that adds a `partial` or `gap` row names its milestone or its acceptance.

## Alternatives considered

- The map in `STATUS.md`: it sits at its 40-line cap, and the map outlives a session.
- A milestone column in the threat model: about 900 more bytes against the 600 that ADR 0049 left.
- Closing the accepted holes before 9.5: most are root on the host (A2) or a development tool's DoS, which floor 0
  cannot stop without the witness; the product claims only what ADR 0040 point 3 states.

## Consequences

- Of the 28 holes, two block 9.5 in full: T8's x32 ABI and T9's signed manifests. T9 needs the maintainer's
  hardware key (R2), and no ADR has picked one yet. 9.5's other blockers are metrics (#198-#204, #213, #219).
- T33's `gap` predates ADR 0011 and 0018 (evidence only from the runner); its status word is corrected the next time
  the threat model changes, with the maintainer's approval.
- Revert: a pull request removing this file; the issues' milestones change by hand.
