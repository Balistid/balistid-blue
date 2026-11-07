# 0064 — Install the recorder before widening floor 0

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-07
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-07: install first and narrow ADR 0060, decided in session)
- Agent: claude/opus-5.5
- Amends ADR 0060 points 1 and 2.

## Context

Floor 0 has run since 2026-09-30: 779 commits, 62 ADRs, about 28 000 lines of Go beside 32 000 of tests and 7 000 of
Python in `tools/ci`, 17 open issues under the 9.5 and floor-0 milestones (git and gh on 2026-11-07). The recorder has
never run on a real host: everything is proven in the range, and the host's runner is still at 2c09799 (#238 waits).
ADR 0060 closes on floor 0 every hole floor 0 can close, however long it takes; each measurement can name another
(on 2026-11-06, #245 turned into ADR 0062's new loss stage, its Pi decoding and a new acceptance number). The scope
has no end the product bar of ADR 0040 point 4 would set.

## Decision

1. The next milestone is 9.5: #238 installs the runner, then the recorder, on the maintainer's host, and it runs
   there for 7 days (#201). Until then floor 0 takes no new scope.
2. Before that install a hole closes on floor 0 only when it lies on the install path, on ADR 0040 point 4's product
   bar, or costs under a day. Every other one goes to the milestone `after-install` and is decided with the host's
   7 days of data, not from the range alone. ADR 0060 point 1's rule applies again after install.
3. The map, replacing ADR 0060 point 2 until install:

   | Milestone | Issues |
   |---|---|
   | 9.5, before install | #196 and #238, #197 (x32 as a named, visible gap), #199, #200, #201, #202, #203, #204, #213, #244, #252, and #243's refusal of btrfs |
   | after-install | ADR 0062's stage 9 (#245; the decision stands), #246, #247, #248, #243's filesystem of its own (optional by ADR 0040 point 4) |

4. ADR 0055's deletion pass also folds the ADRs on review, merge, CI and approval into `ENGINEERING.md` and marks
   them superseded, so a reader of the rules reads one file.

## Alternatives considered

- Keep ADR 0060 as it is: each range measurement adds work before any user, the pattern K1's 40-pull-request
  limit (ADR 0040 point 5) is there to stop.
- Install with every hole open: the install path and the product bar are what K1 judges, so they stay first.

## Consequences

- T4, T10's own filesystem and T25 stay `partial` until after install; their rows change with the code then.
- The bot moves the issues to the milestones once it has Issues write access; until then this table is the map.
- Revert: a pull request reverting this file; ADR 0060 then applies in full again.
