# 0056 — Install 9.5 on the maintainer's host, then a product checkpoint

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-03
- Decided-by: claude/opus-5.5 (the maintainer's decision in a session on 2026-11-03, recorded under ADR 0044)
- Agent: claude/opus-5.5
- Amends: ADR 0040 point 5 (when K1 starts and the 40-pull-request count).

## Context

ADR 0040 point 5 starts K1, two machines of other people for two weeks, as soon as 9.5 passes, and asks for a
decision within 40 merged product pull requests from 2026-11-01. Agents read that as "the installer for strangers
is the goal" and pushed it ahead of everything else. The maintainer said on 2026-11-03 that floor 0 is a base, not
the final product: 9.5 installs on his own host first, and what follows is decided at a checkpoint, with
brainstorming, thinking and research, before more floors are planned.

## Decision

1. 9.5 is the install on the maintainer's host only. Its product bar (ADR 0040 point 4) is measured there; nobody
   else installs floor 0.
2. After 9.5 passes, a checkpoint decides the next direction before any new floor or K1 is planned. It covers three
   parts: technical (what 9.5 on a real host showed, what the next floor needs), reasoning (which threats and holes
   matter next, ADR 0051's map) and product (segment, rivals, the commercial premise of ADR 0040 points 1-3). It
   uses research with sources and a recorded decision (an ADR), not only a plan.
3. The checkpoint ends within two weeks of 9.5 passing, in an ADR that names when and with what the first person
   other than the maintainer installs Balistid Blue, even if the answer is "after floor 1". K1 starts when that ADR
   says; the 40-pull-request count of ADR 0040 point 5 is paused from 9.5 only until that ADR is merged, so the
   guard against building without users (ADR 0040's reason for it) stays. K2 follows K1 as before.
4. Until 9.5, work goes to what the install on the maintainer's host needs (ADR 0051's 9.5 rows, the 9.5 issues),
   not to making floor 0 ready for strangers.

## Alternatives considered

- Keep K1 right after 9.5: it asks strangers to run a base whose next floors are not chosen yet.
- Pause K1 without a date: "we will see" can run for months, the failure ADR 0040 point 5 was written against.
- Drop K1: the commercial premise needs a test with other people; the checkpoint decides when.

## Consequences

- The install documentation and `balistid status` serve the maintainer at 9.5; their stranger-facing form is the
  checkpoint's decision.
- Revert: a pull request removing this file; ADR 0040 point 5 then applies as written.
