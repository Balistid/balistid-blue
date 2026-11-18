# 0078 — The judge anchors on a result held in two places

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-18
- Decided-by: jvc0n (2026-11-18, in session)
- Agent: claude/opus-5.5
- Amends ADR 0077 points 4, 6 and 8 (the rule's scope, the anchor, what stays open) and `acceptance/1.toml`.

## Context

ADR 0077 anchored `verify` on the runner's result `20261116T163124Z-ba1549c1-p0-smoke-1` and built the judge's
fixtures from its window. Neither was copied anywhere. The host rebooted on 2026-11-17 at 17:18; from 17:28 the
runner took again, one per tick up to its quota, 24 job directories left in the inbox since October, and the 24
newest results it keeps no longer held the anchor. The runner knows a directory by its name, device and inode; the
inbox's device number is anonymous and may change at boot (not proven: the old number was not recorded), and the
runner forgets a job it took after 30 days, so each old directory read as new. Its ledger held the rest: p0-smoke-1,
taken the day before, did not run again. `verify` as written can never pass, and the fixtures' window is gone.

The assumption that failed was not about what an agent can move: the anchor, the fixtures and the next step all
rested on one uncopied file in a ring of 24 that any directory in the inbox can turn over.

## Decision

1. The anchor of ADR 0077 point 6 is `20261117T222824Z-cf92a4e6-pr13-run-d4`, the newest result once the
   maintainer had moved every directory out of the inbox, before any tick could take a job. The pilot ends 23 jobs
   after it; a result before it is not the pilot's and no window may hold one.
2. Git is the record, the runner's store only what `verify` compares it with. Before it puts a job in the inbox, the
   session checks that the inbox holds only pilot jobs younger than 30 days (the runner takes a name once within
   that time), that the newest result is the one it expects, and that every result after the anchor is imported and
   pushed. The inbox is emptied at the pilot's report.
3. The fixtures' base window (`acceptance/1.toml`, `invalid_never_counted`) is that of the result
   `20261117T164346Z-4e1197c7-hard-exec-1` (kind exec, RAN, image 2c09799): its records decoded under
   `internal/detect/testdata`, its result and keys built at test time, as before.
4. A rule is judged on one event: a window matches when one event of the job's uid satisfies the whole `all` or
   `any`; a step on a list lets each leaf take its own element. A fixture splitting a match across two events must
   not match.
5. If the anchor is lost again after a pair has run, there is no third: the report says `verify` failed and counts
   its windows as unverified.
6. ADR 0077 point 8 adds: any 24 results from any inbox job drop the anchor, and `verify` then fails; a directory
   left in the inbox over 30 days can run again after a reboot (a runner defect, filed as an issue, not fixed in the
   pilot, which changes no runner).

## Alternatives considered

- A new job as anchor and fixture base: it adds nothing the existing exec result lacks, cannot run before the quota
  frees and spends one of the pilot's jobs.
- Fix the runner's key now: it needs a runner install as root, outside the pilot's limits.
- `verify` checks the inbox: it sees the inbox at signing, not what ran before; stray results already fail it.

## Consequences

- `acceptance/1.toml` names this ADR and the new base; no number changes. T35 and T38 point here.
- The 24 re-run results and the 36 inbox directories stay in the maintainer's backup, outside the repository.
- Revert: one pull request; reverted, `verify` cannot pass, as on the day this was written.
