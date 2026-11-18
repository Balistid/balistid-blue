# 0078 — The judge re-anchors on the runner's newest result

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-18
- Decided-by: jvc0n (2026-11-18, in session)
- Agent: claude/opus-5.5
- Amends ADR 0077 points 4, 6 and 8 (the rule's scope, the anchor, what stays open) and `acceptance/1.toml`.

## Context

ADR 0077 anchored `verify` on the runner's result `20261116T163124Z-ba1549c1-p0-smoke-1` and built the judge's
fixtures from its window; neither was copied anywhere. A kernel and systemd upgrade was followed by a reboot on
2026-11-17 at 17:18; from 17:28 the runner took again, one per tick up to its quota, 24 job directories left in the
inbox since October, and the 24 newest results it keeps no longer held the anchor. The runner knows a directory by
name, device and inode and forgets a job it took after 30 days; the inbox's device number is anonymous, so after
this boot (not the one of 2026-11-15) each old directory read as new (inferred: the old number was not recorded).
p0-smoke-1, taken the day before, was not taken again; the quota stopped the other 11. `verify` as written can never
pass, and the fixtures' window is gone. Review of ADR 0077 also found its point 4 leaves the scope of `all` open.

## Decision

1. The anchor of ADR 0077 point 6 is `20261117T222824Z-cf92a4e6-pr13-run-d4`: the newest result when the
   maintainer moved every directory out of the inbox, before this is merged and before any tick could take a job.
   The pilot ends 23 jobs after it; a result before it is not the pilot's and no window may hold one.
2. The runner's store decides and `verify` reads it; git and the maintainer's backup hold copies. Before it puts a
   job in the inbox the session checks that the inbox holds only pilot jobs younger than 30 days (the runner takes a
   name once within that time), that the newest result is the one it expects, and that every result after the
   anchor is imported and pushed. Skipping a check gains nothing: a result pushed out fails `verify`. The inbox is
   emptied at the pilot's report.
3. The fixtures' base window (`acceptance/1.toml`, `invalid_never_counted`) is that of the result
   `20261117T164346Z-4e1197c7-hard-exec-1` (kind exec, RAN, image 2c09799; `job-laurel.txt` sha256
   `499fdf58a43fcabac45125d1823e306e4a582b63bb0eccc3d6b66ebe63087801`, `result.json` sha256
   `595cfffa9175728a60fc9c16892b2619dab226534dcdf5f430a8ea9bc539131c`). Its records are decoded under
   `internal/detect/testdata`; a test escapes them back and compares the first sha256, so the base cannot be
   edited; the second records which result was used, as the test builds the result at runtime.
4. A rule is judged on one event: a window matches when one event of the job's uid satisfies the whole `all` or
   `any`; a step on a list lets each leaf take its own element. An `all` whose leaves match only on different
   events must not match (`acceptance/1.toml`, `control_empty`).
5. There is no third anchor. If this one is lost, `windows_match_originals` is missed and, as `acceptance/1.toml`
   says of any missed metric, the pilot's report is blocked.
6. ADR 0077 point 8 adds: any 24 results from any inbox job drop the anchor; a directory left in the inbox over 30
   days can run again after a reboot that changes the inbox's device number (issue #295, a runner defect, not fixed
   in the pilot, which changes no runner).

## Alternatives considered

- A new job as anchor and fixture base: it adds nothing the existing exec result lacks, cannot run before the quota
  frees and spends one of the pilot's jobs.
- Fix the runner's key now: it needs a runner install as root, outside the pilot's limits.
- `verify` checks the inbox: it sees the inbox at signing, not what ran before; a lost result already fails it.

## Consequences

- The methods of `acceptance/1.toml` name this ADR and the new base; no number changes. T38 points here.
- The 24 re-run results and the 36 inbox directories stay in the maintainer's backup, outside the repository.
- Revert: one pull request; reverted, `verify` cannot pass, as on the day this was written.
