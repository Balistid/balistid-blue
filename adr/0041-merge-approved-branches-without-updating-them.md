# 0041 — Merge approved branches without updating them

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

The `main` ruleset requires the ten CI checks on a branch up to date with `main` (ADR 0001, 0002 point 3,
ADR 0015 point 2) and dismisses an approval when its branch is pushed (`dismiss_stale_reviews_on_push`,
read 2026-11-01). Together, every merge outdates every other open pull request; updating one is a push,
which drops the maintainer's approval, and the bot may not force-push (ENGINEERING §4), so it reopens the
pull request instead (#176 became #178 on 2026-11-01). Three owned pull requests then cost three approvals,
each after a CI run of about ten minutes, and no work can land while the maintainer sleeps. The approval
still names an exact head; the up-to-date rule adds only that CI ran on the combination with `main`.
`ci.yml` also runs on every push to `main`. The repository is public, so GitHub's merge queue is
available; it would test each combination without touching the approved branch, but needs a
`merge_group` trigger in the workflows and the range-based gates reading the queue's commits.

## Decision

1. The maintainer turns off "require branches to be up to date before merging" in the `main` ruleset.
   Pull requests, code owner review, the ten checks on the head, dismissal of stale approvals, linear
   history, rebase merges and the force-push and deletion blocks stay.
2. The bot merges an approved pull request only when its own checks are green and the last `ci.yml` run on
   `main` is green, one at a time, each after the previous merge's push run is green. A pull request whose
   rebase onto `main` conflicts, which GitHub refuses, is reopened on `main` and approved again.
3. A red run on `main` after a merge stops further merges; the bot opens a revert pull request at once and
   tells the maintainer which merge broke it.
4. The maintainer approves open pull requests in one batch; the bot merges them in the order it states.
5. Next step, its own pull request (workflows are the maintainer's to push): the merge queue, which runs the
   checks on each combination before it lands and so restores what point 1 gives up.

## Alternatives considered

- Keep the rule and reopen each pull request after every merge: one approval per pull request per merge,
  the cost above. Let the bot rebase a branch on GitHub's side: still a push, so the approval is dropped.
- Keep the approval across pushes (no stale dismissal): the bot could add commits after the maintainer's
  look and merge them under it; refused.
- Narrow the code owners to the gates alone: the floor-0 packages are owned on purpose since A7 (ADR 0015
  point 3, `go_gate` roots), and the pull requests that wait today touch `deploy/` or the range judge,
  which stay owned anyway; refused for now.

## Consequences

- Residual: two pull requests each green on their own can break `main` together (a semantic conflict
  without a textual one); the push run catches it after the merge, not before. Until the merge queue,
  `main` can be red between that merge and its revert. Nothing installs from `main` on its own: the host
  takes only what the maintainer installs (R1, R8).
- Amends ADR 0001 (Consequences), ADR 0002 point 3 and ADR 0015 point 2 ("with the branch up to date").
