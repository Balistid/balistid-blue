# 0041 — Merge through a merge queue and let the compiler list the fuzz targets

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

`fuzz.yml` listed every fuzz target by hand, and only the maintainer pushes `.github/` (the bot has no
workflows permission, ADR 0002): each new `Fuzz` function cost a push by hand. The `main` ruleset requires
up-to-date branches and dismisses approvals on push, so every merge sent the other pull requests back to a
rebase; on 2026-11-01 the maintainer let the bot rebase an approved branch on GitHub when the diff's patch-id
stays the same (#180). GitHub's merge queue docs (read 2026-11-01): a queued pull request needs no branch
update, the queue tests a group commit on top of the target branch, rebase is one of its methods, and a
workflow must listen to `merge_group` or its required checks never report and the merge fails. Unverified:
whether `main` then points at the tested commit itself or at a rewritten commit with the same tree.

## Decision

1. `ci.yml` runs on `merge_group` (`checks_requested`): every job on the group commit, `range-kvm` too
   (5 minutes on 2026-11-01). docs-budget and commit-lint check the group's `base_sha..head_sha`
   (`tools/ci/change_range.py`). A group's commits get the Dependabot exemption as a push's: they entered the
   queue only after their pull request's commit-lint, a required check, passed with the author GitHub reported.
2. The maintainer adds "Require merge queue" to the `main` ruleset: method rebase, build concurrency 1, groups
   of exactly one pull request (each tested alone on what lands before it, as the up-to-date rule did), only
   non-failing pull requests, a 60-minute check timeout. Required checks, code owner review, up-to-date
   branches and dismissal of stale approvals stay. The bot queues a pull request under the conditions it
   merges one under today (ADR 0002, 0015); owned paths still wait for the maintainer's approval.
3. Until the queue is on, the bot may rebase an approved pull request on GitHub only when the patch-id of
   `origin/main...head` equals the approved diff's and every commit carries `Agent:`, then merges with that head
   as the expected sha. The rule ends when the queue is on.
4. `fuzz.yml` takes its matrix at run time from `go test -list '^Fuzz' -json ./...` on the commit it fuzzes,
   through `tools/ci/fuzz_matrix.py`; the minutes rule (ADR 0016) lives there, code-owned. A failed build, a
   name that is not a plain identifier, a duplicate or an empty listing fails the run. Values reach the
   shell only through `env`.

## Alternatives considered

- Keep the listed matrix with a test against the source: correct, but each target still needs the maintainer.
- Scan `*_test.go` with a regular expression (the old test): misses build constraints and odd formatting;
  the compiler's listing is what `go test -fuzz` runs.
- Drop the up-to-date rule (a draft withdrawn after a critic's NO-GO): untested combinations would land.
- Give the bot the workflows permission: it could change the gates' own workflows (ADR 0002).

## Consequences

- Each merge runs CI on the group commit and again on `main`; a queued merge waits about as long as the
  slowest job. `range-kvm`, once required (ADR 0028), runs in the queue as well.
- After the first merge through the queue the maintainer checks that `main`'s new head is the group's
  `head_sha` or has its tree (`git diff` empty); otherwise the queue is turned off and this ADR reopened.
- T29 is unchanged: Go gates run on the head tree, and the group's head is the tree that lands.
- Rollback: turn the queue off in the ruleset; a revert of this change restores the listed matrix.
