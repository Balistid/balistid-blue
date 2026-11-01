# 0041 — Merge through a merge queue and list the fuzz targets from the source

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
update, the queue tests a group commit on top of the target branch with the queued changes ahead of it, rebase
is one of its methods, and a workflow must listen to `merge_group` or its required checks never report and the
merge fails. They do not say whether the up-to-date rule may stay on beside the queue (a third-party report
quotes GitHub support as "you should not combine" them), or whether `main` ends at the tested commit itself.

## Decision

1. `ci.yml` runs on `merge_group` (`checks_requested`): every job on the group commit, `range-kvm` too
   (5 minutes on 2026-11-01). docs-budget and commit-lint check the group's `base_sha..head_sha`
   (`tools/ci/change_range.py`). A group's commits get the Dependabot exemption as a push's: they entered the
   queue only after their pull request's commit-lint, a required check, passed with the author GitHub reported.
2. In one ruleset change the maintainer adds "Require merge queue" (method rebase, build concurrency 1, merge
   limits of one pull request, only non-failing pull requests, a 60-minute check timeout) and turns the
   up-to-date rule off: the group commit carries every change queued ahead, so it is the tree that lands, which is
   what that rule gave. Required checks, code owner review and dismissal of stale approvals stay. The bot queues
   a pull request under the conditions it merges one under today (ADR 0002, 0015); owned paths still wait for the
   maintainer's approval.
3. Until the queue is on, the bot may rebase an approved pull request on GitHub only when
   `git patch-id --verbatim` of `origin/main...head` equals the approved diff's (plain patch-id ignores
   whitespace, which changes Python) and every commit carries `Agent:`, then merges with that head as the
   expected sha. The rule ends when the queue is on.
4. `fuzz.yml` takes its matrix at run time from `tools/ci/fuzz_matrix.py`, code-owned: every top-level
   `func FuzzXxx(*testing.F)` in the tracked `*_test.go` files, outside the directories `./...` skips; the
   minutes rule (ADR 0016) lives there. It reads source and runs no project code, so a package cannot write the
   job's output or another package's rows. An unusable package path, a duplicate or an empty list fails the
   run, and so does a row that fuzzes nothing: a job passes only when go passed and printed the fuzzer's
   progress. Values reach the shell only through `env`; selftest runs the script on every pull request.

## Alternatives considered

- Keep the listed matrix with a test against the source: correct, but each target still needs the maintainer.
- `go test -list` (the compiler's listing): it runs every package's test binary in the job that writes the
  matrix, so a package the bot merges alone could rewrite it (critic, 2026-11-01).
- Drop the up-to-date rule without a queue (a draft withdrawn after a critic's NO-GO): untested combinations land.
- Give the bot the workflows permission: it could change the gates' own workflows (ADR 0002).

## Consequences

- A `Fuzz` declaration the scan cannot read stops the run; a false row (a raw string) fails its job. A package's
  own test code (`TestMain`, an empty fuzz body) decides what its own job proves, never another package's rows.
- CI runs on the group commit and again on `main`; a queued merge waits for the slowest job (`range-kvm`, 0028).
- The first merges through the queue, one alone and two queued together, check what the docs do not say: that a
  pull request enters without a branch update, that the group's commits are its own rebased (commit-lint refuses a
  merge commit), and that `main`'s new head is the group's `head_sha` or has its tree (`git diff` empty). Any
  one false: the queue goes off, the up-to-date rule back on, and this ADR is reopened (also the rollback).
- T29 is unchanged: Go gates run on the head tree, and the group's head is the tree that lands.
