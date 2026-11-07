# 0063 — Name the maintainer by handle

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-07
- Decided-by: jvc0n (2026-11-07: his handle in the repository, never his name)
- Agent: claude/opus-5.5
- Amends ENGINEERING.md (its header and R11) and ADR 0044 point 2.

## Context

The repository is public. Its rules and records named the maintainer by first name: R11's trailer value, the
`Decided-by:` line of the ADR template and of 60 ADRs, and `tools/ci/commit_lint.py`. Commits are already authored
as `Jvc0n`. The maintainer asked that the repository carry his handle and not his name.

## Decision

1. The maintainer is `jvc0n` wherever the repository names him: the `Agent: jvc0n` trailer (R11), `Decided-by: jvc0n`,
   and the delegation line of ADR 0044 point 2.
2. `commit_lint.py` accepts `Agent: jvc0n` and refuses the old value for every new commit.
3. Every commit of a pull request is authored and committed under a GitHub noreply address or GitHub's own
   committer: `commit_lint.py --range` refuses any other, without printing it.
4. History is not rewritten: commits and earlier versions of these files keep what they said, as ENGINEERING.md 4
   allows no force-push to `main`.

## Alternatives considered

- Rewrite history: a force-push to `main`, which ENGINEERING.md 4 forbids, and forks and caches would keep it anyway.
- `the maintainer` in every line: it reads well in prose but is no value a trailer or `Decided-by:` can check.

## Consequences

- Every ADR and rule names the maintainer by handle; a test refuses the old trailer, another a personal address.
  The maintainer's account blocks pushes that expose his address (GitHub's email setting), the source of the old ones.
- The old name stays in git history and in earlier pull request texts.
