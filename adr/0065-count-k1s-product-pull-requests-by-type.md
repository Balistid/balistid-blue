# 0065 — Count K1's product pull requests by type

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-07
- Decided-by: jvc0n (2026-11-07: define and count them); claude/opus-5.5 the definition
- Agent: claude/opus-5.5
- Clarifies ADR 0040 point 5; changes no number.

## Context

ADR 0040 point 5 stops the commercial line if K1 has not happened within 40 merged product pull requests from
2026-11-01, but no rule says which pull requests are product ones, and nothing counts them. Of the 45 pull requests
merged from 2026-11-01 to 2026-11-07, 23 were documentation (gh on 2026-11-07); counted by type, 19 were product.

## Decision

1. A K1 product pull request is one merged into `main` from 2026-11-01 whose title, a Conventional Commits subject
   that commit-lint already enforces on commits, has the type `feat`, `fix`, `perf`, `refactor`, `test` or
   `security`, and whose author is not Dependabot. `docs`, `ci`, `chore`, `build` and `revert` do not count.
2. `tools/ci/status.py --prs` shows the count against 40 and warns from 30, so the decision of ADR 0040 point 5 is
   seen coming, not met.

## Alternatives considered

- Count every merged pull request: documentation and CI tuning would spend the budget meant for the product.
- Count by paths (cmd/, internal/, deploy/): the range's code is product-shaped but serves testing; the type is what
  the author already states and commit-lint checks.

## Consequences

- K1 reads "19 of 40" on 2026-11-07. A title's type now carries weight: a product change titled `docs` would hide
  from the count, which review of the pull request sees.
