# 0055 — Close each floor with a security audit and a deletion pass

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-03
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-03; the checkpoint is the maintainer's request)
- Agent: claude/opus-5.5

## Context

Floor 0 is done when `acceptance/0.toml` is met (`STATUS.md`). Every pull request is reviewed on its diff only, so
code no diff touches is never asked whether it should exist: on 2026-11-03 the three largest files were 1377, 1254
and 1066 lines (`internal/rangevm/session.go`, `internal/store/store.go`, `cmd/balistid-range-guest/loss.go`), and
54 ADRs were written in five weeks. The same day a review of #199 found leftovers, a duplicate and an unused
parameter in new code. The maintainer asked for one large checkpoint at the end of each floor that looks for holes
and for dead code, overengineering and AI slop. The `/security-audit` skill runs schema-checked security hunters
whose findings are validated as vulnerabilities; it has no place for "this should not exist".

## Decision

1. A floor is done when its acceptance file is met and both passes below have closed on the same commit.
2. Security audit: the maintainer runs `/security-audit` in full audit mode, profile `deep`, over the whole
   repository. Its confirmed findings are fixed or decided before the floor closes; the skill is not changed.
3. Deletion pass: fresh Opus agents, one per subsystem of `README.md`'s repository map, each asked only "what
   should not exist here": dead or unreachable code, duplicates, abstractions with one user, defensive paths for
   states that cannot occur, tests that only restate the code, comments and documents that repeat their source.
   Each returns a diff that only deletes or simplifies, every test still passing and no behaviour changed; an
   Opus critic reviews each diff, and they merge as ordinary pull requests.
4. A deletion that would change behaviour or a gate is not part of the pass; it becomes an issue.
5. Both passes record what they covered and found in the floor's `STATUS.md` entry, and in an ADR only if they decide.

## Alternatives considered

- Security hunters also hunting slop: it dilutes their one question, and their findings schema has no place for it.
- A deletion pass on every pull request: the diff review already asks it of new code; old code needs the floor pass.
- No checkpoint: code no change touches is never reviewed again.

## Consequences

- Floor 0 closes only after both passes; the first runs before the 9.5 install, with the security audit already due.
- The deletion pass costs one agent per subsystem plus a critic per diff; it lowers the cost of every later review.
- Revert: a pull request removing this file.
