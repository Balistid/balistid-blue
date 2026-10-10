# 0014 — Raise the threat model cap to 100 lines

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-10
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

`tools/ci/docs_budget.py` caps `THREAT_MODEL.md` at 80 lines, 9600 bytes (ADR 0001, R12). On
2026-10-10 the file stood at 9599 bytes. R10 asks every boundary to name its row and the tests that
trigger it, yet the runner's new syscall allowlist could not name its tests in row T31 without
rewording other rows. Floor 0 still adds the collector, the ledger and the Pi witness, each with
boundaries of its own. The cap now works against R10 instead of against padding.

## Decision

`THREAT_MODEL.md` may hold 100 lines, 12000 bytes. Every other cap stays, and the file stays one
table of rows.

## Alternatives considered

- Shorten existing rows: each saved byte comes out of a mitigation or a gap, which is what a reader
  of the threat model needs.
- Split the threat model per floor: more files in the docs allowlist and a reader who must open
  several to see one boundary.
- Raise every cap: nothing else is near its limit; ADRs fit 60 lines when written tightly.

## Consequences

Rows can name their tests (R10) as the floor grows. 20 more lines are the whole budget until the
next ADR; a row that needs more is a sign the boundary belongs in its own ADR.
