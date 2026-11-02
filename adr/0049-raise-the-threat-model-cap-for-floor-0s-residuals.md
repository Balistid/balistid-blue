# 0049 — Raise the threat model cap for floor 0's residuals

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-03
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

The residual triage of 2026-11-02 (issues #196-#213) found accepted design limits that no `THREAT_MODEL.md` row
states: A1 or A2 silencing the alert path (ADR 0034), local mode against root (0043), A2 flushing the relay-only
table (0032), a dead disk alarming only by silence (0017), and the status report's exposure and 5 s window (0048).
The file stands at 12000 bytes, its cap since ADR 0014, which rejected shortening rows because each saved byte
comes out of a mitigation or a gap, and said growth past 20 more lines needs the next ADR.

## Decision

`THREAT_MODEL.md` may hold 110 lines, 13200 bytes. The limits above go into the rows they belong to (T11, T12,
T21, T27, T28), not into new rows; every other cap stays, and the file stays one table.

## Alternatives considered

- Shorten other rows (T34's test list is the longest): it removes the test names R10 asks a row to carry.
- New rows T38-T42: five rows for limits that already have a row each.
- Keep them only in ADRs and issues: a reader of the threat model would not see them.

## Consequences

About 1100 bytes stay for floor 0's remaining rows (9.5, L12). A limit that does not fit its row belongs in an ADR.
