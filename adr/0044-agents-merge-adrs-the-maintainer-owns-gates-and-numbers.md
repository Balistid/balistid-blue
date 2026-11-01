# 0044 — Agents merge ADRs; the maintainer owns the gates and the numbers

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-02
- Decided-by: claude/opus-5.5 (delegated by alex, 2026-11-02)
- Agent: claude/opus-5.5
- Amends ADR 0002 point 2

## Context

ADR 0002 point 2 makes `adr/` a code-owned path, so every ADR waits for the maintainer's approval. On 2026-11-02 the
maintainer delegated the open floor-0 decisions to the agent and asked why ADR pull requests still need him; under
ADR 0042 his approval reads the summary, not the text. An ADR changes no enforcement by itself: gates live in
`tools/ci/`, `.github/` and `githooks/`, numbers in `acceptance/`, the install path in `deploy/` and `packaging/`.

## Decision

1. `adr/` leaves `.github/CODEOWNERS`. A pull request that touches only `adr/` (and `STATUS.md`) merges through
   `balistid-bot` when CI is green, like product code before install (ADR 0015).
2. `Decided-by: alex` only when the maintainer approved that pull request; an ADR merged without him says
   `Decided-by: <agent> (delegated by alex, <date>)`.
3. The gates, the rules (`ENGINEERING.md`, `CLAUDE.md`, `AGENTS.md`), `acceptance/`, `deploy/`, `packaging/` and the
   installed binaries stay owned: an ADR that changes a gate or a number lands with those files and waits for him.
4. The agent reports each ADR it merged to the maintainer the same day: its number, the decision in a sentence, and
   how to revert it (a pull request reverting the file).

## Alternatives considered

- Keep `adr/` owned: approvals of decisions the maintainer delegated, read as summaries anyway.
- A second bot as code owner: it would approve the first bot's gate changes too, which removes the gate.

## Consequences

- An agent can record a decision the maintainer would not take; his same-day report and a revert are the control,
  and nothing it records runs until an owned file changes.
- Fewer approvals: ADR-only pull requests stop waiting; gate, number and install changes do not.
