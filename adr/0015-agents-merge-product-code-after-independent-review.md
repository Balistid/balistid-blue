# 0015 — Agents merge product code after independent review; the maintainer approves gates and the cage

- Status: accepted (narrows the owned paths of ADR 0002, decision 2)
- Date: 2026-10-10
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

Since `a8c3834` (10.10.) the store, shard and raw record packages are owned, so every change to them
waits for the maintainer. On 10.10. that meant four approvals for #86–#89; the defects in those
changes were found by the Opus critic and the Codex queue, not by the approval, which became a stamp.
The threat model assumes an agent that manages Balistid Blue can be compromised (prompt injection
through data), so whatever confines agents or decides what counts as verified must stay behind a human.
The product code reaches the host only through `balistid-install`, which the maintainer runs from a
hash CI printed (R1, R8). `tools/ci/go_gate.py` already requires an owner for every package compiled
into the binaries that form the agents' cage (range, runner) and the CLI; the store, shard and raw
record packages are compiled into none of them (`go list -deps`, 10.10.).

## Decision

1. The maintainer approves (CODEOWNERS): the gates and rules (`tools/ci/`, `.github/`, `githooks/`,
   lint and secret configs, `ENGINEERING.md`, `CLAUDE.md`, `AGENTS.md`, `adr/`, `acceptance/`,
   `THREAT_MODEL.md`), the agents' cage (`range/`, `internal/range*`, `cmd/balistid-range*`,
   `cmd/balistid-runner`), what root installs or the build trusts (`deploy/`, `packaging/`,
   `go.mod`, `go.sum`, `go.work*`), and the CLI (`cmd/balistid`, `internal/buildinfo`).
2. Product code (`internal/rawrecord`, `internal/shard`, `internal/store` and the collector, ledger
   and normalizer packages to come) is not owned. An agent merges it through `balistid-bot` only when
   all hold, and the pull request body records each: CI green on the merged head; a test that fails on
   the parent or under mutation for every behaviour change; review per ENGINEERING.md §5, and for a
   change to durability, a parser of untrusted input or a socket an Opus critic and a Codex queue review
   (level full) with no finding open inside the change after at most two rounds. A NO-GO or a third
   round goes to the maintainer.
3. After such a merge the agent tells the maintainer what merged, the verdicts and how to revert.

## Alternatives considered

- Keep owning the product code (ADR 0002 as extended on 10.10.): a human stamp on changes reviewed
  by two independent reviewers; rejected for the cost and because it did not find the defects.
- Unown the cage as well: an injected agent could loosen the sandbox its jobs run in; rejected.
- Require an approval on every pull request: rejected in ADR 0002.

## Consequences

Product changes merge without waiting; the maintainer sees them in the report and in git, and still
decides what reaches the host at install. A compromised agent can now merge a weaker store, so the
range acceptance runs (T4, T24, R3) and the install hash remain the gates for what is deployed. When
the collector binary is installed by root, its own `cmd/` entry and install path become owned (decision 1),
not the product packages it compiles in. No acceptance number changes.
