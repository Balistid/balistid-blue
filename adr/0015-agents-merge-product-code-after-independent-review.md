# 0015 — Agents merge product code until it is installed; the maintainer approves the rest

- Status: accepted (narrows the owned paths of ADR 0002, decision 2)
- Date: 2026-10-10
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

Since `a8c3834` (10.10.) the store, shard and raw record packages are owned, so every change to them
waits for the maintainer. On 10.10. that meant four approvals for #86–#89; the defects in those
changes were found by the Opus critic and the Codex queue, not by the approval, which became a stamp.
The threat model assumes an agent that manages Balistid Blue can be compromised (prompt injection
through data). Ownership holds only per package: any file in a package can change how its tests run
(a `TestMain` that skips them), so owning single files protects nothing (review of this ADR, 10.10.).
`tools/ci/go_gate.py` requires an owner for every package compiled into a binary root installs; the
store and shard packages are compiled into none (`go list -deps`, 10.10.). The ruleset requires all
ten CI checks on an up-to-date branch (read 10.10.).

## Decision

1. The maintainer approves everything CODEOWNERS lists: the gates and rules, the agents' cage (the
   range and runner packages listed there; a new one is listed before a gated binary imports it,
   which go_gate enforces), what root installs or the build trusts (`deploy/`, `packaging/`, Go module
   files), the CLI and the record format package `internal/rawrecord`.
2. `internal/store`, `internal/shard` and the collector and normalizer packages to come are not owned
   while no binary root installs compiles them.
   An agent merges them through `balistid-bot` when CI is green on the pull request head with the
   branch up to date, which the ruleset enforces. By the agent's own word, recorded in the pull request
   body: every behaviour change has a test that fails on the parent or under mutation, and for a change
   to durability or a parser an Opus critic and a Codex queue review (level full) leave no finding open
   inside the change within two rounds; otherwise the maintainer decides. After the merge the agent
   reports what merged, the verdicts and how to revert.
3. Before the first binary root installs compiles them (the collector), these packages are owned again,
   their whole source gets one independent review (ultrareview or an Opus critic over the packages, not
   a diff), and that binary joins go_gate's `OWNED_ROOTS`, which first needs go_gate to accept the
   pinned SQLite module. The ledger, which signs, is owned from its first commit.

## Alternatives considered

- Keep owning store and shard: a human stamp on changes two independent reviewers had already read;
  rejected for the cost and because it did not find the defects.
- Own single files (the crash test, the format constants) inside unowned packages: protects nothing,
  as the review showed with a `TestMain` that skips the owned test; rejected.
- A required check that reads the reviews' verdicts from the maintainer-side queue: would make
  decision 2 enforced instead of declared; not built yet.

## Consequences

Only "CI green" in decision 2 is enforced. Until decision 3, a compromised agent can merge a weaker
store, shard or collector into `main`, including their tests (T24's crash test) and the shard's schema and size
checks; none of it reaches the host, because nothing installed compiles them, and decision 3 reviews
all of it before it does. THREAT_MODEL T9 notes that sha256 proves CI provenance, not review.
