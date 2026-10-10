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
through data), so whatever confines agents, decides what counts as verified or encodes an acceptance
number must stay behind a human. `tools/ci/go_gate.py` requires an owner for every package compiled
into the binaries that root installs (range, runner, CLI); the store and shard packages are compiled
into none of them (`go list -deps`, 10.10.). The ruleset requires all ten CI checks on an up-to-date
branch (read 10.10.).

## Decision

1. The maintainer approves everything CODEOWNERS lists: the gates and rules, the agents' cage (the
   range and runner packages listed there; a new one is listed before a gated binary imports it,
   which go_gate enforces), what root installs or the build trusts (`deploy/`, `packaging/`, Go module
   files), the CLI, the record format (`internal/rawrecord`: label, encoding, `MaxBytes` of
   `record_max_kib`) and the store's crash test (`internal/store/crash_test.go`, T24).
2. `internal/shard` and `internal/store` (but its crash test), and the collector and normalizer
   packages to come, are not owned while no binary root installs compiles them. An agent merges them
   through `balistid-bot` when CI is green on the pull request head with the branch up to date (the
   ruleset enforces this) and, by the agent's own word recorded in the pull request body: every
   behaviour change has a test that fails on the parent or under mutation, and for a change to
   durability, a parser of untrusted input or a socket an Opus critic and a Codex queue review (level
   full) leave no finding open inside the change within two rounds; a NO-GO or a third round goes to the
   maintainer. After the merge the agent reports what merged, the verdicts and how to revert.
3. Before any binary root installs (the collector included) compiles one of these packages, they are
   owned again and that binary joins go_gate's `OWNED_ROOTS`. The ledger, which signs, is owned from
   its first commit.

## Alternatives considered

- Keep owning the product code (ADR 0002 as extended on 10.10.): a human stamp on changes reviewed
  by two independent reviewers; rejected for the cost and because it did not find the defects.
- Unown the cage or the record format: an injected agent could loosen the sandbox its jobs run in or
  change what a record is; rejected.
- A required check that reads the reviews' verdicts from the maintainer-side queue: would make
  decision 2 enforced instead of declared; not built yet.

## Consequences

Only "CI green" in decision 2 is enforced; the review conditions rest on the agent's honesty and on the
maintainer reading the reports and git afterwards. A compromised agent can therefore merge a weaker
store or shard into `main`, but not into an installed binary (decision 3), and not change the record
format or the T24 test. The store's cap tests are unowned; the cap is checked again by the range runs
once the collector exists. THREAT_MODEL T9 notes that sha256 proves CI provenance, not review.
