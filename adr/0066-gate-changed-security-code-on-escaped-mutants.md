# 0066 — Gate changed security code on escaped mutants

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-07
- Decided-by: jvc0n (2026-11-07: a machine, not an agent, shows that the tests bite); claude/opus-5.5 the gate
- Agent: claude/opus-5.5
- Adds a CI dependency (R14, ENGINEERING.md 7) and `tools/ci/mutation-blacklist` to the docs layout.

## Context

R4 asks for a test that fails on the parent, but only for the one broken state its author chose. Mutation runs so
far were by hand and reported by the agent that wrote the code (ADR 0015 point 3, ADR 0023). An external review asked
how anyone shows, without trusting the agents, that the security tests catch a broken decision. Measured on
2026-11-07 (report in the maintainer's scratch, not the repo): of four Go tools, only github.com/jonbaldie/go-mutesting
v2.10.40 (MIT) filters to changed lines, tells uncovered from escaped mutants and exits non-zero on escapes. On the
diff 986b354..f54df9f over the packages below it made 62 mutants in 181 s on two workers: 24 killed, 4 escaped, 34
uncovered (socket tests skip outside CI). Three of the escapes sit in error branches no test can reach.

## Decision

1. CI job `mutation`, on pull requests and merge-queue groups only, mutates the lines a change adds or changes in
   the packages that decide security: `internal/anchor`, `unixsock`, `cosign`, `link`, `collector`, `rangevm`,
   `relay`, `entry`, `shard`, `store` and `cmd/balistid-ledger`. A mutant that tests run but none kills fails the job
   (`--fail-on-escaped`); an uncovered one is listed in the job's log for review. Every mutator runs, `%w` to `%v`
   too, since `errors.Is` decides on wrapped errors (the cap's UNKNOWN). No baseline file can hide an escape.
2. An equivalent mutant (no behaviour change, or a branch nothing can reach) goes into
   `tools/ci/mutation-blacklist` by its checksum; the tool reads bare checksums only, so the reason and the mutant's
   file:line go into the commit that adds the line, which `git blame` shows. The file is code-owned.
3. The tool is one exact module version checked against its module hash before it is built (as govulncheck); the job
   holds no secret and reads only. Its maintainer works alone with AI agents and releases often, so a version bump is
   its own reviewed commit.
4. The job becomes a required check in the `main` ruleset after its first green run, by the maintainer.

## Alternatives considered

- gremlins, the avito fork, mutest, gorgon: no function or diff filter, no failing exit, no licence or compile errors
  (measured). A full-tree run: hours on `rangevm` for every pull request.
- 100 % of all mutants: every unreachable error branch would need a blacklist line or a test seam.

## Consequences

- A change to a security decision now needs tests that notice it changed, checked by the machine on every pull request.
- What it does not catch, left to R4 and review: a removed guard (no added line to mutate), a line no test runs
  (listed, not failed), a test written to fail on purpose under mutation, and a mutant that errors or times out.
