# 0012 — Keep the simplicity rules in the repository

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-07
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

The rules against needless code (no wrapper that adds nothing, no helper used once, no comment that
narrates history, a reason for every large change) live in the maintainer's personal coding policy,
outside this repository. A session that does not load it never sees them. The maintainer's session
notes for 2026-10-06 (kept outside this repository) record a runner session that produced a wrapper
that added nothing, process narration inside a test and a change over the size limit without a
reason; that the missing policy caused it is an inference.

Anyone working without the maintainer's machine never sees that policy at all: a cloud session, a
Codex sandbox, a future contributor. Such a context also lacks the bot credential helper, the critic
agent, the Codex review queue and the VM range (KVM), while `CLAUDE.md` refers to "the maintainer's
global instructions" that it cannot read.

## Decision

`ENGINEERING.md` §3 carries the simplicity rules itself: search before adding, no forwarding
wrappers or speculative abstractions (test seams and the `main`/`internal` split count as real
uses), no catch-all names, no deleted or weakened assertions, short comments without history
(doc comments on declarations exempt), and a written reason when a pull request adds more than 100 lines outside
tests; the pull request template asks for it. `ENGINEERING.md` §4, which Claude and Codex both read,
says that work done without the bot helper, the critic agent, the Codex queue or the VM range is not
pushed and not called done until a session on the maintainer's machine has run the missing steps.
`CLAUDE.md` points to it, and the Codex instruction no longer refers to text the reader cannot see.

## Alternatives considered

- Copy the whole personal policy into the repository: most of it is about other projects and would
  break the documentation budget (R12).
- Let cloud sessions push to their own branches through the Claude GitHub App: changes ADR 0002 and
  lets a new identity run CI on branches it controls. Not without its own ADR.

## Consequences

The rules travel with the code, so every reader gets them, including tools that never load the
maintainer's setup. ENGINEERING.md grows by about twelve lines (cap 160). Nothing enforces the §4
rule mechanically; it relies on the agent stopping where the bot helper is missing.
