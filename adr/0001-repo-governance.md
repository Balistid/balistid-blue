# 0001 — Govern the repository through CI gates, not agent-side hooks

- Status: accepted
- Date: 2026-09-30
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

The previous project (System Policeman V1) failed on process, not on ideas: success was reported
before verification, deployed code did not match the repository, documentation grew to hundreds of
kilobytes while the product got no commits, and security boundaries were patched with denylists
round after round. Its post-mortem produced rules R1–R14 (now `ENGINEERING.md`). The maintainer works
alone with AI coding agents (Claude Code, Codex). Agent-side hooks only bind the agent that loads
them; a server-side gate binds every contributor.

## Decision

1. `ENGINEERING.md` is the binding rulebook; changes to it need an ADR.
2. Enforcement lives in CI on a private GitHub repository under the `Kordon-Sec` organisation on the
   GitHub Team plan, so that a ruleset on `main` is enforced server-side: pull request required,
   required status checks, no force-push, no deletion, linear history, no bypass.
3. Agents push branches with a fine-grained token scoped to this repository without the
   Administration permission, so they cannot change the ruleset. The maintainer merges.
4. Local hooks (`githooks/`, `core.hooksPath`) give early feedback and fail closed when a required
   tool is missing. CI remains the authority.
5. Docs allowlist (R12) is extended from the post-mortem's list by `ENGINEERING.md`, `CLAUDE.md`,
   `AGENTS.md`, `STATUS.md` and the pull request template, because the maintainer wants agent context
   to survive across sessions. `STATUS.md` is overwritten, never appended.
6. Provenance trailer `Agent:` on every commit (R11); advertising trailers are rejected.
7. License: Apache-2.0.

## Alternatives considered

- Public repository on the Free plan: rulesets and secret scanning free, but unfinished security code
  and design details would be public before floor 0 works. Rejected by the maintainer for now.
- More global agent hooks: rejected; the global setup is frozen and hooks do not bind Codex or humans.

## Consequences

- Gates are testable code (`tools/ci/tests`), so a broken gate shows up as a failing test.
- A gate that is wrong blocks work until fixed in its own pull request.
- The token is readable by agents by design; leaking it allows pushing branches, not changing `main`.
- Costs the GitHub Team subscription while the repository stays private.
