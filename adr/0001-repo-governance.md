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
3. (Superseded by ADR 0002: a GitHub App pushes; code owners guard the gates.) Agents never push. A token with Contents: write can merge a pull request through the API, and
   every gate runs from the pull request's own checkout, so an agent could weaken a gate and merge
   itself. Agents get a read-only token (contents, pull requests, actions) to read CI results; the
   maintainer pushes, opens pull requests and merges. Merge method: rebase only, so every commit on
   `main` is a commit that CI linted.
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
- The read-only token is readable by agents by design; leaking it exposes the private code, not `main`.
- Changes to `tools/ci/`, `.github/`, `githooks/`, `.gitleaks.toml` and `.gitattributes` weaken or
  strengthen the gates themselves; the maintainer reviews them line by line before merging. The
  gates stop drift and careless agents; a determined author of gate code is stopped by that review.
- Action pinning is audited by zizmor, which reads the parsed YAML; our own regex checker was
  bypassed twice by YAML spellings and was removed (R7, R9). File names follow a strict grammar so
  that the gitleaks default path allowlist cannot exempt a tracked file.
- The `main` ruleset requires branches to be up to date before merging. Layout and secret gates run
  on every commit that lands. Go gates run on the head tree, each job on a fresh runner;
  intermediate commits are not built (THREAT_MODEL T29).
- Costs the GitHub Team subscription while the repository stays private.
