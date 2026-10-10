# 0002 — A GitHub App pushes and merges; the maintainer approves changes to gates

- Status: accepted (supersedes decision 3 of ADR 0001)
- Date: 2026-09-30, amended 2026-10-10 (required checks, not a count)
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0001 kept agents from pushing, because a token that can push can also merge through the API
and every gate runs from the pull request's own checkout. In practice the maintainer then had to
push, open and merge every change by hand, which blocked daily work. Tested on 2026-09-30.

## Decision

1. Agents push branches, open pull requests and merge through `balistid-bot`, a GitHub App
   installed on this repository only. Permissions: contents and pull requests read/write, actions
   and checks read. No administration, no workflows. Installation tokens live one hour.
2. `.github/CODEOWNERS` assigns the gates and the rules to the maintainer: `tools/ci/`, `.github/`,
   `githooks/`, `.gitleaks.toml`, `.gitattributes`, `ENGINEERING.md`, `CLAUDE.md`, `AGENTS.md`,
   `adr/`, `acceptance/`.
3. The `main` ruleset requires a pull request, the required CI checks on an up-to-date branch, code owner
   review, linear history and rebase merges; it blocks force-push and deletion. No approvals are
   required otherwise. Organisation admins may bypass only through a pull request.
4. Result: a change that does not touch owned paths merges when CI is green, without the maintainer.
   A change to a gate or a rule waits for the maintainer's approval.

## Evidence (2026-09-30)

- Bot push to `main`: rejected (GH013, "Changes must be made through a pull request").
- Bot merged pull request 4 (STATUS.md) on its own after CI.
- Pull request 5 changed `tools/ci/`: the bot could not approve it ("Can not approve your own pull
  request") and the merge was refused ("Waiting on code owner review").
- Bot tried to change repository settings and the ruleset: HTTP 403.

## Alternatives considered

- Maintainer pushes everything (ADR 0001): safe, but blocked work.
- One required approval on every pull request: the maintainer clicks for each change; rejected.
- A second user account as bot: costs a paid seat and holds a long-lived credential.

## Consequences

- The bot's private key (`bot.pem`, outside the repository, mode 0600) is readable by agents on the
  host. Whoever holds it can merge non-owned changes that pass CI, never owned ones.
- Changes to workflows must come from the maintainer, because the bot has no workflows permission.
- CODEOWNERS changes are themselves owned, so the owned list cannot be shrunk without approval.
