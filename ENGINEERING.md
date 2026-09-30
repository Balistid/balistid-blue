# Engineering rules

These rules bind every contributor: the maintainer, Claude Code and Codex. When this file conflicts
with any global policy, this file wins inside this repository. Changing a rule requires an ADR
decided by the maintainer (`Decided-by: alex`).

## 1. Definition of done

A change is done when all of these hold, verified now and not from memory:

1. CI is green on the pull request. Nothing reaches `main` except through a pull request with green CI.
2. A behaviour change carries a test that fails on the parent commit (R4). Syntax checks, file
   existence and commit messages are not evidence.
3. Acceptance numbers for the floor were committed before the floor's first code commit, and no
   result is `missed` (R3). Only the maintainer changes an acceptance number, through an ADR.
4. `THREAT_MODEL.md` rows touched by the change are updated.
5. `STATUS.md` reflects the new state.

## 2. The rules (R1–R14)

| # | Rule |
|---|---|
| R1 | Only what runs from a committed hash exists. Code, units, policies, sudoers and tmpfiles live in the repo; the root layer is installed only by `kordon-install` from a sha256 manifest. |
| R2 | The registry of approved digests is out of agent reach: manifests count only when signed with the maintainer's hardware key. |
| R3 | Acceptance numbers are written before code; a miss blocks deployment. |
| R4 | Done means a test that fails on the parent commit. |
| R5 | Every store has an exit (close/expire), a size cap and retention from day one. Caches and baselines are keyed by content, not mtime. |
| R6 | Missing is not healthy. A security decision on error, timeout or unknown input returns deny/UNKNOWN; OK is never a default. |
| R7 | Boundaries are allowlists with negative tests. A third review round finding a defect in the same change, or a defect introduced by a fix, means redesign, not another patch. |
| R8 | No root action outside `kordon-install`. |
| R9 | Do not write a sensor someone already maintains. A new component needs an ADR naming the existing tool, why it is not enough and what changes. |
| R10 | Every detection and boundary names its `THREAT_MODEL.md` row and ships an attack scenario that triggers it and a legitimate one that does not. |
| R11 | Every commit carries exactly one `Agent:` trailer (`alex`, `claude/<model>`, `codex/<model>`). No advertising trailers. |
| R12 | Running floor first, document second. Only the files in the docs allowlist exist (`tools/ci/docs_budget.py`). |
| R13 | Minimal root surface: only the collector and the installer run as root. UI and CLI are unprivileged, talk to the daemon over a Unix socket checked with `SO_PEERCRED`, and never call `sudo`. |
| R14 | Dependencies and CI actions are pinned by hash; builds use the lock only. A dependency update is its own commit. |

## 3. Code

- Security decisions are logged with the decision, the reason and the rule version. Every stored
  record has a `schema_version`; readers reject an unknown major version.
- Secrets never appear in argv, environment, logs or the repository. Files holding secrets are 0600.
- No swallowed exceptions, silent fallbacks or retries that hide a failure. Fail loudly and closed.
- A claim of absence ("no X found") states the method and its blind spot.
- A change after which a check fires less often gets an independent review regardless of size.
- No host-specific data in the repo: no usernames, home paths, hostnames or real tokens. Test
  fixtures that need them are generated at runtime. `gitleaks` enforces the obvious cases.
- Comments explain why, not what. No commented-out code, no TODO without an issue or a date.
- Language-specific rules (formatter, linter, test runner) are added by the ADR that picks the language.

## 4. Commits and pull requests

- Conventional Commits subject (`feat|fix|docs|refactor|test|ci|build|chore|perf|revert|security`),
  at most 72 characters, blank second line, `Agent:` trailer. Enforced by `tools/ci/commit_lint.py`
  locally (commit-msg hook) and in CI over the whole pull request range.
- History is linear. No merge commits, no force-push to `main`, no deleting `main`.
- One logical change per pull request. The pull request template checklist is filled in honestly;
  an unchecked box needs a reason.

## 5. Review

Independent review scales with the impact of a mistake, not with the file type:

| Change | Review |
|---|---|
| Small, reversible, with tests (about 50 lines, one file) | Tests and self-check |
| Security-relevant gate, several files, weak tests | One Claude critic (Opus) |
| Security boundary with root impact, signing, install path, architecture | Claude critic and Codex `cross-review --level full` |

A further round runs only when the last review found a defect inside the change. If the third and
any later round again finds one, stop and redesign (R7); the maintainer decides. Review findings are
hypotheses until reproduced by a test.

## 6. Documentation

- Allowed prose: `README.md`, `SECURITY.md`, `THREAT_MODEL.md` (one page), `ENGINEERING.md`,
  `CLAUDE.md`, `AGENTS.md`, `STATUS.md`, `adr/NNNN-*.md` (one page each), the pull request template.
  Caps live in `tools/ci/docs_budget.py`; changing them needs an ADR.
- Decisions go to an ADR, state goes to `STATUS.md`, history goes to git. Nothing else.
- `STATUS.md` is overwritten at the end of each working session. It never grows into a log.
