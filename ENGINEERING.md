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
| R1 | Only what runs from a committed hash exists. Code, units, policies, sudoers and tmpfiles live in the repo; the root layer is installed only by `balistid-install` from a sha256 manifest. |
| R2 | The registry of approved digests is out of agent reach: manifests count only when signed with the maintainer's hardware key. |
| R3 | Acceptance numbers are written before code; a miss blocks deployment. |
| R4 | Done means a test that fails on the parent commit. |
| R5 | Every store has an exit (close/expire), a size cap and retention from day one. Caches and baselines are keyed by content, not mtime. |
| R6 | Missing is not healthy. A security decision on error, timeout or unknown input returns deny/UNKNOWN; OK is never a default. |
| R7 | Boundaries are allowlists with negative tests. A finding no local fix can close without a special case or a changed assumption (DESIGN), or the same invariant failing again after a fix, means redesign, not another patch (§5, ADR 0033). |
| R8 | No root action outside `balistid-install`. |
| R9 | Do not write a sensor someone already maintains. A new component needs an ADR naming the existing tool, why it is not enough and what changes. |
| R10 | Every detection and boundary names its `THREAT_MODEL.md` row and ships an attack scenario that triggers it and a legitimate one that does not. |
| R11 | Every commit carries exactly one `Agent:` trailer (`alex`, `claude/<model>`, `codex/<model>`). No advertising trailers. |
| R12 | Running floor first, document second. Only the files in the docs allowlist exist (`tools/ci/docs_budget.py`). |
| R13 | Minimal root surface: only the installer runs as root; the one long-running privileged process is `balistid-auditstat` (`CAP_AUDIT_CONTROL`), and `balistid-net` holds `CAP_NET_ADMIN` only for its start at boot (ADR 0032); every other runs as its own uid without privilege (ADR 0007). UI and CLI are unprivileged, talk to the daemon over a Unix socket checked with `SO_PEERCRED`, and never call `sudo`. |
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
  Comments other than doc comments on a declaration stay within three lines. None of them, nor test
  names or messages, tell how a bug was found, the review rounds or who wrote the code (ADR 0012).
- Before adding code, search the repository for a mechanism or idiom that already does it and extend
  that instead.
- No wrapper that only forwards its arguments, no abstraction kept for a hypothetical second caller
  (a test seam or the `main`/`internal` split is a real use), no catch-all names (`util`, `helpers`).
  Fail-closed handling of errors and untrusted input (R6) is never speculative.
- An assertion is never deleted or weakened to make a test pass; it changes only together with the
  behaviour it pins, and the pull request says so.
- A pull request that adds more than 100 lines outside tests and testdata says why it cannot be simpler.
- Language-specific rules (formatter, linter, test runner) are added by the ADR that picks the language.

## 4. Commits and pull requests

- Conventional Commits subject (`feat|fix|docs|refactor|test|ci|build|chore|perf|revert|security`),
  at most 72 characters, blank second line, `Agent:` trailer. Enforced by `tools/ci/commit_lint.py`
  locally (commit-msg hook) and in CI over the whole pull request range.
- History is linear. Rebase merges only; no merge commits, no force-push to `main`, no deleting `main`.
- Agents push and merge only as `balistid-bot` (ADR 0002). Changes to paths in
  `.github/CODEOWNERS` (gates, rules, ADRs, acceptance numbers) need the maintainer's approval.
- One logical change per pull request. The pull request template checklist is filled in honestly;
  an unchecked box needs a reason.
- Where the bot helper, the critic agent, the Codex queue or the VM range is missing (a cloud
  session, another host), work is not pushed and not called done. It ends with the list of review
  and range steps that did not run; a session on the maintainer's machine runs them before pushing.

## 5. Review

Independent review scales with the impact of a mistake, not with the file type:

| Change | Review |
|---|---|
| Small, reversible, with tests (about 50 lines, one file) | Tests and self-check |
| Security-relevant gate, several files, weak tests | One Claude critic (Opus) |
| Security boundary with root impact, signing, install path, architecture | Claude critic and Codex review (queue, level security) |

Each finding carries severity, class (BUG or DESIGN) and fix risk (ADR 0033); an open CRIT or HIGH inside
the change blocks merge. A plain MED or LOW fix is verified by its test failing on the parent; a CRIT or
HIGH fix, a fix that changes a decision and a disputed finding by one reply round on the fix range; a
redesign, or a fix range over about 150 lines outside tests, by a full round. The author decides a redesign
with one sentence why; the maintainer decides when it changes an ADR, acceptance number or threat claim,
when author and reviewer still disagree after the reply round, when an invariant fails again after a
redesign, or before a third full round on one checkpoint. The reviewer's threat names the change's goal and
threat rows, and each fix is checked for the path it opens (ADR 0035). Review findings are hypotheses until
reproduced by a test.

## 6. Documentation

- Allowed prose: `README.md`, `SECURITY.md`, `THREAT_MODEL.md` (one page), `ENGINEERING.md`,
  `CLAUDE.md`, `AGENTS.md`, `STATUS.md`, `adr/NNNN-*.md` (one page each), the pull request template.
  Caps and the closed layout allowlist live in `tools/ci/docs_budget.py`; changing them needs an ADR.
- Decisions go to an ADR, state goes to `STATUS.md`, history goes to git. Nothing else.
- `STATUS.md` is overwritten at the end of each working session. It never grows into a log.

## 7. Go

Decided in ADR 0008. A `(lint: …)` marker covers only the clause it follows; the rest is review.

- **Errors.** Every error is handled or returned (lint: errcheck), wrapped with context where it
  crosses a package (lint: wrapcheck, errorlint). An error in a security decision yields deny or
  UNKNOWN (R6); `main` turns errors into a non-zero exit. No `panic` in `internal/` (lint: forbidigo).
- **Context.** Anything that does I/O, blocks or waits takes `ctx context.Context` first and honours
  cancellation. `context.Background()` and `TODO()` only in `main` and tests (lint: forbidigo,
  contextcheck, noctx).
- **Goroutines and resources.** Each goroutine has an owner that stops it through `ctx` and waits for
  it. Channels and queues are bounded; no goroutine per untrusted input without a limit (T20). Every
  service sets `GOMEMLIMIT` below its share of `rss_mib`; network servers set read, write and idle
  timeouts.
- **Untrusted input.** Readers are size-capped (`io.LimitReader`); protocol messages are decoded
  strictly (`DisallowUnknownFields`, explicit version check). Every parser has a fuzz target (R10).
- **Files Balistid Blue writes whole** (configs, keys, manifests, exports): mode 0600, or 0640 with
  `//nolint:gosec // group-readable for <uid>` (lint: gosec G306); written to a temp file, fsynced,
  renamed, then the directory fsynced. Paths under directories another uid can write are opened
  without following symlinks. SQLite shards and Tessera tiles manage their own files: their safety
  comes from a 0750 directory owned by the service, umask 0027 and the seal of ADR 0005.
- **SQLite.** Pragmas (`journal_mode`, `synchronous=FULL`, `busy_timeout`) go in the DSN so every
  pooled connection gets them; the writer uses `SetMaxOpenConns(1)`; queries are parameterized
  (lint: gosec G701, known taint sources only; parameterization is review).
- **Crypto.** Randomness from `crypto/rand` (lint: depguard); secrets and MACs compared with
  `crypto/subtle.ConstantTimeCompare`; hashes and signatures only through the standard library or a
  reviewed module.
- **Processes.** `os/exec` only with an absolute binary path and a fixed argv; never a shell, never
  input in the command name (lint: gosec G204, variable argv only).
- **Time.** Durations and timeouts use the monotonic clock. Stored times are wall-clock UTC and never
  decide a security question alone (T22); the monotonic clock stops during suspend, so timers that
  span a suspend are re-checked on resume.
- **Logging.** `log/slog` with structured fields (lint: depguard on `log`, forbidigo on `print` and
  `fmt.Print*`, not `Fprint*`, in `internal/`); no record bodies, argv or secrets at any level.
- **Packages.** `cmd/<name>` is a thin `main`; logic lives in `internal/`. No package-level mutable
  state except build info; no `init` with side effects; exported identifiers are documented.
- **Forbidden.** `unsafe` and `math/rand` (lint: depguard); cgo (CI: go-static fails on any cgo
  file in the default build); `reflect` on untrusted data.
- **Dependencies.** Standard library first. A new module needs its own commit, a reason in the pull
  request and a licence in Apache-2.0, MIT, BSD or ISC; no GPL, AGPL or BSL code is linked (R14). The one
  exception is `github.com/hashicorp/golang-lru/v2` (MPL-2.0, Tessera's, linked unmodified; ADR 0026).
- **Tests.** Table-driven where cases repeat; failure paths tested as well as success; `t.Parallel()`
  only where tests share no state. A behaviour change still needs a test that fails on the parent (R4).
