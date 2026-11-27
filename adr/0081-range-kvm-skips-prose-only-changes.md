# 0081 — range-kvm skips a change that is prose only

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-27
- Decided-by: maintainer (2026-11-27, in session)
- Agent: claude/opus-5.5
- Amends ADR 0028 point 1 (which pull requests the job builds and runs).

## Context

`range-kvm` builds the commit's range image and boots it on every pull request and again in the merge queue. A
pull request that changed only the README (#319, 2026-11-27) waited about 50 minutes: the job failed three times
because archive.archlinux.org did not serve the snapshot's packages, then ran again in the queue. The build reads
such files only as entries of the commit's export, which takes regular files (`listTree` in
`internal/rangevm/session.go`); nothing copies them into the image or runs them (`imageFiles`, `range/`, `deploy/`,
`packaging/`, the Go packages).

## Decision

1. On `pull_request` and `merge_group` the job's step asks `tools/ci/range_kvm.py --prose-only` about the range that
   `tools/ci/change_range.py` prints. When every changed entry, both sides of a rename, is at a path the allowlist
   `PROSE` names and is a plain file (mode 100644) on each side where it exists, the job ends green and says so; it builds
   nothing and boots nothing. A symlink, an executable file or a submodule at such a path runs the self-test.
2. `PROSE` is an allowlist of exact names: the root's README, STATUS, SECURITY, THREAT_MODEL, ENGINEERING, CLAUDE
   and AGENTS files, `adr/NNNN-*.md` one level deep, the pull request template, the issue templates and the two
   README banners. A path it does not name runs the self-test, until it is added here.
3. An empty change, a git error or output it cannot read runs the self-test; when `change_range.py` cannot name
   the range, the step fails. `push` to main and the weekly `schedule` always run, so every merge still gets one
   KVM run on main. docs-budget, a required check, still refuses a symlink or an oversize prose file.

## Consequences

- A prose-only pull request no longer waits for the image or the Arch archive.
- Lost: a KVM run on such a pull request. A later change that makes a listed file an input of the build (the image
  copying README, a test reading an ADR) must take it off the list in the same change; review reads `PROSE` as a
  gate (ENGINEERING.md 3), and the push run on main still builds it.
- Not done here: a package cache across runs. ADR 0010 gives each build try its own download on purpose.
- Revert: a pull request that removes the step's `if` block and `--prose-only`.
