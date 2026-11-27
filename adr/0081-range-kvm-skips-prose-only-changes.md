# 0081 — range-kvm skips a change that is prose only

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-27
- Decided-by: maintainer (2026-11-27, in session)
- Agent: claude/opus-5.5
- Amends ADR 0028 point 1 (which pull requests the job builds and runs).

## Context

`range-kvm` builds the commit's range image and boots it on every pull request and again in the merge queue. A
pull request that changed only the README (#319, 2026-11-27) waited about 50 minutes: the job failed three times
because archive.archlinux.org did not serve the snapshot's packages, then ran again in the queue. No file such a
change touches is read by the build, the image or the run (`imageFiles` in `internal/rangevm/session.go`,
`range/`, `deploy/`, `packaging/`, the Go packages).

## Decision

1. On `pull_request` and `merge_group` the job's step asks `tools/ci/range_kvm.py --prose-only` about the range that
   `tools/ci/change_range.py` prints. When every changed path, both sides of a rename, matches the allowlist
   `PROSE`, the job ends green and says so; it builds nothing and boots nothing.
2. `PROSE` is an allowlist of exact names: the root's README, STATUS, SECURITY, THREAT_MODEL, ENGINEERING, CLAUDE
   and AGENTS files, `adr/NNNN-*.md` one level deep, the pull request template, the issue templates and the two
   README banners. A path it does not name runs the self-test, until it is added here.
3. Everything else runs it as before: an empty change, a git error, a range that is not two full shas, any other
   event. `push` to main and the weekly `schedule` always run, so every merge still gets one KVM run on main.

## Consequences

- A prose-only pull request no longer waits for the image or the Arch archive.
- Lost: a KVM run on such a pull request. A later change that makes a listed file an input of the build (the image
  copying README, a test reading an ADR) must take it off the list in the same change; review reads `PROSE` as a
  gate (ENGINEERING.md 3), and the push run on main still builds it.
- Not done here: a package cache across runs. ADR 0010 gives each build try its own download on purpose.
- Revert: a pull request that removes the step's `if` block and `--prose-only`.
