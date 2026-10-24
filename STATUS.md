# Status

Updated: 2026-10-24 by claude/opus-5.5

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011, 0018-0021) | VM where agents test the recorder; the runner runs the acceptance suite itself | installed at 2c09799; trials are baseline until the collector joins the image (ADR 0022, proposed #124) |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main` |
| Store (0005, 0013) | cap, reserve, loss records, seal index | on `main`; full filesystem is a second cap (#120), file modes and index cap (#118) |
| Collector (0007, 0016, 0017) | takes Laurel's records over a socket, never blocks Laurel | on `main` with units (CP3); A7 open: reconnect counts (#125 or #122) |
| Ledger, relay, Pi witness (0006) | signed log, cosigned off the host | not started; plan draft outside the repo |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions
- A7, the whole-source review of store, shard, collector and cmd (Opus critic, Codex security): full filesystem
  below the cap blinded the store (#120, ADR 0013 p8); shard modes, index cap, `-journal`, synchronous=FULL test (#118).
- `tools/ci/check.py` fast local mirror of the Go jobs (#121); scorecard 2.5.0 (#109).
## Next step
1. Collector A7: the maintainer picks #125 (counts per kind and pid, never queued; two critic rounds, no HIGH) or
   #122 (folds given-way records; NO-GO in round 2 from both reviewers). Then the flip (ADR 0015 point 3): branch
   `chore/flip-collector-owned` adds store, shard, collector and `cmd/balistid-collector` to CODEOWNERS, OWNED_ROOTS
   and the CI `go list -deps`; the maintainer pushes it (workflow change).
2. B4 (collector in the range image): ADR 0022 #124 with decisions D1-D4 in its description; B4.1 #123 (modules from
   the Go mirror, draft) waits for it.
## Open decisions (maintainer)
- #123: a commit without a root `go.mod` makes go use one above the stage (fix: `go env GOMOD` check); a dependency's
  assembly `#include` reads host files despite go.sum (record under ADR 0010, or confine go build); proxy env vars.
- #125: past 16 pids per cause only a count is kept (amend ADR 0017 point 4?); a read error's text is not recorded.
- Store: btrfs keeps truncated extents and an active filler takes the freed reserve (T10 partial): a filesystem of
  its own for the store at host install.
- The build unit has no syscall filter, yet runs a commit's PKGBUILD and mkosi: its own change.
- R2 signing keys; before floor 0's host install: x32 mitigation, io_uring. shellcheck in CI is unpinned (R14).
