# Status

Updated: 2026-10-25 by claude/opus-5.5

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011, 0018-0021) | VM where agents test the recorder; the runner runs the acceptance suite itself | installed at 2c09799; image build takes modules from the Go mirror (#123); trials are baseline until the collector joins the image (ADR 0022, B4.3-B4.4) |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main`, code-owned (#127) |
| Store (0005, 0013) | cap, reserve, loss records, seal index | on `main`, code-owned; `Committed` (last durable seq, #128) |
| Collector (0007, 0016, 0017) | takes Laurel's records over a socket, never blocks Laurel | on `main` with units, code-owned; A7 closed (#125); range-only `-log-commits` and `-headroom` (#128) |
| Ledger, relay, Pi witness (0006) | signed log, cosigned off the host | not started; plan draft outside the repo |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions
- A7 closed: reconnect counts per kind and pid (#125), store, shard, collector and `cmd/balistid-collector`
  code-owned (#127). ADR 0022 accepted (#124): the collector runs in the range image, which reads sealed shards.
- B4.1 (#123): the image build fetches modules from proxy.golang.org against the export's go.sum; a path replace,
  a go.mod outside the export and caller proxies are refused; the module cache is capped at 1 GiB before an
  offline go build.
- B4.2 (#128): `Store.Committed` rises only when a commit or seal returns; `-log-commits` journals it.
## Next step
1. B4.3 (ADR 0022): image files gain `deploy/collector/*`, the binary, the range drop-in and the store-setup
   oneshot; scratch disk in every run; checked with one short KVM run with the maintainer present.
2. B4.4: Laurel writes to the collector socket and the guest reads sealed shards (atomic switch); then B4.5-B4.9.
## Open decisions (maintainer)
- #123: the module cap measures after the download; a real bound needs a quota filesystem or a watcher (T36).
- #128: a reserve made at one `-headroom` is reused at another without resizing (`reserve()`); B5 measures it.
- #125: past 16 pids per cause only a count is kept (amend ADR 0017 point 4?); a read error's text is not recorded.
- Store: btrfs keeps truncated extents and an active filler takes the freed reserve (T10 partial): a filesystem of
  its own for the store at host install.
- The build unit has no syscall filter, yet runs a commit's PKGBUILD and mkosi: its own change.
- R2 signing keys; before floor 0's host install: x32 mitigation, io_uring. shellcheck in CI is unpinned (R14).
