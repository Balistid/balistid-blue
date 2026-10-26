# Status

Updated: 2026-10-26 by claude/opus-5.5

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011, 0018-0021) | VM where agents test the recorder; the runner runs the acceptance suite itself | installed at 2c09799; on `main` once C1 merges: the collector in the image, the guest reads its sealed shards, trials decide metrics (ADR 0022); not yet run in KVM |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main`, code-owned (#127) |
| Store (0005, 0013) | cap, reserve, loss records, seal index | on `main`, code-owned; `Committed` (last durable seq, #128) |
| Collector (0007, 0016, 0017) | takes Laurel's records over a socket, never blocks Laurel | on `main` with units, code-owned; A7 closed (#125); range-only `-log-commits` and `-headroom` (#128) |
| Ledger, relay, Pi witness (0006) | signed log, cosigned off the host | not started; plan draft outside the repo |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions
- A7 closed: reconnect counts per kind and pid (#125), store, shard, collector and `cmd/balistid-collector`
  code-owned (#127). ADR 0022 accepted (#124): the collector runs in the range image, which reads sealed shards.
- B4.1 (#123): the image build fetches modules from proxy.golang.org against the export's go.sum; a path replace,
  a go.mod outside the export and caller proxies are refused; the module cache is capped at 1 GiB.
- B4.2 (#128): `Store.Committed` rises only when a commit or seal returns; `-log-commits` journals it.
- C1 = B4.3-B4.5 (feat/collector-in-image): collector, store-setup oneshot and range drop-in in the image, a
  512 MiB scratch disk in every run (4 GiB sustained); Laurel to the socket, guest reads up to a barrier from
  sealed shards only; exec window whole only up to the stopped run's end without loss (T25); no baseline.
  KVM 5890be4: self-test PASS, burst PASS 100000/100000, drop and the three controls as expected; sustained
  MISS: 889009 of 1.2 M generated in 2 vCPU (rate not held, CPU saturated), all stored, scratch enough.
## Next step
1. C1 merge (maintainer's approval), then a small PR: exec jobs check kernel `audit_lost` and overflow.
2. C2 = B4.6-B4.8 (crash, record, refusal, ready, exposure, cpu trials), then C3 = B4.9 (install, suite).
## Open decisions (maintainer)
- #123: the module cap measures after the download; a real bound needs a quota filesystem or a watcher (T36).
- #128: a reserve made at one `-headroom` is reused at another without resizing (`reserve()`); B5 measures it.
- sustained_rate MISS in a 2-vCPU range VM with the collector: more vCPUs for that trial, or a product limit?
- C1: `shard.Read` hashes a shard, then SQLite reopens it by path: a collector broken through T18 could swap it.
- #125: past 16 pids per cause only a count is kept (amend ADR 0017 point 4?); a read error's text is not recorded.
- Store: btrfs keeps truncated extents, an active filler takes the freed reserve (T10): own filesystem at install.
- The build unit has no syscall filter, yet runs a commit's PKGBUILD and mkosi: its own change.
- R2 signing keys; before floor 0's host install: x32 mitigation, io_uring. shellcheck in CI is unpinned (R14).
