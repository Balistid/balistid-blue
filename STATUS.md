# Status

Updated: 2026-10-26 by claude/opus-5.5

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011, 0018-0021) | VM where agents test the recorder; the runner runs the acceptance suite itself | installed at 2c09799; on `main` (#131, #132): the collector in the image, the guest reads its sealed shards, trials decide metrics (ADR 0022); KVM run on 5890be4 |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main`, code-owned (#127) |
| Store (0005, 0013) | cap, reserve, loss records, seal index | on `main`, code-owned; `Committed` (last durable seq, #128) |
| Collector (0007, 0016, 0017) | takes Laurel's records over a socket, never blocks Laurel | on `main` with units, code-owned; A7 closed (#125); range-only `-log-commits` and `-headroom` (#128) |
| Ledger, relay, Pi witness (0006) | signed log, cosigned off the host | not started; plan draft outside the repo |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions
- C1 (#131, #132): collector and store in the image, guest reads sealed shards to a barrier. KVM 5890be4: burst PASS,
  sustained MISS (889009 of 1.2 M in 2 vCPU). #133: refusal summaries per cause, with socket and rule version.
- C2 (#134, ADR 0023): trials by method; crash_loss_ms by kill/reset of the collector (S from its commit line),
  record-max, refusal-flood, ready-1..4, exposure, cpu-1000. KVM: record, refusal (60498 of 60500 ms), ready (7.2 s),
  exposure (0.8), cpu (0.468) PASS; kill/reset INVALID, rate not held; burst 2 of 3 failed: systemd's 10 s watchdog
  killed the collector mid-burst (journal in the guest's report).
## Next step
1. Merge #133, then C2 (owned: maintainer approves).
2. Collector: a writer tick appends the whole queue before it feeds the watchdog (writer.go step), so a burst can
   outlast WatchdogSec=10s and lose the queue; bound a tick's work or feed the watchdog within it (own PR, test).
3. C3 = B4.9: reinstall the runner (maintainer), the suite, verdicts of the 8 metrics in status.py.
## Open decisions (maintainer)
- #123: the module cap measures after the download; a real bound needs a quota filesystem or a watcher (T36).
- #128: a reserve made at one `-headroom` is reused at another without resizing (`reserve()`); B5 measures it.
- sustained_rate MISS in 2 vCPU: more vCPUs for the range, or a product limit? Crash trials stay INVALID until then.
- C1: `shard.Read` hashes a shard, then SQLite reopens it by path: a collector broken through T18 could swap it.
- #125: past 16 pids per cause only a count is kept (amend ADR 0017 point 4?); a read error's text is not recorded.
- Store: btrfs keeps truncated extents, an active filler takes the freed reserve (T10): own filesystem at install.
- The build unit has no syscall filter, yet runs a commit's PKGBUILD and mkosi (exposure 4.6): its own change.
- refusal_summary_s held by 2 ms and cpu_cores at 0.468 of 0.5 in KVM: margins to watch in the suite.
- A collector killed mid-read makes a rate trial INVALID (barrier missing), not MISS: a loss it causes is not a MISS.
- R2 signing keys; before floor 0's host install: x32 mitigation, io_uring. shellcheck in CI is unpinned (R14).
