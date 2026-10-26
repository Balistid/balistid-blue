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
- C1 = B4.3-B4.5 (#131, follow-up #132): collector, store-setup and range drop-in in the image, a scratch disk in
  every run, the guest reads sealed shards up to a barrier. KVM 5890be4: self-test and burst PASS, drop and the three
  controls as expected; sustained MISS (889009 of 1.2 M generated in 2 vCPU, CPU saturated, all stored).
- #133: refusal summaries count each cause and name the socket and rule version (refusal_summary_s).
- C2 = B4.6-B4.8 (feat/collector-trials, ADR 0023 proposed): trials run and are judged by their method;
  crash_loss_ms by 7+7 rows of kill and reset of the collector at 2000/s (S from its live commit line, MISS when
  the recovery record's last seq is below S); record-max, refusal-flood, ready-1..4, exposure, cpu-1000 (collector,
  auditd and Laurel). Judges by closed facts, mutations of every judge killed; not yet run in KVM.
## Next step
1. C2: Opus critic and Codex security on the pull request, maintainer's `/security-audit`, then one short KVM run
   (record, refusal, ready, exposure, one kill, one reset); merge #133 first, then C2 (owned: maintainer approves).
2. C3 = B4.9: reinstall the runner (maintainer), the suite, verdicts of the 8 metrics in status.py.
## Open decisions (maintainer)
- #123: the module cap measures after the download; a real bound needs a quota filesystem or a watcher (T36).
- #128: a reserve made at one `-headroom` is reused at another without resizing (`reserve()`); B5 measures it.
- sustained_rate MISS in 2 vCPU: more vCPUs for the range, or a product limit? Crash trials stay INVALID until then.
- C1: `shard.Read` hashes a shard, then SQLite reopens it by path: a collector broken through T18 could swap it.
- #125: past 16 pids per cause only a count is kept (amend ADR 0017 point 4?); a read error's text is not recorded.
- Store: btrfs keeps truncated extents, an active filler takes the freed reserve (T10): own filesystem at install.
- The build unit has no syscall filter, yet runs a commit's PKGBUILD and mkosi: its own change.
- R2 signing keys; before floor 0's host install: x32 mitigation, io_uring. shellcheck in CI is unpinned (R14).
