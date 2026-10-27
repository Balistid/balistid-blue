# Status

Updated: 2026-10-27 by claude/opus-5.5

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011, 0018-0021) | VM where agents test the recorder; the runner runs the acceptance suite itself | installed at 2c09799; on `main` (#131, #132): the collector in the image, the guest reads its sealed shards, trials decide metrics (ADR 0022) |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main`, code-owned (#127) |
| Store (0005, 0013) | cap, reserve, loss records, seal index | on `main`, code-owned; `Committed` (last durable seq, #128) |
| Collector (0007, 0016, 0017) | takes Laurel's records over a socket, never blocks Laurel | on `main` with units, code-owned; A7 closed (#125); range-only `-log-commits` and `-headroom` (#128) |
| Ledger, relay, Pi witness (0006) | signed log, cosigned off the host | not started; plan draft outside the repo |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions
- C1, C2 (ADR 0023), #135 on `main`; KVM 2 vCPU: record, refusal, ready (7.2 s), exposure, cpu, burst 3/3 PASS,
  sustained MISS. `main` CI go-test failed once after #135 on the tree its PR passed (logs unread): watch it.
## Next step
1. #136 (a store that opened takes the waiting records; a dropped probe goes out on the next tick): review
   closed, critic and Codex GO; the maintainer's approve, merge.
2. One trial run on 4 vCPU (a local commit, `-smp 4` only), then an ADR on vCPUs for trials (maintainer decides).
3. Ledger, Tessera and litewitness end to end in CI and in the range (ADR 0006), no Pi and no host yet.
   Alongside: B5, B6, a scheduled fuzz workflow (acceptance asks for it), sensor_down_s.
4. 2026-11-10 C3 = B4.9: runner reinstall (maintainer), the suite, metric verdicts in status.py; the Pi.
   2026-11-15 checkpoint: how far the witness is end to end, and the prerequisites of 9.5.
5. Host install (9.5) only when every metric the range measures passes, with balistid-install, R2 keys, an own
   filesystem for the store, x32 and io_uring, alarms and a build unit with a syscall filter. Floor 2 after acceptance/2.toml.
## Open decisions (maintainer)
- #123: the module cap measures after the download; a real bound needs a quota filesystem or a watcher (T36).
- #128: a reserve made at one `-headroom` is reused at another without resizing (`reserve()`); B5 measures it.
- sustained_rate MISS in 2 vCPU (`-smp 2`, vm.go): more vCPUs or a product limit? An ADR after one run on 4 vCPU.
- C1: `shard.Read` hashes a shard, then SQLite reopens it by path: a collector broken through T18 could swap it.
- #125: past 16 pids per cause only a count is kept (amend ADR 0017 point 4?); a read error's text is not recorded.
- Store: btrfs keeps truncated extents, an active filler takes the freed reserve (T10): own filesystem at install.
- refusal_summary_s held by 2 ms and cpu_cores at 0.468 of 0.5 in KVM: margins to watch in the suite.
- A collector killed mid-read makes a rate trial INVALID (barrier missing), not MISS: a loss it causes is not a MISS.
- shellcheck in CI is unpinned (R14). #135: a run may take the queue again once its backlog empties; keep or drop?
