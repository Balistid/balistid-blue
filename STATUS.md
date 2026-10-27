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
- C1, C2 (ADR 0023), #135, #136, #137 on `main`. KVM 2 vCPU: record, refusal, ready, exposure, cpu, burst PASS, sustained
  MISS; 4 vCPU (c9fdf5e): sustained, burst, kill-1, reset-1 PASS, cpu-1000 MISS. `main` go-test failed once: watch.
## Next step
1. ADR 0024 (#137, the range on 4 vCPU) on `main` 9f4a7a7; the full suite in KVM on 4 vCPU before C3.
2. ADR 0025: cpu_cores decided on the reference host after install; cpu-1000 stays in the range as a trend.
3. Ledger, Tessera and litewitness end to end in CI and in the range (ADR 0006), no Pi and no host yet.
   Alongside: B5, B6, a scheduled fuzz workflow (acceptance asks for it), sensor_down_s.
4. 2026-11-10 C3 = B4.9: runner reinstall (maintainer), the suite, metric verdicts in status.py; the Pi.
   2026-11-15 checkpoint: how far the witness is end to end, and the prerequisites of 9.5.
5. Host install (9.5) only when every metric the range measures passes, with balistid-install, R2 keys, an own
   filesystem for the store, x32 and io_uring, alarms and a build unit with a syscall filter. Floor 2 after acceptance/2.toml.
## Open decisions (maintainer)
- #123: the module cap measures after the download; a real bound needs a quota filesystem or a watcher (T36).
- #128: a reserve made at one `-headroom` is reused at another without resizing (`reserve()`); B5 measures it.
- cpu_cores 0.637 of 0.5 on 4 vCPU, 0.468 on 2 (auditd with Laurel about 0.42): it follows the vCPUs (ADR 0024).
- C1: `shard.Read` hashes a shard, then SQLite reopens it by path: a collector broken through T18 could swap it.
- #125: past 16 pids per cause only a count is kept (amend ADR 0017 point 4?); a read error's text is not recorded.
- Store: btrfs keeps truncated extents, an active filler takes the freed reserve (T10): own filesystem at install.
- refusal_summary_s held by 2 ms and ready_s 7.2 s on 2 vCPU: measured again on 4.
- A collector killed mid-read makes a rate trial INVALID (barrier missing), not MISS: a loss it causes is not a MISS.
- shellcheck in CI is unpinned (R14).
