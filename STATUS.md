# Status

Updated: 2026-10-30 by claude/opus-5.5 (#158-#161: ADR 0034, overflow flake, nightly fuzz, ADR 0035)

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011, 0018-0021, 0028) | VM where agents test the recorder; the runner runs the acceptance suite itself | installed at 2c09799; CI job `range-kvm` self-tests every pull request on GitHub's KVM (#146, advisory); on `main` (#131, #132): the collector in the image, the guest reads its sealed shards, trials decide metrics (ADR 0022) |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main`, code-owned (#127) |
| Store (0005, 0013, 0029) | cap, reserve, loss records, seal index, retirement | on `main`, code-owned; `Committed` (#128); index v2 and retirement by cosign time and the host clock on `main` (#147, L7) |
| Collector (0007, 0016, 0017) | takes Laurel's records over a socket, never blocks Laurel | on `main` with units, code-owned; A7 closed (#125); range-only `-log-commits` and `-headroom` (#128) |
| Ledger, relay, Pi witness (0006, 0026, 0027, 0030, 0031) | signed log, cosigned off the host | ledger core on `main` (#142, ff8398c): ADR 0027, `internal/anchor`, `internal/link`, collector stream, `balistid-ledger`, deploy, range fact `ledger_anchored` (KVM PASS at bf95659); relay (`internal/relay`, `balistid-relay`, deploy) with a pinned litewitness in the range on `main` (#144, 2e2f7de): `ledger_cosigned`, `fork_refused` (KVM PASS at 4fd6db0); announce, final, rollover, old-log retention on `main` (#148, b4d9ca3); the Pi's watcher `balistid-pi` and the relay's bundle server (ADR 0031) on `main` (#150, 3a6d88b), range fact `pi_verified`; L10 on `main` (#153, 6854cdf; ADR 0032): `balistid-net`, the relay-only nftables table and the WireGuard tunnel, facts `pi_reach`, `ledger_net` |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions
- #155 (a5a8502), #156 (ADR 0033). #159: overflow_journal read once raced auditd's syslog line (range-kvm failed on
  a docs-only commit); now a journal cursor before the flood and only _SYSTEMD_UNIT/_EXE/_UID=0 lines, bounded wait.
- #160: nightly fuzz of all 30 targets (60 min host and Pi parsers, 10 min guest); a test pins the matrix. #158 ADR
  0034: T27 narrowed to failure (A6); dead-man ping from the Pi, ntfy probe every 30 min; dead_site_alarm_s 900,
  push_refused_alarm_s 2700. #161 ADR 0035: review threat scoped to the change, maintainer decides before round 3.
- cpu-1000 trend 0.70 on 4 vCPU; write_logs=no saves only 0.04; log_format=RAW breaks the store barrier (ENRICHED).
## Next step
1. L11 range e2e (ledger plan): decide first 24 h trials vs the 30 min trial wall, power-off without the Pi in the
   VM, an ntfy sink in the Pi namespace, loss injection with locked rules; then L12 the Pi (balistid-pi by its CI hash).
2. `range-kvm` advisory until a week of runs, then the maintainer decides on required (0028). /security-audit of floor
   0 as a whole before 9.5. Fuzz: only a fuzzed commit is installed (9.5); seeds in testdata/fuzz, not .jsonl.
3. 2026-11-10 C3 = B4.9: runner reinstall, the suite, metric verdicts; 2026-11-15: witness end to end, 9.5 needs.
4. Host install (9.5) only when every metric the range decides passes, with balistid-install (its ADR sets the install
   numbers), R2 keys, an own filesystem for the store, x32 and io_uring, alarms and a build unit with a syscall filter.
## Open decisions (maintainer)
- #142: seal continuity left to the Pi; appends wait each (about 45 ms on btrfs). #148: `-final` ends anchoring until rollover.
- #142: the ledger socket is 0666 and serves one connection; a local flood can delay the collector's reconnect.
- #123: the module cap measures after the download; a real bound needs a quota filesystem or a watcher (T36).
- cpu_cores: ADR 0025 (#138); 0.70 of 0.5 on 4 vCPU, auditd with Laurel 0.46: a host MISS is likely.
- C1: `shard.Read` hashes a shard, then SQLite reopens it by path: a collector broken through T18 could swap it.
- #125, #128, store on btrfs (T10), refusal_summary_s and ready_s on 4 vCPU, a killed collector's INVALID trial,
  unpinned shellcheck: as before (git log of this file).
