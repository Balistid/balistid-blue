# Status

Updated: 2026-10-31 by claude/opus-5.5 (L11: #163 ADR 0036, #165 alarm trials, #167 ADR 0037, #168 log cap, #170 loss)

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
- L11 (ADR 0036): range trials time the Pi's alerts at an ntfy sink in its namespace. #165 on `main`: silence 3
  trials PASS at 840.8-840.9 s, quiet-off/-masked/-again trends PASS at 20:00.8-20:02.5 (KVM via ADR 0037 dispatch).
- #168 L11c: the log at its cap logs reason 7 before final, alerted as `logcap`; `-cap-bytes` range-only; log-cap
  PASS 2/2. #170 L11b (on 4cfba3b): full-fs PASS 6/6 at 4.1-5.4 s, store 2/2 at 6.3-6.4 s, control PASS; kernel and
  dispatcher INVALID (no detector); queue INVALID (dispatcher overflows first); a full fs's store-down INVALID.
- #167 ADR 0037: `range-trial` on `repository_dispatch` (main's definition, payload checked), the bot dispatches it.
## Next step
1. Merge #170 (maintainer approve). The store's disk full in a shard write (below), its own change. Then
   balistid-auditstat (ADR 0007): kernel/dispatcher loss, per-stage alert keys, a socket writer for loss-queue, 10-run shapes.
2. `range-kvm` advisory until a week of runs, then required (0028). /security-audit of floor 0 before 9.5.
3. 2026-11-10 C3 = B4.9: runner reinstall, the suite, metric verdicts; 2026-11-15: witness end to end, 9.5 needs.
4. Host install (9.5) only when every metric the range decides passes, with balistid-install (its ADR sets the install
   numbers), R2 keys, an own filesystem for the store, x32 and io_uring, alarms and a build unit with a syscall filter.
## Open decisions (maintainer)
- #142: seal continuity left to the Pi; appends wait each (about 45 ms on btrfs). #148: `-final` ends anchoring until rollover.
- #142: the ledger socket is 0666 and serves one connection; a local flood can delay the collector's reconnect.
- #123: the module cap measures after the download; a real bound needs a quota filesystem or a watcher (T36).
- cpu_cores: ADR 0025 (#138); 0.70 of 0.5 on 4 vCPU, auditd with Laurel 0.46: a host MISS is likely.
- C1: `shard.Read` hashes a shard, then SQLite reopens it by path: a collector broken through T18 could swap it.
- #170: a fill after the store's statfs check breaks the shard's SQLite commit (disk full): UNKNOWN, not its cap.
- #125, #128, store on btrfs (T10), refusal_summary_s and ready_s on 4 vCPU, a killed collector's INVALID trial,
  unpinned shellcheck: as before (git log of this file).
