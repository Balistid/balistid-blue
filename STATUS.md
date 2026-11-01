# Status

Updated: 2026-11-01 by claude/opus-5.5 (#184, #185 ADRs 0041-0042; #186 CP4 on `main`; CP5a: this PR)

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
- #186 CP4 (c9a2258): the collector logs kernel and dispatcher loss and reasons 8-10 from auditstat's report.
- #184 (ADR 0041): CI on `merge_group`, fuzz matrix from the test source; the queue waits for the ruleset switch.
  #185 (ADR 0042): an owned approval rests on the summary and verdicts; gate changes keep one Opus critic.
- #175 balistid-auditstat on `main` (2a2fac7); audit-set (#180, fff816a): under -e 2 auditstat's uid gets EPERM for every
  lock gate, EEXIST for the pid, EPERM for user messages, and may still reset lost and flip loginuid (KVM PASS).
## Next step
1. auditstat CP5a here: `-queue-bytes` (79bf743), then the guest's `lost` and flag brackets, kernel and dispatcher
   judged, 10 runs each; CP5b four auditd crashes and `loss_alarm_s`, which closes before 9.5 (ADR 0040).
2. `range-kvm` advisory until a week of runs, then required (0028). /security-audit of floor 0 before 9.5.
3. Before L12, CPU (ADR 0040): cpu_cores 0.70 of 0.5, auditd with Laurel 0.46; a time-boxed fit, else
   an ADR on the data source (reopens 0004); then the local-mode ADR. 2026-11-10 C3 = B4.9 (reinstall, suite, verdicts).
4. Host install (9.5) when every range metric and the product bar pass: balistid-install, R2 keys, the store on the
   existing fs with its reserve, x32, io_uring, alarms, a syscall-filtered build unit; L12 and the witness e2e after it.
## Open decisions (maintainer)
- #142: seal continuity left to the Pi; appends wait each (about 45 ms on btrfs). #148: `-final` ends anchoring until rollover.
- #142: the ledger socket is 0666 and serves one connection; a local flood can delay the collector's reconnect.
- #123: the module cap measures after the download; a real bound needs a quota filesystem or a watcher (T36).
- C1: `shard.Read` hashes a shard, then SQLite reopens it by path: a collector broken through T18 could swap it.
- #170: another writer filling the store's fs past its statfs check: SQLITE_FULL, UNKNOWN (ADR 0016 pt 4); T10 residual.
- #125, #128, store on btrfs (T10), refusal_summary_s and ready_s on 4 vCPU, a killed collector's INVALID trial,
  unpinned shellcheck: as before (git log of this file).
