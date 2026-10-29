# Status

Updated: 2026-10-29 by claude/opus-5.5 (L7)

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011, 0018-0021, 0028) | VM where agents test the recorder; the runner runs the acceptance suite itself | installed at 2c09799; CI job `range-kvm` self-tests every pull request on GitHub's KVM (#146, advisory); on `main` (#131, #132): the collector in the image, the guest reads its sealed shards, trials decide metrics (ADR 0022) |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main`, code-owned (#127) |
| Store (0005, 0013, 0029) | cap, reserve, loss records, seal index, retirement | on `main`, code-owned; `Committed` (#128); index v2 and retirement by cosign time and the host clock on `feat/retention-cosign` (L7) |
| Collector (0007, 0016, 0017) | takes Laurel's records over a socket, never blocks Laurel | on `main` with units, code-owned; A7 closed (#125); range-only `-log-commits` and `-headroom` (#128) |
| Ledger, relay, Pi witness (0006, 0026, 0027) | signed log, cosigned off the host | ledger core on `main` (#142, ff8398c): ADR 0027, `internal/anchor`, `internal/link`, collector stream, `balistid-ledger`, deploy, range fact `ledger_anchored` (KVM PASS at bf95659); relay (`internal/relay`, `balistid-relay`, deploy) with a pinned litewitness in the range on `main` (#144, 2e2f7de): `ledger_cosigned`, `fork_refused` (KVM PASS at 4fd6db0); Pi not started |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions
- #144 (R1): the relay and a pinned witness; #146 (ADR 0028): `range-kvm` self-tests each pull request on KVM.
- L7 (#147, ADR 0029): the ledger tells the collector the covered seal (frame 5); the collector checks the note
  itself and retires a shard only when the witness's and the host's clocks are both 30 days past it. KVM PASS
  (`shard_cosigned`); Opus critic rounds 1-4 fixed, Codex security GO at round 7. Awaits the maintainer's approve.
## Next step
1. Merge #147 after the approve; then announce/final and the Pi (ledger-PLAN L8-L12).
   `range-kvm` is advisory until a week of runs; then the maintainer decides whether it becomes required (0028).
   /security-audit of floor 0 as a whole before 9.5, not per pull request (maintainer, 2026-10-28).
2. Local go: go.mod pins go1.27.3; until Arch ships it, run go with GOTOOLCHAIN=local or let it download.
3. ADR 0024 (#137, 4 vCPU) on `main`; the full suite in KVM on 4 vCPU before C3. ADR 0025: cpu_cores on the host.
   Alongside: B5, B6, a scheduled fuzz workflow (acceptance asks for it), sensor_down_s.
4. 2026-11-10 C3 = B4.9: runner reinstall, the suite, metric verdicts; 2026-11-15: witness end to end, 9.5 needs.
5. Host install (9.5) only when every metric the range decides passes, with balistid-install, R2 keys, an own
   filesystem for the store, x32 and io_uring, alarms and a build unit with a syscall filter. Floor 2 after acceptance/2.toml.
## Open decisions (maintainer)
- #142: seal continuity left to the Pi; no rollover yet (R5 exception, ADR 0027); appends wait each (about 45 ms on btrfs).
- #142: the ledger socket is 0666 and serves one connection; a local flood can delay the collector's reconnect.
- #123: the module cap measures after the download; a real bound needs a quota filesystem or a watcher (T36).
- cpu_cores: ADR 0025 (#138); 0.637 of 0.5 on 4 vCPU, auditd with Laurel 0.42 (0.32 on 2): a host MISS is likely.
- C1: `shard.Read` hashes a shard, then SQLite reopens it by path: a collector broken through T18 could swap it.
- #125, #128, store on btrfs (T10), refusal_summary_s and ready_s on 4 vCPU, a killed collector's INVALID trial,
  unpinned shellcheck: as before (git log of this file).
