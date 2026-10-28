# Status

Updated: 2026-10-28 by claude/opus-5.5

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
| Ledger, relay, Pi witness (0006, 0026, 0027) | signed log, cosigned off the host | ledger core on `main` (#142, ff8398c): ADR 0027, `internal/anchor`, `internal/link`, collector stream, `balistid-ledger`, deploy, range fact `ledger_anchored` (KVM PASS at bf95659); relay (`internal/relay`, `balistid-relay`, deploy) with a pinned litewitness in the range on feat/relay: `ledger_cosigned`, `fork_refused` (KVM PASS at 8989d16); Pi not started |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions
- #142 merged (ff8398c). R1 on feat/relay: the relay carries checkpoints to the witness and keeps the cosigned one;
  range/witness pins torchwood v0.10.0 as its own module, built per module against its own go.sum.
## Next step
1. R1: review (Opus critic, Codex security), the maintainer's approval, merge. Then an ADR for the runner building
   a commit an agent asks for, then retention from cosign times, announce/final and the Pi (ledger-PLAN L7-L12).
   /security-audit of floor 0 as a whole before 9.5, not per pull request (maintainer, 2026-10-28).
2. Local go: go.mod pins go1.27.3; until Arch ships it, run go with GOTOOLCHAIN=local or let it download.
3. ADR 0024 (#137, 4 vCPU) on `main`; the full suite in KVM on 4 vCPU before C3. ADR 0025: cpu_cores on the host.
   Alongside: B5, B6, a scheduled fuzz workflow (acceptance asks for it), sensor_down_s.
4. 2026-11-10 C3 = B4.9: runner reinstall (maintainer), the suite, metric verdicts in status.py; the Pi, the relay.
   2026-11-15 checkpoint: how far the witness is end to end, and the prerequisites of 9.5.
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
