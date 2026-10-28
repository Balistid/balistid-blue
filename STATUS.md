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
| Ledger, relay, Pi witness (0006, 0026, 0027) | signed log, cosigned off the host | ledger core in #142 (draft): ADR 0027, `internal/anchor`, `internal/link`, collector stream, `balistid-ledger`, deploy, range fact `ledger_anchored` (KVM PASS at f06dd98); review round 2 stopped under R7 |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions
- #142: Tessera v1.0.4 with pinned licences in go_gate, x/crypto v0.52.0 and otel v1.41.0 (advisories); review round 1
  (Opus critic, Codex security) closed; round 2 found a defect its fix brought in (below).
## Next step
1. #142: redesign the collector's check of the ledger's last batch (maintainer decides, R7), then review round 3 only on it.
2. #142: Go 1.27.3 pin (GO-2026-6809 in crypto/x509, reachable through Tessera's net/http) needs the maintainer's push.
3. ADR 0024 (#137, 4 vCPU) on `main`; the full suite in KVM on 4 vCPU before C3. ADR 0025: cpu_cores on the host.
   Alongside: B5, B6, a scheduled fuzz workflow (acceptance asks for it), sensor_down_s.
4. 2026-11-10 C3 = B4.9: runner reinstall (maintainer), the suite, metric verdicts in status.py; the Pi, the relay.
   2026-11-15 checkpoint: how far the witness is end to end, and the prerequisites of 9.5.
5. Host install (9.5) only when every metric the range decides passes, with balistid-install, R2 keys, an own
   filesystem for the store, x32 and io_uring, alarms and a build unit with a syscall filter. Floor 2 after acceptance/2.toml.
## Open decisions (maintainer)
- #142 R7: the 256 MiB read-back bound can stop a valid stream for good (critic, Codex round 2); and health precedence.
- #142: seal continuity left to the Pi; no rollover yet (R5 exception, ADR 0027); appends wait each (about 45 ms on btrfs).
- #142: the ledger socket is 0666 and serves one connection; a local flood can delay the collector's reconnect.
- #123: the module cap measures after the download; a real bound needs a quota filesystem or a watcher (T36).
- cpu_cores: ADR 0025 (#138); 0.637 of 0.5 on 4 vCPU, auditd with Laurel 0.42 (0.32 on 2): a host MISS is likely.
- C1: `shard.Read` hashes a shard, then SQLite reopens it by path: a collector broken through T18 could swap it.
- #125, #128, store on btrfs (T10), refusal_summary_s and ready_s on 4 vCPU, a killed collector's INVALID trial,
  unpinned shellcheck: as before (git log of this file).
