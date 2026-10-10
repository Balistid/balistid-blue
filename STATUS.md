# Status

Updated: 2026-10-10 by claude/opus-5.5

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011) | VM where agents test the recorder | ADR 0011 accepted; installed at 506f775 |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main` (#56, #63) |
| Store (0005, 0013) | cap, reserve, loss records, seal index | on `main` (#71, #72), hard cap |
| Collector (0007) | takes Laurel's records over a socket | not started |
| Ledger, relay, Pi witness (0006) | signed log, cosigned off the host | not started |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions

- Store commits in batches: per Flush (250 ms) or 2 MiB, not per record; 1 KiB records 157 → ~17500/s
  (btrfs/NVMe, maintainer's machine, not the range). A record is durable after Flush. `rss_mib` at burst
  with 64 KiB records is offered load: drops allowed and counted (maintainer, 10.10.). Benchmark #87.
- #86: a run directory left behind no longer turns a verdict into INVALID. Runner installed at 506f775.
- #75: the tick's syscall filter is an allowlist, four denied calls probed each tick as a tripwire;
  Codex's second NO-GO (no `process_vm_writev` probe) stays open by the maintainer's decision (10.10.).
- ADR 0011 accepted: 22 runs PASS on 506f775, exec memory job RAN, no OOM kill. Agent quota 24 a day,
  ledger 768, 24 results kept (#78; an older build refuses a ledger over 256). ADR 0014 (#76).

## Next step
1. 9.3: the collector (Laurel socket, Flush ticker, seals to the ledger), then ledger and Pi witness. Built
   in from the start: a versioned socket protocol, store and ledger migrations with a tested rollback, a
   throughput metric; the normalizer redacts secrets before the derived DB, which agents can read (T6).
   It calls Flush every FlushEvery and Close with a live context; a bounded queue drops and counts.
## Open decisions (maintainer)

- The build unit has no syscall filter, yet runs a commit's PKGBUILD and mkosi: its own change.
- `test_release.py` bootstrap cleanup removes every `/tmp/balistid-install.*`, also other runs'.
- Does `systemd_exposure` (2.5) cover the runner? Install skips .wants/.requires (root-only).
- Moving the repo and Go module to the BALISTID name (chosen 4.10.); R2 signing keys; before floor 0's host install: x32 mitigation, io_uring.
- Store: a full filesystem under the cap needs a range test (`headroom_gib`); index format for deleted shards.
