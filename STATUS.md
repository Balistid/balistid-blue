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
- Store commits per Flush (250 ms) or a page budget, not per record (#88): 1 KiB records 157 → ~18000/s
  (btrfs/NVMe, maintainer's machine, not the range); durable after Flush; WAL header checked (#89).
  `rss_mib` at burst with 64 KiB records is offered load: drops allowed and counted (maintainer, 10.10.);
  `burst_rate` stays zero loss (maintainer, 10.10.).
- ADR 0015 (#90): store, shard, collector and normalizer merge without the maintainer until installed.
- #75: tick syscall filter is an allowlist with four tripwire probes; Codex's process_vm_writev NO-GO open.
- ADR 0011 accepted (22 PASS on 506f775, installed; #86 waits for the next reinstall); quota 24/day (#78).
## Next step
1. 9.3: the collector (Laurel socket, Flush ticker, seals to the ledger), then ledger and Pi witness. Built
   in from the start: a versioned socket protocol, store and ledger migrations with a tested rollback, a
   throughput metric; the normalizer redacts secrets before the derived DB, which agents can read (T6).
   It calls Flush every FlushEvery and Close with a live context. A full bounded queue stops reading the socket,
   so Laurel blocks (ADR 0007 point 5, maintainer, 10.10.); records drop only at the store cap, with a loss record
   (ADR 0005 point 4). Laurel 0.8.2 connects to it (`file = "unix:…"`, deploy config still writes a file), dies
   after ~25 s of failed reconnects, auditd restarts it at most 10 times (`max_restarts`): absence must read UNKNOWN.
## Open decisions (maintainer)
- The build unit has no syscall filter, yet runs a commit's PKGBUILD and mkosi: its own change.
- `test_release.py` bootstrap cleanup removes every `/tmp/balistid-install.*`, also other runs'.
- Does `systemd_exposure` (2.5) cover the runner? Install skips .wants/.requires (root-only).
- R2 signing keys; before floor 0's host install: x32 mitigation, io_uring.
- Store: a full filesystem under the cap needs a range test (`headroom_gib`); index format for deleted shards.
- shellcheck in CI is unpinned (`.github/workflows/ci.yml:336`), against R14; a workflow change is the maintainer's.
