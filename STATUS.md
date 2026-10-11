# Status

Updated: 2026-10-11 by claude/opus-5.5

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011) | VM where agents test the recorder | ADR 0011 accepted; installed at 506f775 |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main` (#56, #63) |
| Store (0005, 0013) | cap, reserve, loss records, seal index | on `main` (#71, #72), hard cap |
| Collector (0007, 0016, 0017) | takes Laurel's records over a socket, never blocks Laurel | ADRs 0016, 0017 proposed |
| Ledger, relay, Pi witness (0006) | signed log, cosigned off the host | not started |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions
- ADR 0016 (collector): socket activation, a reader that never blocks Laurel (a full queue drops and counts),
  lines stored as evidence, loss counted per stage, store failure drains and retries, canary without exec. Laurel
  0.8.2, auditd 4.2.1 and kernel source showed that blocking Laurel moves loss to auditd, uncounted, and can freeze
  the host; it amends ADR 0007 points 2 and 5. ADR 0017: health from the collector's own canary. ADR 0016 proposes a
  scheduled CI workflow for `fuzz_hours`.
- Store commits per Flush (250 ms) or a page budget (#88): 1 KiB records 157 → ~18000/s (btrfs/NVMe, maintainer's
  machine, not the range). `burst_rate` stays zero loss; at 64 KiB records `rss_mib` load may drop, counted.
- ADR 0015 (#90): store, shard, collector and normalizer merge without the maintainer until installed.
## Next step
1. Collector in agent-merged pull requests (ADR 0015): `Store.Append` takes a record; acceptor, reader, queue and
   loss counters with fuzz seeds; writer, health, canary, reopen, shutdown and `cmd/balistid-collector`. Each with
   an Opus critic and a Codex full review. Then the fuzz workflow (maintainer pushes it), the whole-source review.
2. Deployment and range (owned, after the review): units and the `.socket` grammar, Laurel `unix:`, the canary rule,
   go_gate for the SQLite module, the range image with the collector, kill -9 and hard-reset trials.
## Open decisions (maintainer)
- The build unit has no syscall filter, yet runs a commit's PKGBUILD and mkosi: its own change.
- Runner: #86 waits for the next reinstall; Codex's process_vm_writev NO-GO on the tick filter (#75) is open.
- `test_release.py` bootstrap cleanup removes every `/tmp/balistid-install.*`, also other runs'.
- Does `systemd_exposure` (2.5) cover the runner? Install skips .wants/.requires (root-only).
- R2 signing keys; before floor 0's host install: x32 mitigation, io_uring.
- Store: a full filesystem under the cap needs a range test (`headroom_gib`); index format for deleted shards.
- shellcheck in CI is unpinned (`.github/workflows/ci.yml:336`), against R14; a workflow change is the maintainer's.
