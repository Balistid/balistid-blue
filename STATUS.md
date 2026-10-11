# Status

Updated: 2026-10-11 (evening) by claude/opus-5.5

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011) | VM where agents test the recorder | ADR 0011 accepted; installed at 506f775; ADR 0018 trials proposed |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main` (#56, #63) |
| Store (0005, 0013) | cap, reserve, loss records, seal index | on `main` (#71, #72), hard cap |
| Collector (0007, 0016, 0017) | takes Laurel's records over a socket, never blocks Laurel | store side #94; core in the CP2 pull request, not in an image |
| Ledger, relay, Pi witness (0006) | signed log, cosigned off the host | not started |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions
- Collector master plan (Opus critic and Codex, two rounds each, GO): checkpoints CP1 store side, CP2 collector core,
  CP3 gates and units, CP4 range; acceptance proof path per metric. Kept outside the repo with the maintainer.
- #94 (CP1): `rawrecord.FromParts` and `Record.Check`, `Store.Append(record)` with `ErrRefused`, `store.ReadSeals`.
- CP2: `internal/collector` (lines as evidence, byte-bounded queue that never blocks, SO_PEERCRED acceptor, one
  writer owning the store, losses per stage, canary health with exact-key Laurel parsing, reopen, watchdog) and
  `cmd/balistid-collector` (socket from systemd, READY, stop within 100 ms). Opus critic 2 rounds GO.
## Next step
1. Merge #94 (maintainer approves owned `internal/rawrecord/`), then the CP2 pull request after its Codex review.
2. CP3, owned: `*.socket` gate, go_gate for the SQLite modules, units, sysusers, tmpfiles (MASTER_PLAN B1-B3).
3. Laurel spike outside the sandbox (fixtures, line lengths, `\x01` keys); range trials with ADR 0018 (B4).
## Open decisions (maintainer)
- The build unit has no syscall filter, yet runs a commit's PKGBUILD and mkosi: its own change.
- Runner: #86 waits for the next reinstall; Codex's process_vm_writev NO-GO on the tick filter (#75) is open.
- `test_release.py` bootstrap cleanup removes every `/tmp/balistid-install.*`, also other runs'.
- Does `systemd_exposure` (2.5) cover the runner? Install skips .wants/.requires (root-only).
- R2 signing keys; before floor 0's host install: x32 mitigation, io_uring.
- Store: a full filesystem under the cap needs a range test (`headroom_gib`); index format for deleted shards.
- shellcheck in CI is unpinned (`.github/workflows/ci.yml:336`), against R14; a workflow change is the maintainer's.
