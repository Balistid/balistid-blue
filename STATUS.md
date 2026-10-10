# Status

Updated: 2026-10-10 by claude/opus-5.5

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011) | VM where agents test the recorder | installed at c00f59e; fixes in #75 |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main` (#56, #63) |
| Store (0005, 0013) | cap, reserve, loss records, seal index | on `main` (#71, #72), hard cap |
| Collector (0007) | takes Laurel's records over a socket | not started |
| Ledger, relay, Pi witness (0006) | signed log, cosigned off the host | not started |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions

- Runner security review fixes (#75): the tick unit's syscall filter is an allowlist (`@system-service
  @mount` minus keyrings, AIO, `process_vm_*`, EPERM); a logging-only filter on the installed unit saw no
  call outside it. Each tick probes four denied calls as a tripwire for a missing or deny-list filter; the
  whole filter rests on the pinned unit text and the hash-checked install (maintainer, 10.10.). The
  install writes each file beside its target and renames it. Opus critic, Codex two rounds.
- ADR 0014 (#76): `THREAT_MODEL.md` cap 100 lines.
- Store on `main` (#71, #72); ADR 0013 (#67, #69); Go 1.27.2 (#68); install refuses drop-ins (#64).

## Next step

1. Merge #75 and #76. Remove the two probe drop-ins on the tick unit, reinstall from the push run:
   evidence PASS, no "confinement missing" in the journal. Then PR 13's runs on that commit and ADR 0011.
2. 9.3: the collector (Laurel socket, Flush ticker, seals to the ledger), then ledger and Pi witness.
## Open decisions (maintainer)

- The build unit has no syscall filter, yet runs a commit's PKGBUILD and mkosi: its own change.
- `test_release.py` bootstrap cleanup removes every `/tmp/balistid-install.*`, also other runs'.
- Does `systemd_exposure` (2.5) cover the runner? Install skips .wants/.requires (root-only).
- Renaming the repo and product; R2 signing keys; before floor 0's host install: x32 mitigation, io_uring.
- Store: a full filesystem under the cap needs a range test (`headroom_gib`); index format for deleted shards.
