# Status

Updated: 2026-10-09 by claude/opus-5.5

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011) | VM where agents test the recorder | runner installed at 511a02f; PR 13 runs 10.10. |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main` (#56, #63) |
| Store (0005, 0013) | cap, reserve, loss records, seal index | on `main` (#71, #72), hard cap |
| Collector (0007) | takes Laurel's records over a socket | not started |
| Ledger, relay, Pi witness (0006) | signed log, cosigned off the host | not started |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions

- Go 1.27.2 for GO-2026-6604 (#68). The install refuses a unit with drop-ins or a foreign fragment,
  before writing and after its reload (#64).
- Tick unit hardening (#65): SystemCallFilter, RestrictAddressFamilies, IPAddressDeny, PrivateIPC,
  RemoveIPC. ProtectHostname breaks bwrap's /proc mount, but only together with the unit's own mount
  directives (root probe, comment on #65). Reinstalled at 511a02f: evidence run PASS under it.
- ADR 0013 (#67, #69): a fsynced seal index beside the shards, losses flushed every 250 ms by the
  collector, recovery that never deletes rows still in a WAL; three critic rounds.
- Earlier: runner install bundle and inbox (#50, #52, #53), FAIL saved before result (#57), MemoryHigh
  dropped (#62), weekly govulncheck (#61), raw record and shard (#56, #63).

## Next step

1. Runner security review (Codex, 9.10.): syscall allowlist instead of the deny-list, units written via
   temp file and rename, a real rollback, a test of the real unit; then PR 13's 21 runs and ADR 0011.
2. 9.3: the collector (Laurel socket, Flush ticker, seals to the ledger), then ledger and Pi witness.
## Open decisions (maintainer)

- Does `systemd_exposure` (2.5) cover the runner? Install skips .wants/.requires (root-only).
- Renaming the repo and product; R2 signing keys; before floor 0's host install: x32 mitigation, io_uring.
- Raise the caps of `THREAT_MODEL.md` and ADRs (needs an ADR).
- Store: a full filesystem under the cap needs a range test (`headroom_gib`); index format for deleted shards.
