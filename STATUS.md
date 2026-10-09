# Status

Updated: 2026-10-09 by claude/opus-5.5

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011) | VM where agents test the recorder | runner installed at 88f42a6; PR 13 open |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main` (#56, #63) |
| Store (0005, 0013) | cap, reserve, loss records | branch `feat/store`; waits for ADR 0013 |
| Collector (0007) | takes Laurel's records over a socket | not started |
| Ledger, relay, Pi witness (0006) | signed log, cosigned off the host | not started |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions

- Runner: install bundle (#52), inbox 2750 with pinned ACLs (#50), first-install faults (#53); evidence FAIL
  saved before its result and a tick's own result kept when the clock is set back (#57); the overlay step's
  output kept in its INVALID reason (#55); MemoryHigh dropped from the tick unit (#62).
- PR 13: 1 evidence run PASS on 88f42a6; the day's 8 agent jobs ran under a test drop-in and ended INVALID
  (below). Root probes: build under MemoryMax=3G and a job under MemoryMax=2560M both end in
  oom-kill (1.3 s, 0.97 s), the only OOM kills in the kernel log. With MemoryHigh=2304M and no swap a job
  over it stalled 5 min instead (hence #62). Tick peak 2.2G: 2071M anon, the rest base-image page cache.
- CI: release after every other check (#60); weekly govulncheck run (#61), which found GO-2026-6604.
- The install refuses a unit with drop-ins or a foreign fragment, before writing and after its reload (#64).

## Next step

1. Tick hardening (#65): under a drop-in every job was INVALID, "bwrap: Can't mount proc on /proc" from
   ProtectHostname (a mount over /proc); dropped. Probe the other five directives, test again, then PR 13's
   20 runs on 88f42a6 (agent quota 8 per 24 h), accept ADR 0011, reinstall with #64 and #65.
2. 9.3: the store (cap, reserve, loss records; branch feat/store, two critic rounds NO-GO) needs the ledger's
   set of sealed hashes and a collector ticker first: decide that interface (ADR), then finish the store.
## Open decisions (maintainer)

- Does `systemd_exposure` (2.5) cover the runner? Install skips .wants/.requires (root-only).
- Renaming the repo and product; R2 signing keys; before floor 0's host install: x32 mitigation, io_uring.
- Raise the caps of `THREAT_MODEL.md` and ADRs (needs an ADR).
