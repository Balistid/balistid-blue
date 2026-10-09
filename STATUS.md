# Status

Updated: 2026-10-09 by claude/opus-5.5

## Where we are

Floor 0 (recorder): the attack range (ADR 0009), the sensor (auditd + Laurel, ADR 0004), the build from a
verified export (ADR 0010) are accepted; the range runner (ADR 0011, proposed) is installed on the host from
the CI bundle at 88f42a6. Its build cap is met; its job cap needs the last 20 runs on 88f42a6 (PR 13). Step 9.3
has started: the raw record encoding and the SQLite shard are on `main`; the collector does not exist yet.

## Done in the last sessions

- Runner: install bundle (#52), inbox 2750 with pinned ACLs (#50), first-install faults (#53); evidence FAIL
  saved before its result and a tick's own result kept when the clock is set back (#57); the overlay step's
  output kept in its INVALID reason (#55); MemoryHigh dropped from the tick unit (#62).
- PR 13: 1 evidence run PASS on 88f42a6; the day's 8 agent jobs ran under a test drop-in and ended INVALID
  (below). Root probes: build under MemoryMax=3G and a job under MemoryMax=2560M both end in
  oom-kill (1.3 s, 0.97 s), the only OOM kills in the kernel log. With MemoryHigh=2304M and no swap a job
  over it stalled 5 min instead (hence #62). Tick peak 2.2G: 2071M anon, the rest base-image page cache.
- CI: the release needs every other check (#60); a weekly run on main for govulncheck (#61).
- 9.3: `internal/rawrecord` (#56, leaf `balistid/raw/v1`, vectors computed outside Go) and `internal/shard`
  with modernc.org/sqlite (#63): gap-free append, seal, read only with the seal hash.
- The install refuses a unit with drop-ins or a foreign fragment, before writing and after its reload (#64).

## Next step

1. Tick hardening (#65): under a drop-in every job was INVALID, "bwrap: Can't mount proc on /proc" from
   ProtectHostname (a mount over /proc); dropped. Probe the other five directives, test again, then PR 13's
   20 runs on 88f42a6 (agent quota 8 per 24 h), accept ADR 0011, reinstall with #64 and #65.
2. 9.3: the store (cap, reserve, loss records; branch feat/store, two critic rounds NO-GO) needs the ledger's
   set of sealed hashes and a collector ticker first: decide that interface (ADR), then finish the store.

## Open decisions (maintainer)

- Does `systemd_exposure` (2.5) cover the runner's units? The build unit needs the network for mkosi.
- Dependency directories (.wants/, .requires/) of the runner units are not checked by the install.
- Renaming the repo and the product (org is `Balistid`); hardware signing keys for R2.
- Before the host install of floor 0: x32 mitigation, and whether the host runs without io_uring.
- Raise the caps of `THREAT_MODEL.md` and ADRs (needs an ADR).
