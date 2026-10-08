# Status

Updated: 2026-10-08 by claude/opus-5.5

## Where we are

Floor 0 (recorder): the attack range (ADR 0009), the sensor (auditd + Laurel, ADR 0004) and the build from a
verified export (ADR 0010) are accepted. The range runner of ADR 0011 (proposed) is installed on the host from
the CI bundle (#52) and runs under its units: build of 16258e2 at 1.7 GiB peak (cap 3 GiB), evidence PASS
under the tick unit, timer enabled. Acceptance of its two memory metrics (PR 13) is running. No recorder code yet.

## Done in the last session

- #52 install bundle, #50 inbox 2750 in the runner's group with pinned ACLs, #53 the first install's faults
  (sysusers.d entry, no RestrictSUIDSGID on the tick: bwrap's open_tree got ENOSYS).
- PR 13 so far: 16 of 16 runs on 16258e2 PASS (five run jobs of 3 trials and one evidence run), tick
  peaks 1.4-2.2 GiB; two run jobs wait for the quota. Three exec jobs that fill guest memory ran; the tick unit's cgroup peaked at
  2071 MiB anon plus base-image page cache, which MemoryHigh (2304M) reclaims; no OOM, MemoryMax 2560M kept.
- A job unit inside the guest has MemoryMax=1G, so no job alone touches all 2048 MiB; the fill jobs use pipes
  and page cache instead of streaming /dev/zero, which a seekable device lets tail do without holding it.
- `systemd-analyze security` offline: tick 4.5, build 4.6. A tick hardening (syscall deny list, AF_UNIX and
  AF_NETLINK, IPAddressDeny, ProtectHostname, PrivateIPC, RemoveIPC) scores 2.5; not yet run under the unit.

## Next step

1. Finish PR 13: the remaining run jobs (agent quota is 8 per 24 h), then the root probes: build and job caps
   end in oom-kill with no OOM kill outside them, and `systemd-analyze security` of the installed units.
2. Run one evidence run and one job under the tick hardening, then open it as a pull request.
3. Step 9.3: `balistid-collector` and raw SQLite shards (ADR 0005), against `acceptance/0.toml`. Laurel
   0.8.2 can write to a Unix socket (`file = "unix:..."`); the range guest still reads its log file.

## Open decisions (maintainer)

- Does `systemd_exposure` (2.5) cover the runner's units? The build unit needs the network for mkosi.
- Accept ADR 0011 once PR 13 passes.
- Renaming the repo and the product (org is `Balistid`); hardware signing keys for R2.
- Before the host install of floor 0: x32 mitigation, and whether the host runs without io_uring.
- Raise the caps of `THREAT_MODEL.md` and ADRs (needs an ADR).
