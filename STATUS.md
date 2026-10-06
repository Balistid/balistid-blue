# Status

Updated: 2026-10-06 by claude/opus-5.5

## Where we are

Floor 0 (recorder): the attack range (ADR 0009), the sensor (auditd + Laurel, ADR 0004) and the build from a
verified export (ADR 0010) are accepted. The range runner of ADR 0011 (proposed) is written and tested end to
end by hand from `main` (cf92ed0): its own image built by `balistid-runner build`, an evidence run PASS on
7.2.8-arch1-2, and an agent exec job RAN with its 5 s `timeout_s` enforced in the guest and its output and Laurel
records escaped in its result. It is not installed: it ran at the maintainer's uid, which proves function, not
trust. No recorder code yet.

## Done in the last session

- #38–#44: job disk carries `timeout_s`; strict exec report and `Printable`; ledger on disk (schema 2, evidence
  latch, pending runs, failed commits); admission and memory watch (reserves 4 GiB memory, 5 GiB disk);
  `BuildCommit`/`OpenImage`; results the maintainer's group reads; `cmd/balistid-runner` (`build`, `tick`).
- Accepted residuals (#44): a FAIL is lost only if both its result write and the ledger save fail; small clock
  set-backs before evidence falls due postpone it (needs clock control, T22); `Next` does not log rejections.
- `THREAT_MODEL.md` (9596/9600 bytes) and ADR 0011 (60/60 lines) are at their caps.
- Step C: `go list -deps` gate and release with sha256 for the runner (64fb238); `deploy/runner/` build and
  tick units, timer, sysusers, tmpfiles, pinned by a test. Checked with `systemd-analyze verify`, not yet run
  under systemd. The tick unit has no ProtectKernelTunables/Logs: they make bwrap's `--proc` fail (EPERM).

## Next step

1. Go fix: at a system uid mkosi 27 likely puts its package cache in `/var/cache` (read from its code, not
   run); set the cache in `toolEnv`.
2. Install manifest and procedure, then a first real build and tick under these units: setuid files in the
   image; hardening to test there (SystemCallFilter, RestrictAddressFamilies, PrivateIPC, ProtectProc,
   ProtectHostname, RemoveIPC, ReadOnlyPaths on images). Then acceptance (PR 13).
3. Step 9.3: `balistid-collector` and raw SQLite shards (ADR 0005), against `acceptance/0.toml`.

## Open decisions (maintainer)

- Renaming the repo and the product (org is `Balistid`).
- Hardware signing keys for R2 (budget approved in principle).
- Before the host install: x32 mitigation, and whether the host runs without io_uring.
- Raise the caps of `THREAT_MODEL.md` and ADRs (needs an ADR).
