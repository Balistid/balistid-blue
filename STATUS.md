# Status

Updated: 2026-10-03 by claude/opus-5.5

## Where we are

Floor 0 (recorder) designed, acceptance numbers approved, Go toolchain and gates live. The attack range
of ADR 0009 is merged (PR #15). This pull request puts the floor-0 sensor (auditd + Laurel, ADR 0004 as
amended in #17) into the range image and smoke-tests it; a run on the maintainer's host passed every check
on kernel 7.2.8-arch1-2. ADR 0004 and 0009 stay proposed until the follow-up pull request accepts them
with a run from `main`.

## Done in the last session

- PR #15: range launcher, guest, mkosi image (step 9.1). PR #16: acceptance numbers marked approved.
  PR #17: ADR 0004 amended (Laurel release binary, io_uring disabled, socket check with the collector).
- This pull request: Laurel package, audit rules and configuration in `deploy/`, sensor smoke checks.
  The smoke test found that Arch's `audit` lacks a `gawk` dependency (rules silently not loaded) and that
  `audit=1` needs a boot-time `audit_backlog_limit`.

## Next step

1. After merge: build and run from `main`, then accept ADR 0004 and 0009 citing that result.
2. Step 9.3: `kordon-collector` and raw SQLite shards (ADR 0005), against `acceptance/0.toml`.
3. Before the host install (9.5): x32 ABI mitigation (THREAT_MODEL T8) and whether the host runs without io_uring.

## Open decisions (maintainer)

- Project name.
- Hardware signing keys for R2 (budget approved in principle).
