# Status

Updated: 2026-10-04 by claude/opus-5.5

## Where we are

Floor 0 (recorder): the attack range (ADR 0009), the sensor (auditd + Laurel, ADR 0004) and the build from a
verified export (ADR 0010) are merged and accepted; range run 20261004T203204Z-9fb1da84, built and run from
`main` (bde5578, kernel 7.2.8-arch1-2), passed every check. No recorder code yet.

## Done in the last session

- PR #22: the range builds only the launcher's own commit, from a verified export (ADR 0010). PR #23:
  `internal/rangeguest` code-owned. This pull request: ADR 0010 accepted with the run from `main`.
- Known gaps kept open: audit=1 is set but not proven at runtime (ADR 0004); x32 ABI syscalls match no audit
  rule (THREAT_MODEL T8), mitigation chosen before the host install; a build runs its commit's PKGBUILD and
  mkosi configuration on the host (T34), so only reviewed commits are built.

## Next step

1. Agents must run range jobs themselves: a confined runner that boots only its own commit's image and runs
   an agent's program from a read-only job disk (ADR 0011, in review); it builds no branches.
2. Step 9.3: `balistid-collector` and raw SQLite shards (ADR 0005), against `acceptance/0.toml`.

## Open decisions (maintainer)

- Project name: BALISTID chosen (4.10.), GitHub org renamed to `Balistid` (5.10.); renaming the repo and the product is still open.
- Hardware signing keys for R2 (budget approved in principle).
- Before the host install: x32 mitigation, and whether the host runs without io_uring.
