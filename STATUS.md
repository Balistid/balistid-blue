# Status

Updated: 2026-10-04 by claude/opus-5.5

## Where we are

Floor 0 (recorder): the attack range (ADR 0009) and the sensor (auditd + Laurel, ADR 0004) are merged and
accepted; range run 20261004T075611Z-3a36f42b on `main` (fa883b2, kernel 7.2.8-arch1-2) passed every check.
No recorder code yet: the collector and raw shards (ADR 0005) are next.

## Done in the last session

- PR #15 range, #16 acceptance numbers approved, #17 ADR 0004 amendment, #18 sensor smoke test.
- This pull request: ADR 0004 and 0009 accepted with the run from `main`.
- Known gaps kept open: audit=1 is set but not proven at runtime (ADR 0004); x32 ABI syscalls match no audit
  rule (THREAT_MODEL T8), mitigation chosen before the host install.

## Next step

1. Repository map in README kept current by CI (next pull request).
2. Step 9.3: `kordon-collector` and raw SQLite shards (ADR 0005), against `acceptance/0.toml`.
3. Agents must run range jobs themselves (range runner, ADR 0010 to be planned with the maintainer).

## Open decisions (maintainer)

- Project name.
- Hardware signing keys for R2 (budget approved in principle).
- Before the host install: x32 mitigation, and whether the host runs without io_uring.
