# Status

Updated: 2026-09-30 by claude/opus-5.5

## Where we are

Floor 0 (recorder) not started. Repository skeleton with CI gates is being bootstrapped.

## Done in the last session

- Name chosen and reserved: Kordon (domain `kordon.cz`, GitHub organisation `Kordon-Sec`).
- Skeleton: `ENGINEERING.md`, agent instructions, CI gates (docs budget, commit lint, action pinning,
  secret scan, workflow lint) with tests.

## Next step

1. Merge the bootstrap pull request once CI is green and the `main` ruleset is active.
2. Process the five Deep Research reports (sensors and language, event store, agent isolation,
   attack range, orchestration layer) and verify their key claims.
3. ADRs for language, sensor stack and event schema; one-page `THREAT_MODEL.md`;
   `acceptance/0.toml` with numbers approved by the maintainer. Then floor 0 code.

## Open decisions (maintainer)

- Implementation language (waits for Deep Research 1).
- Acceptance numbers for floor 0.
- Hardware signing keys for R2 (budget approved in principle).
