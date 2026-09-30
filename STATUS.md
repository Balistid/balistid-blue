# Status

Updated: 2026-09-30 by claude/opus-5.5

## Where we are

Floor 0 (recorder) not started. Repository skeleton, CI gates and the `main` ruleset are live.

## Done in the last session

- Name chosen and reserved: Kordon (domain `kordon.cz`, GitHub organisation `Kordon-Sec`).
- Skeleton: `ENGINEERING.md`, agent instructions, CI gates (docs budget, commit lint, action pinning,
  secret scan, workflow lint) with tests.
- Workflow: the kordon-sec-bot GitHub App pushes and opens pull requests; changes to gates and rules
  need the maintainer's approval (CODEOWNERS), everything else merges when CI is green.

- ADR 0002: the bot pushes and merges; the maintainer approves only changes to gates and rules.

## Next step

1. Process the five Deep Research reports (sensors and language, event store, agent isolation,
   attack range, orchestration layer) and verify their key claims.
2. ADRs for language, sensor stack and event schema; one-page `THREAT_MODEL.md`;
   `acceptance/0.toml` with numbers approved by the maintainer. Then floor 0 code.

## Open decisions (maintainer)

- Implementation language (waits for Deep Research 1).
- Acceptance numbers for floor 0.
- Hardware signing keys for R2 (budget approved in principle).
