# Status

Updated: 2026-10-01 by claude/opus-5.5

## Where we are

Floor 0 (recorder) designed, not coded. Gates and rulesets are live; the pin gate is tested (PR #8).

## Done in the last session

- PR #8 merged: zizmor replaces the regex pin check, with executable tests against the pinned binary.
- ADR 0003–0007 proposed in PR #9, accepted when the maintainer approves (0004 only after its smoke
  test): Go without cgo, auditd + Laurel sensor, raw SQLite day shards sealed and anchored in a
  Tessera log cosigned and watched from the Pi, separate process identities.
  Two review rounds (Claude critic, Codex) found fixes introducing new defects, so R7 applied:
  the ADRs now fix components and required properties; protocols are designed in code with tests,
  and the floor-0 gaps against root go to `THREAT_MODEL.md`.
- The project name is still open; "Kordon" is a working name (kordon.app is an existing product).

## Next step

1. `THREAT_MODEL.md` (one page) and `acceptance/0.toml`; the maintainer sets the numbers (R3).
2. Go toolchain pull request: `go.mod`, layout gate extension with negative tests, CI jobs
   (the maintainer pushes workflow changes).
3. Smoke test auditd + Laurel in the range VM (needs `/dev/kvm`), then floor 0 code.

## Open decisions (maintainer)

- Project name.
- Acceptance numbers for floor 0 (loss, crash window, cosign interval, caps, health timeouts).
- Hardware signing keys for R2 (budget approved in principle).
