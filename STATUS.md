# Status

Updated: 2026-10-01 by claude/opus-5.5

## Where we are

Floor 0 (recorder) designed, not coded. ADR 0003–0007 merged (PR #9); 0004 stays proposed until its
smoke test. Gates and rulesets are live; the pin gate is tested (PR #8).

## Done in the last session

- PR #8: zizmor replaces the regex pin check, with executable tests against the pinned binary.
- PR #9: ADR 0003–0007 after three review rounds; R7 reshaped them to components and properties,
  with protocols designed in code and floor-0 gaps against root stated openly.
- `THREAT_MODEL.md` (28 rows, gaps marked with the floor that closes them) and `acceptance/0.toml`
  (33 metrics, each with rows, ADR and method) proposed in this pull request.
- The project name is still open; "Kordon" is a working name (kordon.app is an existing product).

## Next step

1. Maintainer approves or changes the acceptance numbers (R3).
2. Go toolchain pull request: `go.mod`, layout gate extension with negative tests, CI jobs
   (the maintainer pushes workflow changes).
3. Smoke test auditd + Laurel in the range VM (needs `/dev/kvm`), then floor 0 code.

## Open decisions (maintainer)

- Project name.
- Acceptance numbers for floor 0, including how long the host may be offline before the Pi alarms.
- Hardware signing keys for R2 (budget approved in principle).
